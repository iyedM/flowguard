"""Mechanism C: 4-State Transactional Idempotency & Side-Effect Proxy.

Implements SQLite WAL ledger (`busy_timeout=5000`, `threading.RLock()`) with the
4-state idempotency machine:
  - PENDING_IN_FLIGHT
  - COMMITTED
  - FAILED_SAFE_TO_RETRY
  - AMBIGUOUS_REQUIRES_RECONCILIATION (post-commit HTTP timeout requiring read-before-write reconciliation)
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from flowguard.models import (
    ExecutionModeLabel,
    IdempotencyRecord,
    IdempotencyState,
    SinkMutationReceipt,
)
from flowguard.telemetry import SpanTimer, TelemetryRecorder


class PreCommitTransientError(RuntimeError):
    """Raised when a downstream sink rejects a call BEFORE mutating state (e.g., HTTP 429/503)."""


class PostCommitTimeoutError(TimeoutError):
    """Raised when a downstream sink MUTATED state, but the HTTP response timed out in transit."""


class IdempotencyLedger:
    """Thread-safe SQLite WAL 4-state idempotency store and execution proxy."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        telemetry: Optional[TelemetryRecorder] = None,
    ) -> None:
        self.db_path = str(db_path) if db_path is not None else ":memory:"
        self.telemetry = telemetry
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.db_path,
            timeout=5.0,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS idempotency_ledger (
                    idem_key TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    state TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 1,
                    sink_receipt_json TEXT,
                    reconciled INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )

    @staticmethod
    def derive_key(
        workflow_id: str,
        entity_id: str,
        operation: str,
        canonical_payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Compute deterministic SHA-256 idempotency key."""
        payload_part = ""
        if canonical_payload is not None:
            filtered = {
                k: v
                for k, v in sorted(canonical_payload.items())
                if k not in ("request_attempt", "webhook_delivery_id", "timestamp")
            }
            payload_part = json.dumps(filtered, sort_keys=True, separators=(",", ":"))
        raw = f"{workflow_id}:{entity_id}:{operation}:{payload_part}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def hash_payload(payload: Dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]

    def get_record(self, idem_key: str) -> Optional[IdempotencyRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM idempotency_ledger WHERE idem_key = ?",
                (idem_key,),
            ).fetchone()
            if row is None:
                return None
            receipt = (
                json.loads(row["sink_receipt_json"])
                if row["sink_receipt_json"]
                else None
            )
            return IdempotencyRecord(
                idem_key=row["idem_key"],
                workflow_id=row["workflow_id"],
                entity_id=row["entity_id"],
                operation=row["operation"],
                payload_hash=row["payload_hash"],
                state=IdempotencyState(row["state"]),
                attempt_count=int(row["attempt_count"]),
                sink_receipt=receipt,
                reconciled=bool(row["reconciled"]),
                created_at=float(row["created_at"]),
                updated_at=float(row["updated_at"]),
            )

    def execute_through_proxy(
        self,
        workflow_id: str,
        domain: str,
        entity_id: str,
        operation: str,
        payload: Dict[str, Any],
        mutate_fn: Callable[[str], Dict[str, Any]],
        reconcile_fn: Optional[Callable[[str, str], Optional[Dict[str, Any]]]] = None,
        idem_key: Optional[str] = None,
        reconciliation_enabled: bool = True,
        trace_id: Optional[str] = None,
    ) -> SinkMutationReceipt:
        """Execute a side-effect mutation guarded by the 4-state idempotency lifecycle."""
        computed_key = idem_key or self.derive_key(
            workflow_id=workflow_id,
            entity_id=entity_id,
            operation=operation,
            canonical_payload=payload,
        )
        p_hash = self.hash_payload(payload)

        with SpanTimer() as timer:
            receipt = self._execute_locked_lifecycle(
                idem_key=computed_key,
                workflow_id=workflow_id,
                entity_id=entity_id,
                operation=operation,
                payload_hash=p_hash,
                mutate_fn=mutate_fn,
                reconcile_fn=reconcile_fn,
                reconciliation_enabled=reconciliation_enabled,
            )

        if self.telemetry is not None:
            self.telemetry.record_span(
                name="flowguard.idempotency",
                workflow_id=workflow_id,
                domain=domain,
                status=receipt.idempotency_state.value,
                duration_ms=timer.elapsed_ms,
                trace_id=trace_id,
                attributes={
                    "idem_key": computed_key,
                    "entity_id": entity_id,
                    "operation": operation,
                    "applied": receipt.applied,
                    "replayed_from_ledger": receipt.replayed_from_ledger,
                    "reconciled_after_timeout": receipt.reconciled_after_timeout,
                    "concurrent_duplicate_blocked": receipt.concurrent_duplicate_blocked,
                    "halted_for_reconciliation": receipt.halted_for_reconciliation,
                },
                execution_mode_label=ExecutionModeLabel.DETERMINISTIC_HARNESS.value,
            )
        return receipt

    def _execute_locked_lifecycle(
        self,
        idem_key: str,
        workflow_id: str,
        entity_id: str,
        operation: str,
        payload_hash: str,
        mutate_fn: Callable[[str], Dict[str, Any]],
        reconcile_fn: Optional[Callable[[str, str], Optional[Dict[str, Any]]]],
        reconciliation_enabled: bool,
    ) -> SinkMutationReceipt:
        now = time.time()
        with self._lock:
            existing = self.get_record(idem_key)

            # Case 1: Already COMMITTED -> Replay cached receipt without mutating sink
            if existing is not None and existing.state == IdempotencyState.COMMITTED:
                self._conn.execute(
                    "UPDATE idempotency_ledger SET attempt_count = attempt_count + 1, updated_at = ? WHERE idem_key = ?",
                    (now, idem_key),
                )
                cached = existing.sink_receipt or {}
                return SinkMutationReceipt(
                    idem_key=idem_key,
                    entity_id=entity_id,
                    operation=operation,
                    applied=False,
                    idempotency_state=IdempotencyState.COMMITTED,
                    replayed_from_ledger=True,
                    mutation_count_for_entity=int(cached.get("mutation_count_for_entity", 1)),
                    ground_truth_snapshot=cached.get("ground_truth_snapshot", {}),
                )

            # Case 2: Currently PENDING_IN_FLIGHT -> Block concurrent duplicate execution
            if existing is not None and existing.state == IdempotencyState.PENDING_IN_FLIGHT:
                self._conn.execute(
                    "UPDATE idempotency_ledger SET attempt_count = attempt_count + 1, updated_at = ? WHERE idem_key = ?",
                    (now, idem_key),
                )
                return SinkMutationReceipt(
                    idem_key=idem_key,
                    entity_id=entity_id,
                    operation=operation,
                    applied=False,
                    idempotency_state=IdempotencyState.PENDING_IN_FLIGHT,
                    concurrent_duplicate_blocked=True,
                    mutation_count_for_entity=0,
                    ground_truth_snapshot={},
                )

            # Case 3: AMBIGUOUS_REQUIRES_RECONCILIATION (prior post-commit HTTP timeout)
            if (
                existing is not None
                and existing.state == IdempotencyState.AMBIGUOUS_REQUIRES_RECONCILIATION
            ):
                if reconciliation_enabled:
                    if reconcile_fn is None:
                        # Cannot reconcile without read endpoint -> halt safely to prevent duplicate side effects
                        self._conn.execute(
                            "UPDATE idempotency_ledger SET attempt_count = attempt_count + 1, updated_at = ? WHERE idem_key = ?",
                            (now, idem_key),
                        )
                        return SinkMutationReceipt(
                            idem_key=idem_key,
                            entity_id=entity_id,
                            operation=operation,
                            applied=False,
                            idempotency_state=IdempotencyState.AMBIGUOUS_REQUIRES_RECONCILIATION,
                            halted_for_reconciliation=True,
                            mutation_count_for_entity=0,
                            ground_truth_snapshot={},
                        )

                    reconciled_state = reconcile_fn(entity_id, idem_key)
                    if reconciled_state is not None and reconciled_state.get("committed_on_sink") is True:
                        # Sink already applied the side effect during the timed-out call!
                        # Transition AMBIGUOUS_REQUIRES_RECONCILIATION -> COMMITTED without re-mutating.
                        receipt_json = json.dumps(reconciled_state, sort_keys=True)
                        self._conn.execute(
                            """
                            UPDATE idempotency_ledger
                            SET state = ?, sink_receipt_json = ?, reconciled = 1,
                                attempt_count = attempt_count + 1, updated_at = ?
                            WHERE idem_key = ?
                            """,
                            (IdempotencyState.COMMITTED.value, receipt_json, now, idem_key),
                        )
                        return SinkMutationReceipt(
                            idem_key=idem_key,
                            entity_id=entity_id,
                            operation=operation,
                            applied=False,
                            idempotency_state=IdempotencyState.COMMITTED,
                            reconciled_after_timeout=True,
                            mutation_count_for_entity=int(
                                reconciled_state.get("mutation_count_for_entity", 1)
                            ),
                            ground_truth_snapshot=reconciled_state.get("ground_truth_snapshot", {}),
                        )
                    elif reconciled_state is not None and reconciled_state.get("committed_on_sink") is False:
                        # Sink confirmed side effect did NOT apply; safe to transition to PENDING_IN_FLIGHT
                        self._conn.execute(
                            """
                            UPDATE idempotency_ledger
                            SET state = ?, reconciled = 1, attempt_count = attempt_count + 1, updated_at = ?
                            WHERE idem_key = ?
                            """,
                            (IdempotencyState.PENDING_IN_FLIGHT.value, now, idem_key),
                        )
                    else:
                        # Read endpoint returned indeterminate state -> halt safely
                        self._conn.execute(
                            "UPDATE idempotency_ledger SET attempt_count = attempt_count + 1, updated_at = ? WHERE idem_key = ?",
                            (now, idem_key),
                        )
                        return SinkMutationReceipt(
                            idem_key=idem_key,
                            entity_id=entity_id,
                            operation=operation,
                            applied=False,
                            idempotency_state=IdempotencyState.AMBIGUOUS_REQUIRES_RECONCILIATION,
                            halted_for_reconciliation=True,
                            mutation_count_for_entity=0,
                            ground_truth_snapshot={},
                        )
                else:
                    # Ablation mode: reconciliation disabled -> blindly re-executes
                    self._conn.execute(
                        """
                        UPDATE idempotency_ledger
                        SET state = ?, attempt_count = attempt_count + 1, updated_at = ?
                        WHERE idem_key = ?
                        """,
                        (IdempotencyState.PENDING_IN_FLIGHT.value, now, idem_key),
                    )

            # Case 4: New key or FAILED_SAFE_TO_RETRY -> Set PENDING_IN_FLIGHT
            elif existing is None:
                self._conn.execute(
                    """
                    INSERT INTO idempotency_ledger (
                        idem_key, workflow_id, entity_id, operation, payload_hash,
                        state, attempt_count, sink_receipt_json, reconciled, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, NULL, 0, ?, ?)
                    """,
                    (
                        idem_key,
                        workflow_id,
                        entity_id,
                        operation,
                        payload_hash,
                        IdempotencyState.PENDING_IN_FLIGHT.value,
                        now,
                        now,
                    ),
                )
            else:
                # existing.state == FAILED_SAFE_TO_RETRY
                self._conn.execute(
                    """
                    UPDATE idempotency_ledger
                    SET state = ?, attempt_count = attempt_count + 1, updated_at = ?
                    WHERE idem_key = ?
                    """,
                    (IdempotencyState.PENDING_IN_FLIGHT.value, now, idem_key),
                )

        # Execute sink mutation outside the SQLite statement block (while preserving thread safety or allowing simulated concurrency tests)
        try:
            sink_result = mutate_fn(idem_key)
        except PreCommitTransientError:
            with self._lock:
                self._conn.execute(
                    "UPDATE idempotency_ledger SET state = ?, updated_at = ? WHERE idem_key = ?",
                    (IdempotencyState.FAILED_SAFE_TO_RETRY.value, time.time(), idem_key),
                )
            raise
        except PostCommitTimeoutError:
            with self._lock:
                self._conn.execute(
                    "UPDATE idempotency_ledger SET state = ?, updated_at = ? WHERE idem_key = ?",
                    (
                        IdempotencyState.AMBIGUOUS_REQUIRES_RECONCILIATION.value,
                        time.time(),
                        idem_key,
                    ),
                )
            raise

        with self._lock:
            receipt_json = json.dumps(sink_result, sort_keys=True)
            self._conn.execute(
                """
                UPDATE idempotency_ledger
                SET state = ?, sink_receipt_json = ?, updated_at = ?
                WHERE idem_key = ?
                """,
                (IdempotencyState.COMMITTED.value, receipt_json, time.time(), idem_key),
            )
            return SinkMutationReceipt(
                idem_key=idem_key,
                entity_id=entity_id,
                operation=operation,
                applied=True,
                idempotency_state=IdempotencyState.COMMITTED,
                replayed_from_ledger=False,
                reconciled_after_timeout=False,
                mutation_count_for_entity=int(
                    sink_result.get("mutation_count_for_entity", 1)
                ),
                ground_truth_snapshot=sink_result.get("ground_truth_snapshot", {}),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
