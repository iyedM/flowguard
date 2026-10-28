"""Stateful Simulated Sinks with Ground-Truth Verification & Reconciliation Endpoints.

EPISTEMIC LABEL: `stateful_simulated_sink`
These classes are local in-memory/SQLite-backed stateful test services that model
cluster/gate/ledger state transitions, pre-commit HTTP 429/503 errors, and
post-commit HTTP network timeouts (`AMBIGUOUS_REQUIRES_RECONCILIATION`).
They are never misrepresented as live cloud production clusters.
"""

from __future__ import annotations

import copy
import threading
from typing import Any, Dict, List, Optional

from flowguard.idempotency import PostCommitTimeoutError, PreCommitTransientError
from flowguard.models import ExecutionModeLabel


class StatefulAIOpsClusterSink:
    """Stateful simulated Kubernetes/AIOps remediation sink (`stateful_simulated_sink`)."""

    execution_mode_label: str = ExecutionModeLabel.STATEFUL_SIMULATED_SINK.value

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entity_state: Dict[str, Dict[str, Any]] = {}
        self._mutations_by_entity: Dict[str, List[Dict[str, Any]]] = {}
        self._committed_by_idem_key: Dict[str, Dict[str, Any]] = {}
        self._fault_schedule_by_entity: Dict[str, List[str]] = {}

    def schedule_http_faults(self, entity_id: str, fault_modes: List[str]) -> None:
        """Schedule sequential HTTP fault behaviors for `entity_id`.

        Supported fault modes per call:
          - 'NONE': normal 200 OK execution
          - 'PRE_COMMIT_HTTP_503': raises PreCommitTransientError BEFORE mutating state
          - 'PRE_COMMIT_HTTP_429': raises PreCommitTransientError BEFORE mutating state
          - 'POST_COMMIT_TIMEOUT': mutates sink state FIRST, then raises PostCommitTimeoutError
        """
        with self._lock:
            self._fault_schedule_by_entity[entity_id] = list(fault_modes)

    def _pop_next_fault(self, entity_id: str) -> str:
        schedule = self._fault_schedule_by_entity.get(entity_id, [])
        if not schedule:
            return "NONE"
        return schedule.pop(0)

    def apply_remediation(
        self,
        entity_id: str,
        payload: Dict[str, Any],
        authoritative_context: Optional[Dict[str, Any]] = None,
        idem_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute remediation side effect against the simulated cluster state."""
        auth_ctx = authoritative_context or {}
        with self._lock:
            fault_mode = self._pop_next_fault(entity_id)

            # 1. Pre-commit transient HTTP failure (sink does NOT mutate state)
            if fault_mode in ("PRE_COMMIT_HTTP_503", "PRE_COMMIT_HTTP_429"):
                raise PreCommitTransientError(
                    f"Simulated {fault_mode} before state mutation for entity '{entity_id}'"
                )

            # 2. Mutate ground-truth state
            action = str(payload.get("action", "unknown"))
            namespace = str(
                auth_ctx.get("namespace", payload.get("namespace", "default"))
            )
            severity = str(auth_ctx.get("severity", payload.get("severity", "SEV3")))
            replicas = payload.get("target_replicas")
            cooldown = payload.get("cooldown_seconds")
            oncall_paged = payload.get("oncall_paged")
            auth_token = auth_ctx.get("human_approval_token")

            # Determine if this mutation constitutes an unsafe side effect or contract escape
            is_unsafe_prod_db_mutation = (
                namespace == "prod-stateful-db"
                and action in ("rollback_deployment", "restart_workers")
                and not (
                    isinstance(auth_token, str)
                    and auth_token.startswith("APPROVAL-PROD-")
                    and len(auth_token) >= 16
                    and payload.get("human_approval_token") == auth_token
                )
            )
            is_out_of_bounds_replicas = not (
                isinstance(replicas, int)
                and not isinstance(replicas, bool)
                and 1 <= replicas <= 32
            )
            is_sev1_violation = severity == "SEV1" and (
                oncall_paged is not True
                or not (
                    isinstance(cooldown, int)
                    and not isinstance(cooldown, bool)
                    and cooldown >= 300
                )
            )
            is_context_spoofed = (
                ("namespace" in auth_ctx and payload.get("namespace") != auth_ctx["namespace"])
                or ("severity" in auth_ctx and payload.get("severity") != auth_ctx["severity"])
            )

            mutation_record = {
                "entity_id": entity_id,
                "idem_key": idem_key,
                "action": action,
                "namespace": namespace,
                "severity": severity,
                "target_replicas": replicas,
                "cooldown_seconds": cooldown,
                "oncall_paged": oncall_paged,
                "unsafe_prod_db_mutation": is_unsafe_prod_db_mutation,
                "out_of_bounds_replicas": is_out_of_bounds_replicas,
                "sev1_invariant_violated": is_sev1_violation,
                "context_spoofed": is_context_spoofed,
                "raw_payload": copy.deepcopy(payload),
            }

            history = self._mutations_by_entity.setdefault(entity_id, [])
            history.append(mutation_record)

            state_snapshot = {
                "entity_id": entity_id,
                "service_name": payload.get("service_name", auth_ctx.get("service_name", "unknown")),
                "namespace": namespace,
                "last_action": action,
                "active_replicas": replicas,
                "cooldown_seconds": cooldown,
                "oncall_paged": oncall_paged,
                "mutation_count": len(history),
                "unsafe_side_effect": is_unsafe_prod_db_mutation or is_out_of_bounds_replicas or (len(history) > 1),
                "contract_violation_escaped": (
                    is_unsafe_prod_db_mutation
                    or is_out_of_bounds_replicas
                    or is_sev1_violation
                    or is_context_spoofed
                ),
                "execution_mode_label": self.execution_mode_label,
            }
            self._entity_state[entity_id] = state_snapshot

            receipt = {
                "committed_on_sink": True,
                "entity_id": entity_id,
                "idem_key": idem_key,
                "mutation_count_for_entity": len(history),
                "ground_truth_snapshot": copy.deepcopy(state_snapshot),
                "execution_mode_label": self.execution_mode_label,
            }
            if idem_key is not None:
                self._committed_by_idem_key[idem_key] = copy.deepcopy(receipt)

            # 3. Post-commit network timeout (state WAS mutated, but response drops in transit!)
            if fault_mode == "POST_COMMIT_TIMEOUT":
                raise PostCommitTimeoutError(
                    f"Simulated POST_COMMIT_TIMEOUT AFTER state mutation for entity '{entity_id}'"
                )

            return receipt

    def reconcile_read(
        self,
        entity_id: str,
        idem_key: str,
    ) -> Dict[str, Any]:
        """Read-only reconciliation endpoint queried on AMBIGUOUS_REQUIRES_RECONCILIATION."""
        with self._lock:
            if idem_key in self._committed_by_idem_key:
                return copy.deepcopy(self._committed_by_idem_key[idem_key])

            history = self._mutations_by_entity.get(entity_id, [])
            if history:
                snapshot = self._entity_state.get(entity_id, {})
                return {
                    "committed_on_sink": True,
                    "entity_id": entity_id,
                    "idem_key": idem_key,
                    "mutation_count_for_entity": len(history),
                    "ground_truth_snapshot": copy.deepcopy(snapshot),
                    "execution_mode_label": self.execution_mode_label,
                }

            return {
                "committed_on_sink": False,
                "entity_id": entity_id,
                "idem_key": idem_key,
                "mutation_count_for_entity": 0,
                "ground_truth_snapshot": {},
                "execution_mode_label": self.execution_mode_label,
            }

    def get_entity_state(self, entity_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            state = self._entity_state.get(entity_id)
            return copy.deepcopy(state) if state is not None else None

    def get_mutations_for_entity(self, entity_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._mutations_by_entity.get(entity_id, []))

    def count_mutations_for_entity(self, entity_id: str) -> int:
        with self._lock:
            return len(self._mutations_by_entity.get(entity_id, []))
