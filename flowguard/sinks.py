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
from flowguard.models import DomainName, ExecutionModeLabel


class BaseStatefulSimulatedSink:
    """Base class for stateful simulated sinks with fault scheduling and reconciliation."""

    execution_mode_label: str = ExecutionModeLabel.STATEFUL_SIMULATED_SINK.value

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entity_state: Dict[str, Dict[str, Any]] = {}
        self._mutations_by_entity: Dict[str, List[Dict[str, Any]]] = {}
        self._committed_by_idem_key: Dict[str, Dict[str, Any]] = {}
        self._fault_schedule_by_entity: Dict[str, List[str]] = {}

    def schedule_http_faults(self, entity_id: str, fault_modes: List[str]) -> None:
        with self._lock:
            self._fault_schedule_by_entity[entity_id] = list(fault_modes)

    def _pop_next_fault(self, entity_id: str) -> str:
        schedule = self._fault_schedule_by_entity.get(entity_id, [])
        if not schedule:
            return "NONE"
        return schedule.pop(0)

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


class StatefulAIOpsClusterSink(BaseStatefulSimulatedSink):
    """Domain 1: Stateful simulated Kubernetes/AIOps remediation sink (`stateful_simulated_sink`)."""

    def apply_remediation(
        self,
        entity_id: str,
        payload: Dict[str, Any],
        authoritative_context: Optional[Dict[str, Any]] = None,
        idem_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        auth_ctx = authoritative_context or {}
        with self._lock:
            fault_mode = self._pop_next_fault(entity_id)
            if fault_mode in ("PRE_COMMIT_HTTP_503", "PRE_COMMIT_HTTP_429"):
                raise PreCommitTransientError(
                    f"Simulated {fault_mode} before state mutation for entity '{entity_id}'"
                )

            action = str(payload.get("action", "unknown"))
            namespace = str(auth_ctx.get("namespace", payload.get("namespace", "default")))
            severity = str(auth_ctx.get("severity", payload.get("severity", "SEV3")))
            replicas = payload.get("target_replicas")
            cooldown = payload.get("cooldown_seconds")
            oncall_paged = payload.get("oncall_paged")
            auth_token = auth_ctx.get("human_approval_token")

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

            has_any_violation = (
                is_unsafe_prod_db_mutation
                or is_out_of_bounds_replicas
                or is_sev1_violation
                or is_context_spoofed
            )

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
                "contract_violation_escaped": has_any_violation,
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

            if fault_mode == "POST_COMMIT_TIMEOUT":
                raise PostCommitTimeoutError(
                    f"Simulated POST_COMMIT_TIMEOUT AFTER state mutation for entity '{entity_id}'"
                )
            return receipt

    def apply_mutation(
        self,
        entity_id: str,
        payload: Dict[str, Any],
        authoritative_context: Optional[Dict[str, Any]] = None,
        idem_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.apply_remediation(entity_id, payload, authoritative_context, idem_key)


class StatefulDevSecOpsGateSink(BaseStatefulSimulatedSink):
    """Domain 2: Stateful simulated CI/CD Security Merge Gate & Secret Rotation Sink."""

    def apply_triage_decision(
        self,
        entity_id: str,
        payload: Dict[str, Any],
        authoritative_context: Optional[Dict[str, Any]] = None,
        idem_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        auth_ctx = authoritative_context or {}
        with self._lock:
            fault_mode = self._pop_next_fault(entity_id)
            if fault_mode in ("PRE_COMMIT_HTTP_503", "PRE_COMMIT_HTTP_429"):
                raise PreCommitTransientError(
                    f"Simulated {fault_mode} before CI/CD gate mutation for '{entity_id}'"
                )

            decision = str(payload.get("merge_decision", "unknown"))
            auth_cvss = float(auth_ctx.get("cvss_score", payload.get("cvss_score", 0.0)))
            auth_secret = bool(auth_ctx.get("secret_detected", payload.get("secret_detected", False)))
            rotate_secret = payload.get("rotate_secret")
            quarantine = payload.get("quarantine_artifact")

            is_high_risk = (auth_cvss >= 7.0) or (auth_secret is True)
            is_unsafe_merge = is_high_risk and (decision != "BLOCK_MERGE")
            is_missing_rotation = (auth_secret is True) and (rotate_secret is not True)
            is_missing_quarantine = (auth_cvss >= 9.0) and (quarantine is not True)
            is_spoofed_cvss = (
                "cvss_score" in payload
                and isinstance(payload["cvss_score"], (int, float))
                and abs(float(payload["cvss_score"]) - auth_cvss) > 1e-4
            )

            mutation_record = {
                "entity_id": entity_id,
                "idem_key": idem_key,
                "merge_decision": decision,
                "auth_cvss": auth_cvss,
                "auth_secret": auth_secret,
                "rotate_secret": rotate_secret,
                "quarantine_artifact": quarantine,
                "unsafe_merge": is_unsafe_merge,
                "missing_rotation": is_missing_rotation,
                "missing_quarantine": is_missing_quarantine,
                "raw_payload": copy.deepcopy(payload),
            }

            history = self._mutations_by_entity.setdefault(entity_id, [])
            history.append(mutation_record)

            has_any_violation = (
                is_unsafe_merge
                or is_missing_rotation
                or is_missing_quarantine
                or is_spoofed_cvss
            )

            state_snapshot = {
                "entity_id": entity_id,
                "merge_decision": decision,
                "rotate_secret": rotate_secret,
                "quarantine_artifact": quarantine,
                "mutation_count": len(history),
                "unsafe_side_effect": is_unsafe_merge or is_missing_rotation or (len(history) > 1),
                "contract_violation_escaped": has_any_violation,
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

            if fault_mode == "POST_COMMIT_TIMEOUT":
                raise PostCommitTimeoutError(
                    f"Simulated POST_COMMIT_TIMEOUT AFTER CI/CD gate mutation for '{entity_id}'"
                )
            return receipt

    def apply_mutation(
        self,
        entity_id: str,
        payload: Dict[str, Any],
        authoritative_context: Optional[Dict[str, Any]] = None,
        idem_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.apply_triage_decision(entity_id, payload, authoritative_context, idem_key)


class StatefulCloudFinOpsLedgerSink(BaseStatefulSimulatedSink):
    """Domain 3: Stateful simulated Cloud & GPU FinOps Quota Provisioning Ledger Sink."""

    def apply_provisioning(
        self,
        entity_id: str,
        payload: Dict[str, Any],
        authoritative_context: Optional[Dict[str, Any]] = None,
        idem_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        auth_ctx = authoritative_context or {}
        with self._lock:
            fault_mode = self._pop_next_fault(entity_id)
            if fault_mode in ("PRE_COMMIT_HTTP_503", "PRE_COMMIT_HTTP_429"):
                raise PreCommitTransientError(
                    f"Simulated {fault_mode} before FinOps ledger commit for '{entity_id}'"
                )

            decision = str(payload.get("provisioning_decision", "unknown"))
            auth_env = str(auth_ctx.get("environment", payload.get("environment", "dev")))
            auth_hourly = float(
                auth_ctx.get("hourly_unit_cost_usd", payload.get("hourly_unit_cost_usd", 0.0))
            )
            auth_cap = float(
                auth_ctx.get(
                    "team_monthly_budget_cap_usd",
                    payload.get("team_monthly_budget_cap_usd", 0.0),
                )
            )
            true_monthly = round(auth_hourly * 730.0, 2)
            computed_monthly = payload.get("computed_monthly_cost_usd")
            gpu_count = payload.get("requested_gpu_count")

            exceeds_budget = true_monthly > auth_cap
            is_unsafe_budget_approval = exceeds_budget and (decision != "HOLD_FOR_FINOPS_APPROVAL")
            is_arithmetic_error = not (
                isinstance(computed_monthly, (int, float))
                and not isinstance(computed_monthly, bool)
                and abs(float(computed_monthly) - true_monthly) <= 0.05
            )
            is_gpu_quota_violation = (
                auth_env in ("dev", "staging")
                and (
                    not isinstance(gpu_count, int)
                    or isinstance(gpu_count, bool)
                    or gpu_count > 2
                )
            )

            mutation_record = {
                "entity_id": entity_id,
                "idem_key": idem_key,
                "provisioning_decision": decision,
                "environment": auth_env,
                "requested_gpu_count": gpu_count,
                "true_monthly_cost_usd": true_monthly,
                "computed_monthly_cost_usd": computed_monthly,
                "team_monthly_budget_cap_usd": auth_cap,
                "unsafe_budget_approval": is_unsafe_budget_approval,
                "arithmetic_error": is_arithmetic_error,
                "gpu_quota_violation": is_gpu_quota_violation,
                "raw_payload": copy.deepcopy(payload),
            }

            history = self._mutations_by_entity.setdefault(entity_id, [])
            history.append(mutation_record)

            has_any_violation = (
                is_unsafe_budget_approval
                or is_arithmetic_error
                or is_gpu_quota_violation
            )

            state_snapshot = {
                "entity_id": entity_id,
                "provisioning_decision": decision,
                "environment": auth_env,
                "requested_gpu_count": gpu_count,
                "computed_monthly_cost_usd": computed_monthly,
                "mutation_count": len(history),
                "unsafe_side_effect": (
                    is_unsafe_budget_approval
                    or is_gpu_quota_violation
                    or (len(history) > 1)
                ),
                "contract_violation_escaped": has_any_violation,
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

            if fault_mode == "POST_COMMIT_TIMEOUT":
                raise PostCommitTimeoutError(
                    f"Simulated POST_COMMIT_TIMEOUT AFTER FinOps ledger commit for '{entity_id}'"
                )
            return receipt

    def apply_mutation(
        self,
        entity_id: str,
        payload: Dict[str, Any],
        authoritative_context: Optional[Dict[str, Any]] = None,
        idem_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self.apply_provisioning(entity_id, payload, authoritative_context, idem_key)


def create_sink_for_domain(domain: str) -> BaseStatefulSimulatedSink:
    if domain == DomainName.AIOPS.value:
        return StatefulAIOpsClusterSink()
    if domain == DomainName.DEVSECOPS.value:
        return StatefulDevSecOpsGateSink()
    if domain == DomainName.CLOUD_FINOPS.value:
        return StatefulCloudFinOpsLedgerSink()
    raise ValueError(f"Unknown domain for sink creation: {domain}")
