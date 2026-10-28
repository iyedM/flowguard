"""Mechanism D: Least-Privilege Policy Engine & Untrusted Taint Auditor.

Enforces strict separation between:
1. Deterministic Security Boundary: Authoritative context attributes & capability allowlists
   across AIOps, DevSecOps, and Cloud FinOps (an LLM can never override a security invariant).
2. Fallible Taint / Prompt-Injection Detector: Heuristic inspection of untrusted strings
   (`recent_log_snippet`, `untrusted_pr_body`, `justification_notes`) emitted strictly as
   an observability/audit signal (`is_authoritative_boundary = False`).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from flowguard.models import (
    DomainName,
    ExecutionModeLabel,
    PolicyDecision,
    TaintSignal,
)
from flowguard.telemetry import SpanTimer, TelemetryRecorder

TAINT_HEURISTIC_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("IGNORE_INSTRUCTIONS", re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.I)),
    ("SYSTEM_OVERRIDE", re.compile(r"(system\s+override|admin\s+override|\[system\])", re.I)),
    ("BYPASS_POLICY", re.compile(r"(bypass\s+security|skip\s+approval|force\s+allow)", re.I)),
    ("FAKE_APPROVAL_TOKEN", re.compile(r"human_approval_token\s*[:=]\s*['\"]?APPROVAL-", re.I)),
    ("DIRECTIVE_INJECTION", re.compile(r"(you\s+must\s+execute|immediately\s+run\s+rollback)", re.I)),
]

UNTRUSTED_TEXT_FIELDS: Tuple[str, ...] = (
    "recent_log_snippet",
    "untrusted_pr_body",
    "untrusted_pr_title_and_body",
    "justification_notes",
    "raw_user_note",
)

AIOPS_ALLOWED_ACTIONS: Set[str] = {
    "scale_replicas",
    "restart_workers",
    "rollback_deployment",
    "noop_observe",
    "escalate_to_human",
}

DEVSECOPS_ALLOWED_DECISIONS: Set[str] = {
    "ALLOW_MERGE",
    "BLOCK_MERGE",
    "HOLD_FOR_SECURITY_REVIEW",
}

CLOUD_FINOPS_ALLOWED_DECISIONS: Set[str] = {
    "APPROVE_PROVISIONING",
    "HOLD_FOR_FINOPS_APPROVAL",
    "REJECT_QUOTA_EXCEEDED",
}


class PolicyGuard:
    """Deterministic Least-Privilege Policy Engine + Fallible Untrusted Taint Auditor."""

    def __init__(self, telemetry: Optional[TelemetryRecorder] = None) -> None:
        self.telemetry = telemetry

    def audit_untrusted_text(
        self,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> TaintSignal:
        """Scan untrusted text fields for prompt-injection heuristics (observability only)."""
        payload = payload or {}
        matched: List[str] = []
        scanned_fields: List[str] = []

        for field_name in UNTRUSTED_TEXT_FIELDS:
            candidates: List[str] = []
            if isinstance(context.get(field_name), str):
                candidates.append(context[field_name])
            if isinstance(payload.get(field_name), str):
                candidates.append(payload[field_name])
            if not candidates:
                continue

            scanned_fields.append(field_name)
            combined_text = "\n".join(candidates)
            for label, pattern in TAINT_HEURISTIC_PATTERNS:
                if pattern.search(combined_text) and label not in matched:
                    matched.append(label)

        risk_score = min(1.0, round(len(matched) * 0.35, 2))
        return TaintSignal(
            detected=len(matched) > 0,
            matched_patterns=matched,
            untrusted_fields_scanned=scanned_fields,
            risk_score=risk_score,
            is_authoritative_boundary=False,
            execution_mode_label=ExecutionModeLabel.DETERMINISTIC_HARNESS.value,
        )

    def evaluate(
        self,
        domain: str,
        payload: Dict[str, Any],
        context: Dict[str, Any],
        workflow_id: str = "wf-default",
        trace_id: Optional[str] = None,
        policy_enabled: bool = True,
    ) -> PolicyDecision:
        """Evaluate authoritative security policy invariants independently of taint detection."""
        with SpanTimer() as timer:
            taint_signal = self.audit_untrusted_text(context=context, payload=payload)
            if not policy_enabled:
                action_val = str(
                    payload.get("action")
                    or payload.get("merge_decision")
                    or payload.get("provisioning_decision")
                    or "unknown"
                )
                decision = PolicyDecision(
                    allowed=True,
                    domain=domain,
                    action=action_val,
                    violations=[],
                    enforced_invariants=["POLICY_GUARD_DISABLED_BY_ABLATION"],
                    taint_signal=taint_signal,
                    requires_human_approval=False,
                )
            elif domain == DomainName.AIOPS.value:
                decision = self._evaluate_aiops_policy(
                    payload=payload,
                    context=context,
                    taint_signal=taint_signal,
                )
            elif domain == DomainName.DEVSECOPS.value:
                decision = self._evaluate_devsecops_policy(
                    payload=payload,
                    context=context,
                    taint_signal=taint_signal,
                )
            elif domain == DomainName.CLOUD_FINOPS.value:
                decision = self._evaluate_cloud_finops_policy(
                    payload=payload,
                    context=context,
                    taint_signal=taint_signal,
                )
            else:
                raise ValueError(f"Unsupported domain in PolicyGuard: {domain}")

        if self.telemetry is not None:
            self.telemetry.record_span(
                name="flowguard.policy.audit",
                workflow_id=workflow_id,
                domain=domain,
                status="ALLOWED" if decision.allowed else "BLOCKED",
                duration_ms=timer.elapsed_ms,
                trace_id=trace_id,
                attributes={
                    "allowed": decision.allowed,
                    "action": decision.action,
                    "violations": decision.violations,
                    "taint_detected": taint_signal.detected,
                    "taint_patterns": taint_signal.matched_patterns,
                    "taint_is_authoritative_boundary": taint_signal.is_authoritative_boundary,
                },
                execution_mode_label=ExecutionModeLabel.DETERMINISTIC_HARNESS.value,
            )
        return decision

    def _evaluate_aiops_policy(
        self,
        payload: Dict[str, Any],
        context: Dict[str, Any],
        taint_signal: TaintSignal,
    ) -> PolicyDecision:
        action = str(payload.get("action", ""))
        auth_namespace = str(context.get("namespace", payload.get("namespace", "")))
        auth_token = context.get("human_approval_token")

        violations: List[str] = []
        enforced_invariants: List[str] = [
            "AIOPS_LEAST_PRIVILEGE_ACTION_ALLOWLIST",
            "AIOPS_PROD_STATEFUL_DB_DESTRUCTIVE_GUARD",
            "AIOPS_REPLICA_UPPER_HARD_CAP",
        ]
        requires_approval = False

        if action not in AIOPS_ALLOWED_ACTIONS:
            violations.append(
                f"POLICY_CAPABILITY_DENIED: Action '{action}' is not in workflow allowlist."
            )

        if auth_namespace == "prod-stateful-db" and action in (
            "rollback_deployment",
            "restart_workers",
        ):
            requires_approval = True
            has_valid_auth_token = (
                isinstance(auth_token, str)
                and auth_token.startswith("APPROVAL-PROD-")
                and len(auth_token) >= 16
                and payload.get("human_approval_token") == auth_token
            )
            if not has_valid_auth_token:
                violations.append(
                    f"POLICY_PROD_DB_PROTECTION: Destructive action '{action}' on authoritative "
                    f"namespace 'prod-stateful-db' requires a valid authoritative human_approval_token."
                )

        if "namespace" in payload and payload["namespace"] != auth_namespace:
            violations.append(
                f"POLICY_NAMESPACE_SPOOFING: Payload namespace '{payload['namespace']}' "
                f"conflicts with authoritative namespace '{auth_namespace}'."
            )

        replicas = payload.get("target_replicas")
        if isinstance(replicas, int) and not isinstance(replicas, bool):
            if replicas < 1 or replicas > 32:
                violations.append(
                    f"POLICY_REPLICA_HARD_BOUND: target_replicas={replicas} violates [1, 32] bound."
                )

        return PolicyDecision(
            allowed=len(violations) == 0,
            domain=DomainName.AIOPS.value,
            action=action,
            violations=violations,
            enforced_invariants=enforced_invariants,
            taint_signal=taint_signal,
            requires_human_approval=requires_approval,
        )

    def _evaluate_devsecops_policy(
        self,
        payload: Dict[str, Any],
        context: Dict[str, Any],
        taint_signal: TaintSignal,
    ) -> PolicyDecision:
        decision_str = str(payload.get("merge_decision", ""))
        auth_cvss = context.get("cvss_score", payload.get("cvss_score", 0.0))
        auth_secret = context.get("secret_detected", payload.get("secret_detected", False))

        violations: List[str] = []
        enforced_invariants: List[str] = [
            "DEVSECOPS_DECISION_ALLOWLIST",
            "DEVSECOPS_HIGH_CVSS_MANDATORY_BLOCK",
            "DEVSECOPS_SECRET_DETECTION_MANDATORY_BLOCK_AND_ROTATE",
        ]
        requires_approval = False

        if decision_str not in DEVSECOPS_ALLOWED_DECISIONS:
            violations.append(
                f"POLICY_CAPABILITY_DENIED: merge_decision '{decision_str}' not in allowlist."
            )

        is_high_cvss = (
            isinstance(auth_cvss, (int, float))
            and not isinstance(auth_cvss, bool)
            and float(auth_cvss) >= 7.0
        )
        if is_high_cvss or (auth_secret is True):
            requires_approval = True
            if decision_str != "BLOCK_MERGE":
                violations.append(
                    f"POLICY_SECURITY_GATE_VIOLATION: Authoritative cvss_score={auth_cvss} "
                    f"or secret_detected={auth_secret} strictly requires merge_decision == 'BLOCK_MERGE' "
                    f"(got '{decision_str}')."
                )

        if auth_secret is True and payload.get("rotate_secret") is not True:
            violations.append(
                "POLICY_SECRET_ROTATION_MANDATORY: secret_detected == True requires rotate_secret == True."
            )

        return PolicyDecision(
            allowed=len(violations) == 0,
            domain=DomainName.DEVSECOPS.value,
            action=decision_str,
            violations=violations,
            enforced_invariants=enforced_invariants,
            taint_signal=taint_signal,
            requires_human_approval=requires_approval,
        )

    def _evaluate_cloud_finops_policy(
        self,
        payload: Dict[str, Any],
        context: Dict[str, Any],
        taint_signal: TaintSignal,
    ) -> PolicyDecision:
        decision_str = str(payload.get("provisioning_decision", ""))
        auth_env = str(context.get("environment", payload.get("environment", "dev")))
        auth_hourly = float(
            context.get("hourly_unit_cost_usd", payload.get("hourly_unit_cost_usd", 0.0))
        )
        auth_cap = float(
            context.get(
                "team_monthly_budget_cap_usd",
                payload.get("team_monthly_budget_cap_usd", 0.0),
            )
        )
        true_monthly = round(auth_hourly * 730.0, 2)

        violations: List[str] = []
        enforced_invariants: List[str] = [
            "FINOPS_DECISION_ALLOWLIST",
            "FINOPS_MONTHLY_BUDGET_CAP_GUARD",
            "FINOPS_NONPROD_GPU_QUOTA_CAP",
        ]
        requires_approval = False

        if decision_str not in CLOUD_FINOPS_ALLOWED_DECISIONS:
            violations.append(
                f"POLICY_CAPABILITY_DENIED: provisioning_decision '{decision_str}' not in allowlist."
            )

        if true_monthly > auth_cap:
            requires_approval = True
            if decision_str == "APPROVE_PROVISIONING":
                violations.append(
                    f"POLICY_BUDGET_CAP_BREACH: True monthly cost ${true_monthly:.2f} exceeds "
                    f"authoritative team_monthly_budget_cap_usd ${auth_cap:.2f}; "
                    f"APPROVE_PROVISIONING is forbidden."
                )

        gpu_count = payload.get("requested_gpu_count")
        if (
            auth_env in ("dev", "staging")
            and isinstance(gpu_count, int)
            and not isinstance(gpu_count, bool)
            and gpu_count > 2
            and decision_str == "APPROVE_PROVISIONING"
        ):
            violations.append(
                f"POLICY_NONPROD_GPU_QUOTA_BREACH: Environment '{auth_env}' forbids approving "
                f"requested_gpu_count={gpu_count} (> 2)."
            )

        return PolicyDecision(
            allowed=len(violations) == 0,
            domain=DomainName.CLOUD_FINOPS.value,
            action=decision_str,
            violations=violations,
            enforced_invariants=enforced_invariants,
            taint_signal=taint_signal,
            requires_human_approval=requires_approval,
        )
