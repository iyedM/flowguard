"""Mechanism D: Least-Privilege Policy Engine & Untrusted Taint Auditor.

Enforces strict separation between:
1. Deterministic Security Boundary: Authoritative context attributes & capability allowlists
   (an LLM can never override a security invariant).
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

# Heuristic patterns for untrusted text taint auditing (observability signal only).
# Deliberately realistic: catches common overt prompt-injection patterns while subtle
# semantic phrasing may evade regex detection—proving why deterministic attribute
# policies are required as the actual security boundary.
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
                decision = PolicyDecision(
                    allowed=True,
                    domain=domain,
                    action=str(payload.get("action", "unknown")),
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

        # 1. Capability allowlist check
        if action not in AIOPS_ALLOWED_ACTIONS:
            violations.append(
                f"POLICY_CAPABILITY_DENIED: Action '{action}' is not in workflow allowlist."
            )

        # 2. Hard deterministic rule on authoritative namespace (immune to LLM spoofing or subtle prompt injection)
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

        # 3. Prevent LLM from bypassing prod-stateful-db by rewriting payload['namespace']
        if "namespace" in payload and payload["namespace"] != auth_namespace:
            violations.append(
                f"POLICY_NAMESPACE_SPOOFING: Payload namespace '{payload['namespace']}' "
                f"conflicts with authoritative namespace '{auth_namespace}'."
            )

        # 4. Prevent extreme resource exhaustion via replica count
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
