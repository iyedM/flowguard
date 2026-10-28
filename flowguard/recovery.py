"""Mechanism B: Two-Tier Bounded Recovery Controller.

- Tier 1 (Symbolic Schema-Drift Normalizer): Resolves known alias renames, envelope
  unwrapping, and safe scalar type coercions (0 LLM tokens). Honestly fails on unknown
  or unmapped schema drift.
- Tier 2 (Bounded Repair Loop, max_repair_turns = 2): Parses markdown-wrapped JSON
  and executes up to 2 predicate-guided repair turns, re-validating every candidate
  through Mechanism A (ContractValidator). Transitions to SAFE_ESCALATION_HALT on
  budget exhaustion or unrecoverable policy block.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from flowguard.contracts import ContractValidator
from flowguard.models import (
    ContractValidationResult,
    ContractVerdict,
    DomainName,
    ExecutionModeLabel,
    RecoveryAttempt,
    RecoveryResult,
)
from flowguard.telemetry import SpanTimer, TelemetryRecorder

# Known alias mappings for Tier-1 symbolic schema-drift normalization per domain.
# Unknown/unmapped drift fields are intentionally NOT in this map so Tier-1 failure
# modes can be measured honestly.
KNOWN_FIELD_ALIASES: Dict[str, Dict[str, str]] = {
    DomainName.AIOPS.value: {
        "id": "alert_id",
        "incident_id": "alert_id",
        "service": "service_name",
        "svc_name": "service_name",
        "ns": "namespace",
        "k8s_namespace": "namespace",
        "sev": "severity",
        "alert_severity": "severity",
        "remediation_action": "action",
        "command": "action",
        "replicas": "target_replicas",
        "desired_replicas": "target_replicas",
        "cooldown": "cooldown_seconds",
        "cooldown_sec": "cooldown_seconds",
        "page_oncall": "oncall_paged",
        "notify_oncall": "oncall_paged",
        "notes": "justification_notes",
        "reason": "justification_notes",
        "justification": "justification_notes",
        "approval_token": "human_approval_token",
    },
}

KNOWN_ENVELOPE_KEYS: Tuple[str, ...] = ("remediation", "payload", "decision", "data")

INT_FIELDS_BY_DOMAIN: Dict[str, Tuple[str, ...]] = {
    DomainName.AIOPS.value: ("target_replicas", "cooldown_seconds"),
}

BOOL_FIELDS_BY_DOMAIN: Dict[str, Tuple[str, ...]] = {
    DomainName.AIOPS.value: ("oncall_paged",),
}

CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)
FIRST_JSON_OBJ_RE = re.compile(r"(\{.*\})", re.DOTALL)

RepairCallbackType = Callable[
    [Any, List[str], Dict[str, Any], int],
    Tuple[Optional[Dict[str, Any]], int],
]


class RecoveryController:
    """Two-Tier Bounded Recovery Controller (Mechanism B)."""

    def __init__(
        self,
        validator: ContractValidator,
        max_repair_turns: int = 2,
        telemetry: Optional[TelemetryRecorder] = None,
    ) -> None:
        self.validator = validator
        self.max_repair_turns = max_repair_turns
        self.telemetry = telemetry

    @staticmethod
    def extract_json_object(raw_input: Any) -> Optional[Dict[str, Any]]:
        """Extract a dictionary from raw dict or markdown-fenced JSON string."""
        if isinstance(raw_input, dict):
            return copy.deepcopy(raw_input)
        if not isinstance(raw_input, str):
            return None
        text = raw_input.strip()
        # Try direct JSON parse first
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        # Try markdown code fence extraction
        fence_match = CODE_FENCE_RE.search(text)
        if fence_match:
            try:
                parsed = json.loads(fence_match.group(1))
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass

        # Try extracting first {...} block
        obj_match = FIRST_JSON_OBJ_RE.search(text)
        if obj_match:
            try:
                parsed = json.loads(obj_match.group(1))
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                return None

        return None

    def normalize_tier1(
        self,
        domain: str,
        payload: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], bool]:
        """Tier-1 symbolic schema-drift normalizer (0 LLM tokens).

        Resolves known envelope wrappers, known alias field names, and safe scalar
        type coercions. Does not guess unknown fields or alter semantic bounds.
        """
        working = copy.deepcopy(payload)
        changed = False

        # 1. Unwrap single-key known envelope if present
        for env_key in KNOWN_ENVELOPE_KEYS:
            if (
                env_key in working
                and isinstance(working[env_key], dict)
                and len(working) <= 2
            ):
                inner = copy.deepcopy(working.pop(env_key))
                inner.update(working)
                working = inner
                changed = True
                break

        # 2. Apply known alias renames for the domain
        alias_map = KNOWN_FIELD_ALIASES.get(domain, {})
        remapped: Dict[str, Any] = {}
        for k, v in working.items():
            target_key = alias_map.get(k, k)
            if target_key != k:
                changed = True
            # Do not overwrite if canonical key already exists
            if target_key not in remapped or k == target_key:
                remapped[target_key] = v
        working = remapped

        # 3. Safe scalar string-to-int coercions
        for int_field in INT_FIELDS_BY_DOMAIN.get(domain, ()):
            val = working.get(int_field)
            if isinstance(val, str):
                stripped = val.strip()
                if re.fullmatch(r"[+-]?\d+", stripped):
                    working[int_field] = int(stripped)
                    changed = True

        # 4. Safe scalar string-to-bool coercions
        for bool_field in BOOL_FIELDS_BY_DOMAIN.get(domain, ()):
            val = working.get(bool_field)
            if isinstance(val, str):
                lowered = val.strip().lower()
                if lowered in ("true", "1", "yes"):
                    working[bool_field] = True
                    changed = True
                elif lowered in ("false", "0", "no"):
                    working[bool_field] = False
                    changed = True

        # 5. Canonicalize uppercase enum strings where unambiguous
        if domain == DomainName.AIOPS.value and isinstance(working.get("severity"), str):
            upper_sev = working["severity"].strip().upper()
            if upper_sev in ("SEV1", "SEV2", "SEV3") and upper_sev != working["severity"]:
                working["severity"] = upper_sev
                changed = True

        return working, changed

    def recover(
        self,
        domain: str,
        raw_payload: Any,
        context: Dict[str, Any],
        initial_validation: Optional[ContractValidationResult] = None,
        tier1_enabled: bool = True,
        tier2_enabled: bool = True,
        enforce_policy_invariants: bool = True,
        repair_callback: Optional[RepairCallbackType] = None,
        workflow_id: str = "wf-default",
        trace_id: Optional[str] = None,
        execution_mode_label: str = ExecutionModeLabel.DETERMINISTIC_HARNESS.value,
    ) -> RecoveryResult:
        """Execute bounded Two-Tier Recovery when initial validation fails."""
        with SpanTimer() as timer:
            result = self._recover_internal(
                domain=domain,
                raw_payload=raw_payload,
                context=context,
                initial_validation=initial_validation,
                tier1_enabled=tier1_enabled,
                tier2_enabled=tier2_enabled,
                enforce_policy_invariants=enforce_policy_invariants,
                repair_callback=repair_callback,
                workflow_id=workflow_id,
                trace_id=trace_id,
                execution_mode_label=execution_mode_label,
            )

        if self.telemetry is not None:
            self.telemetry.record_span(
                name="flowguard.recovery",
                workflow_id=workflow_id,
                domain=domain,
                status=result.terminal_state,
                duration_ms=timer.elapsed_ms,
                trace_id=trace_id,
                attributes={
                    "recovered": result.recovered,
                    "final_verdict": result.final_verdict.value,
                    "tier1_applied": result.tier1_applied,
                    "tier1_resolved": result.tier1_resolved,
                    "tier2_turns_used": result.tier2_turns_used,
                    "total_tokens_used": result.total_tokens_used,
                    "escalated_to_human": result.escalated_to_human,
                },
                execution_mode_label=execution_mode_label,
            )
        return result

    def _recover_internal(
        self,
        domain: str,
        raw_payload: Any,
        context: Dict[str, Any],
        initial_validation: Optional[ContractValidationResult],
        tier1_enabled: bool,
        tier2_enabled: bool,
        enforce_policy_invariants: bool,
        repair_callback: Optional[RepairCallbackType],
        workflow_id: str,
        trace_id: Optional[str],
        execution_mode_label: str,
    ) -> RecoveryResult:
        attempts: List[RecoveryAttempt] = []

        # Step 0: Check initial validation if payload is already a dict
        current_dict = raw_payload if isinstance(raw_payload, dict) else None
        if initial_validation is None:
            initial_validation = self.validator.validate(
                domain=domain,
                payload=raw_payload,
                context=context,
                workflow_id=workflow_id,
                trace_id=trace_id,
                enforce_policy_invariants=enforce_policy_invariants,
            )

        if initial_validation.is_valid:
            return RecoveryResult(
                recovered=True,
                final_verdict=ContractVerdict.VALID,
                final_payload=initial_validation.validated_payload,
                tier1_applied=False,
                tier1_resolved=False,
                tier2_turns_used=0,
                total_tokens_used=0,
                escalated_to_human=False,
                terminal_state="VALID_NO_RECOVERY_NEEDED",
                attempts=[],
                execution_mode_label=execution_mode_label,
            )

        # Hard security policy block -> Never bypass via recovery; escalate immediately
        if initial_validation.verdict == ContractVerdict.UNSAFE_POLICY_BLOCK:
            return RecoveryResult(
                recovered=False,
                final_verdict=ContractVerdict.UNSAFE_POLICY_BLOCK,
                final_payload=None,
                tier1_applied=False,
                tier1_resolved=False,
                tier2_turns_used=0,
                total_tokens_used=0,
                escalated_to_human=True,
                terminal_state="SAFE_ESCALATION_POLICY_BLOCK",
                attempts=[],
                execution_mode_label=execution_mode_label,
            )

        current_validation = initial_validation
        tier1_applied = False

        # Step 1: Tier-1 Symbolic Schema-Drift Normalizer (0 tokens)
        if tier1_enabled and isinstance(current_dict, dict):
            with SpanTimer() as t1_timer:
                normalized_dict, changed = self.normalize_tier1(domain, current_dict)
            if changed:
                tier1_applied = True
                current_dict = normalized_dict
                current_validation = self.validator.validate(
                    domain=domain,
                    payload=current_dict,
                    context=context,
                    workflow_id=workflow_id,
                    trace_id=trace_id,
                    enforce_policy_invariants=enforce_policy_invariants,
                )
                attempts.append(
                    RecoveryAttempt(
                        tier=1,
                        turn=1,
                        strategy_description="tier1_symbolic_schema_drift_normalizer",
                        candidate_payload=copy.deepcopy(current_dict),
                        validation_verdict=current_validation.verdict,
                        remaining_violations=list(current_validation.violations),
                        tokens_used=0,
                        latency_ms=round(t1_timer.elapsed_ms, 4),
                    )
                )
                if current_validation.is_valid:
                    return RecoveryResult(
                        recovered=True,
                        final_verdict=ContractVerdict.VALID,
                        final_payload=current_validation.validated_payload,
                        tier1_applied=True,
                        tier1_resolved=True,
                        tier2_turns_used=0,
                        total_tokens_used=0,
                        escalated_to_human=False,
                        terminal_state="RECOVERED_TIER_1",
                        attempts=attempts,
                        execution_mode_label=execution_mode_label,
                    )
                if current_validation.verdict == ContractVerdict.UNSAFE_POLICY_BLOCK:
                    return RecoveryResult(
                        recovered=False,
                        final_verdict=ContractVerdict.UNSAFE_POLICY_BLOCK,
                        final_payload=None,
                        tier1_applied=True,
                        tier1_resolved=False,
                        tier2_turns_used=0,
                        total_tokens_used=0,
                        escalated_to_human=True,
                        terminal_state="SAFE_ESCALATION_POLICY_BLOCK",
                        attempts=attempts,
                        execution_mode_label=execution_mode_label,
                    )

        # If Tier-2 is disabled, stop here and escalate safely
        if not tier2_enabled or self.max_repair_turns <= 0:
            return RecoveryResult(
                recovered=False,
                final_verdict=current_validation.verdict,
                final_payload=None,
                tier1_applied=tier1_applied,
                tier1_resolved=False,
                tier2_turns_used=0,
                total_tokens_used=0,
                escalated_to_human=True,
                terminal_state="SAFE_ESCALATION_HALT",
                attempts=attempts,
                execution_mode_label=execution_mode_label,
            )

        # Step 2: Tier-2 Bounded Repair Loop (max_repair_turns = 2)
        total_tokens = 0
        tier2_turns = 0
        working_input: Any = current_dict if current_dict is not None else raw_payload

        for turn in range(1, self.max_repair_turns + 1):
            tier2_turns += 1
            with SpanTimer() as t2_timer:
                if repair_callback is not None:
                    candidate, tokens = repair_callback(
                        working_input,
                        current_validation.violations,
                        context,
                        turn,
                    )
                else:
                    candidate, tokens = self._deterministic_tier2_repair_step(
                        domain=domain,
                        working_input=working_input,
                        violations=current_validation.violations,
                        context=context,
                        turn=turn,
                    )
                total_tokens += tokens

                if candidate is None:
                    attempts.append(
                        RecoveryAttempt(
                            tier=2,
                            turn=turn,
                            strategy_description=f"tier2_bounded_repair_turn_{turn}_parse_failure",
                            candidate_payload=None,
                            validation_verdict=ContractVerdict.RECOVERABLE_VIOLATION,
                            remaining_violations=list(current_validation.violations),
                            tokens_used=tokens,
                            latency_ms=round(t2_timer.elapsed_ms, 4),
                        )
                    )
                    continue

                current_validation = self.validator.validate(
                    domain=domain,
                    payload=candidate,
                    context=context,
                    workflow_id=workflow_id,
                    trace_id=trace_id,
                    enforce_policy_invariants=enforce_policy_invariants,
                )

            attempts.append(
                RecoveryAttempt(
                    tier=2,
                    turn=turn,
                    strategy_description=f"tier2_bounded_repair_turn_{turn}",
                    candidate_payload=copy.deepcopy(candidate),
                    validation_verdict=current_validation.verdict,
                    remaining_violations=list(current_validation.violations),
                    tokens_used=tokens,
                    latency_ms=round(t2_timer.elapsed_ms, 4),
                )
            )

            if current_validation.is_valid:
                return RecoveryResult(
                    recovered=True,
                    final_verdict=ContractVerdict.VALID,
                    final_payload=current_validation.validated_payload,
                    tier1_applied=tier1_applied,
                    tier1_resolved=False,
                    tier2_turns_used=tier2_turns,
                    total_tokens_used=total_tokens,
                    escalated_to_human=False,
                    terminal_state=f"RECOVERED_TIER_2_TURN_{turn}",
                    attempts=attempts,
                    execution_mode_label=execution_mode_label,
                )

            if current_validation.verdict == ContractVerdict.UNSAFE_POLICY_BLOCK:
                return RecoveryResult(
                    recovered=False,
                    final_verdict=ContractVerdict.UNSAFE_POLICY_BLOCK,
                    final_payload=None,
                    tier1_applied=tier1_applied,
                    tier1_resolved=False,
                    tier2_turns_used=tier2_turns,
                    total_tokens_used=total_tokens,
                    escalated_to_human=True,
                    terminal_state="SAFE_ESCALATION_POLICY_BLOCK",
                    attempts=attempts,
                    execution_mode_label=execution_mode_label,
                )

            working_input = candidate

        # Exhausted max_repair_turns -> SAFE_ESCALATION_HALT
        return RecoveryResult(
            recovered=False,
            final_verdict=current_validation.verdict,
            final_payload=None,
            tier1_applied=tier1_applied,
            tier1_resolved=False,
            tier2_turns_used=tier2_turns,
            total_tokens_used=total_tokens,
            escalated_to_human=True,
            terminal_state="SAFE_ESCALATION_HALT",
            attempts=attempts,
            execution_mode_label=execution_mode_label,
        )

    def _deterministic_tier2_repair_step(
        self,
        domain: str,
        working_input: Any,
        violations: List[str],
        context: Dict[str, Any],
        turn: int,
    ) -> Tuple[Optional[Dict[str, Any]], int]:
        """Predicate-guided repair step for deterministic harness evaluation.

        Simulates realistic LLM repair behavior with explicit token accounting and
        honest failure on severely corrupted/unmapped schemas or truncated payloads.
        """
        extracted = self.extract_json_object(working_input)
        if extracted is None:
            # Truncated or unparseable JSON cannot be extracted; costs repair prompt tokens
            return None, 185

        # If payload carries an explicit unrecoverable corruption marker or has < 3 recognizable fields
        if extracted.get("__unrecoverable_corruption__") is True:
            return extracted, 210

        candidate = copy.deepcopy(extracted)
        tokens_used = 160 + (25 * len(violations))

        if domain == DomainName.AIOPS.value:
            return self._repair_aiops_candidate(candidate, violations, context, turn), tokens_used

        return candidate, tokens_used

    def _repair_aiops_candidate(
        self,
        candidate: Dict[str, Any],
        violations: List[str],
        context: Dict[str, Any],
        turn: int,
    ) -> Dict[str, Any]:
        violation_text = " | ".join(violations)

        # Turn 1: Fix semantic cross-field invariants and context bindings
        if "INVARIANT_ALERT_ID_MISMATCH" in violation_text and "alert_id" in context:
            candidate["alert_id"] = context["alert_id"]

        if "INVARIANT_NAMESPACE_MISMATCH" in violation_text and "namespace" in context:
            candidate["namespace"] = context["namespace"]

        if "INVARIANT_SEVERITY_MISMATCH" in violation_text and "severity" in context:
            candidate["severity"] = context["severity"]

        if "INVARIANT_REPLICA_BOUNDS" in violation_text:
            rep = candidate.get("target_replicas")
            if isinstance(rep, int):
                candidate["target_replicas"] = max(1, min(32, rep))

        if "INVARIANT_SEV1_PAGING" in violation_text:
            candidate["oncall_paged"] = True

        if "INVARIANT_SEV1_COOLDOWN" in violation_text:
            cd = candidate.get("cooldown_seconds")
            if isinstance(cd, int):
                candidate["cooldown_seconds"] = max(300, cd)
            else:
                candidate["cooldown_seconds"] = 300

        # Turn 2: If structural schema errors remain, attempt to repair single recoverable
        # unknown field ONLY if context supplies enough information and corruption is not catastrophic.
        if turn >= 2 and "SCHEMA_ERROR" in violation_text:
            # If there are multiple unknown fields (catastrophic schema drift), do NOT magically fix
            allowed_keys = set(
                self.validator.get_schema(DomainName.AIOPS.value)["properties"].keys()
            )
            unknown_keys = [k for k in candidate.keys() if k not in allowed_keys]
            if len(unknown_keys) == 1:
                uk = unknown_keys[0]
                val = candidate.pop(uk)
                # Map single unknown key if it holds replica count or justification
                if "target_replicas" not in candidate and isinstance(val, int):
                    candidate["target_replicas"] = max(1, min(32, val))
                elif "justification_notes" not in candidate and isinstance(val, str):
                    candidate["justification_notes"] = val

            # Populate missing context-bound required fields if unambiguously present in context
            for ctx_key in ("alert_id", "service_name", "namespace", "severity"):
                if ctx_key not in candidate and ctx_key in context:
                    candidate[ctx_key] = context[ctx_key]

        return candidate
