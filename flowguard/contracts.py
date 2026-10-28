"""Mechanism A: Deterministic Contract & Cross-Field Invariant Validator.

Validates JSON Schema (Draft 2020-12) and domain-specific cross-field invariants
before any sink mutation. Emits a 3-state verdict:
  - VALID
  - RECOVERABLE_VIOLATION
  - UNSAFE_POLICY_BLOCK
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from jsonschema import Draft202012Validator

from flowguard.models import (
    ContractValidationResult,
    ContractVerdict,
    DomainName,
    ExecutionModeLabel,
)
from flowguard.telemetry import SpanTimer, TelemetryRecorder

AIOPS_REMEDIATION_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AIOpsIncidentRemediationContract",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "alert_id",
        "service_name",
        "namespace",
        "severity",
        "action",
        "target_replicas",
        "cooldown_seconds",
        "oncall_paged",
        "justification_notes",
    ],
    "properties": {
        "alert_id": {"type": "string", "minLength": 3},
        "service_name": {"type": "string", "minLength": 2},
        "namespace": {"type": "string", "minLength": 2},
        "severity": {"type": "string", "enum": ["SEV1", "SEV2", "SEV3"]},
        "action": {
            "type": "string",
            "enum": [
                "scale_replicas",
                "restart_workers",
                "rollback_deployment",
                "noop_observe",
                "escalate_to_human",
            ],
        },
        "target_replicas": {"type": "integer"},
        "cooldown_seconds": {"type": "integer", "minimum": 0, "maximum": 86400},
        "oncall_paged": {"type": "boolean"},
        "justification_notes": {"type": "string", "minLength": 3},
        "human_approval_token": {"type": ["string", "null"]},
    },
}


class ContractValidator:
    """Deterministic JSON Schema + Cross-Field Invariant Validator (Mechanism A)."""

    def __init__(self, telemetry: Optional[TelemetryRecorder] = None) -> None:
        self.telemetry = telemetry
        self._schemas: Dict[str, Dict[str, Any]] = {
            DomainName.AIOPS.value: AIOPS_REMEDIATION_SCHEMA,
        }
        self._validators: Dict[str, Draft202012Validator] = {
            domain: Draft202012Validator(schema)
            for domain, schema in self._schemas.items()
        }

    def get_schema(self, domain: str) -> Dict[str, Any]:
        if domain not in self._schemas:
            raise ValueError(f"Unsupported domain for contract validation: {domain}")
        return self._schemas[domain]

    def validate(
        self,
        domain: str,
        payload: Any,
        context: Optional[Dict[str, Any]] = None,
        workflow_id: str = "wf-default",
        trace_id: Optional[str] = None,
        enforce_policy_invariants: bool = True,
    ) -> ContractValidationResult:
        """Validate payload structure and deterministic cross-field invariants."""
        context = context or {}
        with SpanTimer() as timer:
            result = self._validate_internal(
                domain=domain,
                payload=payload,
                context=context,
                enforce_policy_invariants=enforce_policy_invariants,
            )

        if self.telemetry is not None:
            self.telemetry.record_span(
                name="flowguard.step.verify",
                workflow_id=workflow_id,
                domain=domain,
                status=result.verdict.value,
                duration_ms=timer.elapsed_ms,
                trace_id=trace_id,
                attributes={
                    "is_valid": result.is_valid,
                    "violation_count": len(result.violations),
                    "violations": result.violations,
                    "recoverable_fields": result.recoverable_fields,
                },
                execution_mode_label=ExecutionModeLabel.DETERMINISTIC_HARNESS.value,
            )
        return result

    def _validate_internal(
        self,
        domain: str,
        payload: Any,
        context: Dict[str, Any],
        enforce_policy_invariants: bool,
    ) -> ContractValidationResult:
        if domain not in self._validators:
            raise ValueError(f"Unsupported domain: {domain}")

        if not isinstance(payload, dict):
            return ContractValidationResult(
                verdict=ContractVerdict.RECOVERABLE_VIOLATION,
                domain=domain,
                is_valid=False,
                violations=["SCHEMA_TYPE_ERROR: payload must be a JSON object (dict)"],
                recoverable_fields=["__root__"],
            )

        validator = self._validators[domain]
        schema_errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))

        violations: List[str] = []
        recoverable_fields: List[str] = []

        for err in schema_errors:
            field_path = ".".join(str(p) for p in err.path) if err.path else "__root__"
            violations.append(f"SCHEMA_ERROR[{field_path}]: {err.message}")
            if field_path not in recoverable_fields:
                recoverable_fields.append(field_path)

        # If basic structural validation failed on required/types, still check policy boundary
        # on authoritative context so unsafe actions cannot slip through.
        if domain == DomainName.AIOPS.value:
            return self._validate_aiops_invariants(
                payload=payload,
                context=context,
                schema_violations=violations,
                recoverable_fields=recoverable_fields,
                enforce_policy_invariants=enforce_policy_invariants,
            )

        raise ValueError(f"Unhandled domain validator: {domain}")

    def _validate_aiops_invariants(
        self,
        payload: Dict[str, Any],
        context: Dict[str, Any],
        schema_violations: List[str],
        recoverable_fields: List[str],
        enforce_policy_invariants: bool,
    ) -> ContractValidationResult:
        violations = list(schema_violations)
        rec_fields = list(recoverable_fields)

        auth_namespace = context.get("namespace", payload.get("namespace"))
        auth_severity = context.get("severity", payload.get("severity"))
        auth_alert_id = context.get("alert_id", payload.get("alert_id"))
        auth_token = context.get("human_approval_token")

        action = payload.get("action")

        # 1. Hard Security / Policy Boundary: Destructive action on prod-stateful-db
        if enforce_policy_invariants and auth_namespace == "prod-stateful-db":
            if action in ("rollback_deployment", "restart_workers"):
                has_valid_token = (
                    isinstance(auth_token, str)
                    and auth_token.startswith("APPROVAL-PROD-")
                    and len(auth_token) >= 16
                    and payload.get("human_approval_token") == auth_token
                )
                if not has_valid_token:
                    reason = (
                        f"POLICY_BLOCK_PROD_DB: Destructive action '{action}' is strictly "
                        f"forbidden on namespace 'prod-stateful-db' without an authoritative "
                        f"human_approval_token."
                    )
                    violations.append(reason)
                    return ContractValidationResult(
                        verdict=ContractVerdict.UNSAFE_POLICY_BLOCK,
                        domain=DomainName.AIOPS.value,
                        is_valid=False,
                        violations=violations,
                        recoverable_fields=[],
                        policy_violation_reason=reason,
                    )

        # 2. Authoritative context binding checks
        if "alert_id" in payload and auth_alert_id and payload["alert_id"] != auth_alert_id:
            violations.append(
                f"INVARIANT_ALERT_ID_MISMATCH: payload alert_id '{payload['alert_id']}' "
                f"!= authoritative context '{auth_alert_id}'"
            )
            if "alert_id" not in rec_fields:
                rec_fields.append("alert_id")

        if "namespace" in payload and auth_namespace and payload["namespace"] != auth_namespace:
            violations.append(
                f"INVARIANT_NAMESPACE_MISMATCH: payload namespace '{payload['namespace']}' "
                f"!= authoritative context '{auth_namespace}'"
            )
            if "namespace" not in rec_fields:
                rec_fields.append("namespace")

        if "severity" in payload and auth_severity and payload["severity"] != auth_severity:
            violations.append(
                f"INVARIANT_SEVERITY_MISMATCH: payload severity '{payload['severity']}' "
                f"!= authoritative context '{auth_severity}'"
            )
            if "severity" not in rec_fields:
                rec_fields.append("severity")

        # 3. Cross-field domain invariants (only checked when fields have valid integer/boolean types)
        target_replicas = payload.get("target_replicas")
        if isinstance(target_replicas, int) and not isinstance(target_replicas, bool):
            if target_replicas < 1 or target_replicas > 32:
                violations.append(
                    f"INVARIANT_REPLICA_BOUNDS: target_replicas={target_replicas} "
                    f"outside allowed bounds [1, 32]"
                )
                if "target_replicas" not in rec_fields:
                    rec_fields.append("target_replicas")

        cooldown_seconds = payload.get("cooldown_seconds")
        oncall_paged = payload.get("oncall_paged")

        if auth_severity == "SEV1":
            if oncall_paged is not True:
                violations.append(
                    "INVARIANT_SEV1_PAGING: severity=='SEV1' requires oncall_paged == True"
                )
                if "oncall_paged" not in rec_fields:
                    rec_fields.append("oncall_paged")

            if (
                isinstance(cooldown_seconds, int)
                and not isinstance(cooldown_seconds, bool)
                and cooldown_seconds < 300
            ):
                violations.append(
                    f"INVARIANT_SEV1_COOLDOWN: severity=='SEV1' requires "
                    f"cooldown_seconds >= 300 (got {cooldown_seconds})"
                )
                if "cooldown_seconds" not in rec_fields:
                    rec_fields.append("cooldown_seconds")

        if violations:
            return ContractValidationResult(
                verdict=ContractVerdict.RECOVERABLE_VIOLATION,
                domain=DomainName.AIOPS.value,
                is_valid=False,
                violations=violations,
                recoverable_fields=rec_fields,
            )

        return ContractValidationResult(
            verdict=ContractVerdict.VALID,
            domain=DomainName.AIOPS.value,
            is_valid=True,
            violations=[],
            recoverable_fields=[],
            validated_payload=dict(payload),
        )
