"""Mechanism A: Deterministic Contract & Cross-Field Invariant Validator.

Validates JSON Schema (Draft 2020-12) and domain-specific cross-field invariants
across all three domains:
  1. Domain 1: `aiops_incident_remediation`
  2. Domain 2: `devsecops_cve_triage`
  3. Domain 3: `cloud_finops_provisioning`

Emits a 3-state verdict:
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

DEVSECOPS_TRIAGE_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "DevSecOpsCveAndSecretTriageContract",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "pr_number",
        "repository",
        "cve_id",
        "cvss_score",
        "secret_detected",
        "merge_decision",
        "rotate_secret",
        "quarantine_artifact",
        "justification_notes",
    ],
    "properties": {
        "pr_number": {"type": "string", "minLength": 2},
        "repository": {"type": "string", "minLength": 2},
        "cve_id": {"type": "string", "minLength": 3},
        "cvss_score": {"type": "number", "minimum": 0.0, "maximum": 10.0},
        "secret_detected": {"type": "boolean"},
        "merge_decision": {
            "type": "string",
            "enum": [
                "ALLOW_MERGE",
                "BLOCK_MERGE",
                "HOLD_FOR_SECURITY_REVIEW",
            ],
        },
        "rotate_secret": {"type": "boolean"},
        "quarantine_artifact": {"type": "boolean"},
        "justification_notes": {"type": "string", "minLength": 3},
    },
}

CLOUD_FINOPS_PROVISIONING_SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "CloudFinOpsQuotaProvisioningContract",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "request_id",
        "team_name",
        "environment",
        "requested_vcpu",
        "requested_gpu_count",
        "hourly_unit_cost_usd",
        "computed_monthly_cost_usd",
        "team_monthly_budget_cap_usd",
        "provisioning_decision",
        "justification_notes",
    ],
    "properties": {
        "request_id": {"type": "string", "minLength": 3},
        "team_name": {"type": "string", "minLength": 2},
        "environment": {"type": "string", "enum": ["dev", "staging", "prod"]},
        "requested_vcpu": {"type": "integer", "minimum": 1, "maximum": 512},
        "requested_gpu_count": {"type": "integer", "minimum": 0},
        "hourly_unit_cost_usd": {"type": "number", "minimum": 0.01},
        "computed_monthly_cost_usd": {"type": "number", "minimum": 0.0},
        "team_monthly_budget_cap_usd": {"type": "number", "minimum": 1.0},
        "provisioning_decision": {
            "type": "string",
            "enum": [
                "APPROVE_PROVISIONING",
                "HOLD_FOR_FINOPS_APPROVAL",
                "REJECT_QUOTA_EXCEEDED",
            ],
        },
        "justification_notes": {"type": "string", "minLength": 3},
    },
}


class ContractValidator:
    """Deterministic JSON Schema + Cross-Field Invariant Validator (Mechanism A)."""

    def __init__(self, telemetry: Optional[TelemetryRecorder] = None) -> None:
        self.telemetry = telemetry
        self._schemas: Dict[str, Dict[str, Any]] = {
            DomainName.AIOPS.value: AIOPS_REMEDIATION_SCHEMA,
            DomainName.DEVSECOPS.value: DEVSECOPS_TRIAGE_SCHEMA,
            DomainName.CLOUD_FINOPS.value: CLOUD_FINOPS_PROVISIONING_SCHEMA,
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

        if domain == DomainName.AIOPS.value:
            return self._validate_aiops_invariants(
                payload=payload,
                context=context,
                schema_violations=violations,
                recoverable_fields=recoverable_fields,
                enforce_policy_invariants=enforce_policy_invariants,
            )
        if domain == DomainName.DEVSECOPS.value:
            return self._validate_devsecops_invariants(
                payload=payload,
                context=context,
                schema_violations=violations,
                recoverable_fields=recoverable_fields,
                enforce_policy_invariants=enforce_policy_invariants,
            )
        if domain == DomainName.CLOUD_FINOPS.value:
            return self._validate_cloud_finops_invariants(
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

        # 3. Cross-field domain invariants
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

    def _validate_devsecops_invariants(
        self,
        payload: Dict[str, Any],
        context: Dict[str, Any],
        schema_violations: List[str],
        recoverable_fields: List[str],
        enforce_policy_invariants: bool,
    ) -> ContractValidationResult:
        violations = list(schema_violations)
        rec_fields = list(recoverable_fields)

        auth_pr = context.get("pr_number", payload.get("pr_number"))
        auth_cvss = context.get("cvss_score", payload.get("cvss_score"))
        auth_secret = context.get("secret_detected", payload.get("secret_detected"))

        merge_decision = payload.get("merge_decision")

        is_high_risk = (
            isinstance(auth_cvss, (int, float))
            and not isinstance(auth_cvss, bool)
            and float(auth_cvss) >= 7.0
        ) or (auth_secret is True)

        # 1. Hard Security Policy Boundary: Never allow merge when authoritative CVSS >= 7.0 or secret_detected == True
        if enforce_policy_invariants and is_high_risk and merge_decision == "ALLOW_MERGE":
            reason = (
                f"POLICY_BLOCK_HIGH_RISK_MERGE: merge_decision=='ALLOW_MERGE' is strictly "
                f"forbidden when authoritative cvss_score={auth_cvss} (>=7.0) or "
                f"secret_detected={auth_secret}."
            )
            violations.append(reason)
            return ContractValidationResult(
                verdict=ContractVerdict.UNSAFE_POLICY_BLOCK,
                domain=DomainName.DEVSECOPS.value,
                is_valid=False,
                violations=violations,
                recoverable_fields=[],
                policy_violation_reason=reason,
            )

        # 2. Authoritative context binding checks
        if "pr_number" in payload and auth_pr and payload["pr_number"] != auth_pr:
            violations.append(
                f"INVARIANT_PR_MISMATCH: payload pr_number '{payload['pr_number']}' != '{auth_pr}'"
            )
            if "pr_number" not in rec_fields:
                rec_fields.append("pr_number")

        payload_cvss = payload.get("cvss_score")
        if (
            isinstance(payload_cvss, (int, float))
            and not isinstance(payload_cvss, bool)
            and isinstance(auth_cvss, (int, float))
            and abs(float(payload_cvss) - float(auth_cvss)) > 1e-4
        ):
            violations.append(
                f"INVARIANT_CVSS_SPOOFING: payload cvss_score={payload_cvss} "
                f"!= authoritative scanner cvss_score={auth_cvss}"
            )
            if "cvss_score" not in rec_fields:
                rec_fields.append("cvss_score")

        if (
            "secret_detected" in payload
            and isinstance(auth_secret, bool)
            and payload["secret_detected"] != auth_secret
        ):
            violations.append(
                f"INVARIANT_SECRET_FLAG_MISMATCH: payload secret_detected={payload['secret_detected']} "
                f"!= authoritative secret_detected={auth_secret}"
            )
            if "secret_detected" not in rec_fields:
                rec_fields.append("secret_detected")

        # 3. Cross-field invariants
        if enforce_policy_invariants and is_high_risk and merge_decision != "BLOCK_MERGE":
            violations.append(
                "INVARIANT_HIGH_RISK_BLOCK_REQUIRED: cvss_score >= 7.0 or secret_detected == True "
                "requires merge_decision == 'BLOCK_MERGE'"
            )
            if "merge_decision" not in rec_fields:
                rec_fields.append("merge_decision")

        if enforce_policy_invariants and auth_secret is True and payload.get("rotate_secret") is not True:
            violations.append(
                "INVARIANT_SECRET_ROTATION_REQUIRED: secret_detected == True requires rotate_secret == True"
            )
            if "rotate_secret" not in rec_fields:
                rec_fields.append("rotate_secret")

        if (
            enforce_policy_invariants
            and isinstance(auth_cvss, (int, float))
            and not isinstance(auth_cvss, bool)
            and float(auth_cvss) >= 9.0
            and payload.get("quarantine_artifact") is not True
        ):
            violations.append(
                "INVARIANT_CRITICAL_CVE_QUARANTINE: cvss_score >= 9.0 requires quarantine_artifact == True"
            )
            if "quarantine_artifact" not in rec_fields:
                rec_fields.append("quarantine_artifact")

        if violations:
            return ContractValidationResult(
                verdict=ContractVerdict.RECOVERABLE_VIOLATION,
                domain=DomainName.DEVSECOPS.value,
                is_valid=False,
                violations=violations,
                recoverable_fields=rec_fields,
            )

        return ContractValidationResult(
            verdict=ContractVerdict.VALID,
            domain=DomainName.DEVSECOPS.value,
            is_valid=True,
            violations=[],
            recoverable_fields=[],
            validated_payload=dict(payload),
        )

    def _validate_cloud_finops_invariants(
        self,
        payload: Dict[str, Any],
        context: Dict[str, Any],
        schema_violations: List[str],
        recoverable_fields: List[str],
        enforce_policy_invariants: bool,
    ) -> ContractValidationResult:
        violations = list(schema_violations)
        rec_fields = list(recoverable_fields)

        auth_req_id = context.get("request_id", payload.get("request_id"))
        auth_env = context.get("environment", payload.get("environment"))
        auth_hourly = context.get("hourly_unit_cost_usd", payload.get("hourly_unit_cost_usd"))
        auth_budget_cap = context.get(
            "team_monthly_budget_cap_usd", payload.get("team_monthly_budget_cap_usd")
        )

        decision = payload.get("provisioning_decision")

        true_monthly_cost: Optional[float] = None
        if isinstance(auth_hourly, (int, float)) and not isinstance(auth_hourly, bool):
            true_monthly_cost = round(float(auth_hourly) * 730.0, 2)

        exceeds_budget = (
            true_monthly_cost is not None
            and isinstance(auth_budget_cap, (int, float))
            and not isinstance(auth_budget_cap, bool)
            and true_monthly_cost > float(auth_budget_cap)
        )

        # 1. Hard Policy Boundary: Cannot APPROVE_PROVISIONING when authoritative monthly cost exceeds team budget cap
        if enforce_policy_invariants and exceeds_budget and decision == "APPROVE_PROVISIONING":
            reason = (
                f"POLICY_BLOCK_BUDGET_CAP_EXCEEDED: provisioning_decision=='APPROVE_PROVISIONING' "
                f"is forbidden because authoritative monthly cost (${true_monthly_cost:.2f}) "
                f"exceeds team_monthly_budget_cap_usd (${float(auth_budget_cap):.2f})."
            )
            violations.append(reason)
            return ContractValidationResult(
                verdict=ContractVerdict.UNSAFE_POLICY_BLOCK,
                domain=DomainName.CLOUD_FINOPS.value,
                is_valid=False,
                violations=violations,
                recoverable_fields=[],
                policy_violation_reason=reason,
            )

        # 2. Authoritative context binding checks
        if "request_id" in payload and auth_req_id and payload["request_id"] != auth_req_id:
            violations.append(
                f"INVARIANT_REQUEST_ID_MISMATCH: payload request_id '{payload['request_id']}' != '{auth_req_id}'"
            )
            if "request_id" not in rec_fields:
                rec_fields.append("request_id")

        if "environment" in payload and auth_env and payload["environment"] != auth_env:
            violations.append(
                f"INVARIANT_ENVIRONMENT_MISMATCH: payload environment '{payload['environment']}' != '{auth_env}'"
            )
            if "environment" not in rec_fields:
                rec_fields.append("environment")

        payload_cap = payload.get("team_monthly_budget_cap_usd")
        if (
            isinstance(payload_cap, (int, float))
            and not isinstance(payload_cap, bool)
            and isinstance(auth_budget_cap, (int, float))
            and abs(float(payload_cap) - float(auth_budget_cap)) > 0.01
        ):
            violations.append(
                f"INVARIANT_BUDGET_CAP_SPOOFING: payload budget cap {payload_cap} != authoritative {auth_budget_cap}"
            )
            if "team_monthly_budget_cap_usd" not in rec_fields:
                rec_fields.append("team_monthly_budget_cap_usd")

        # 3. Cross-field arithmetic and quota invariants
        computed_monthly = payload.get("computed_monthly_cost_usd")
        if (
            true_monthly_cost is not None
            and isinstance(computed_monthly, (int, float))
            and not isinstance(computed_monthly, bool)
        ):
            if abs(true_monthly_cost - float(computed_monthly)) > 0.05:
                violations.append(
                    f"INVARIANT_ARITHMETIC_MONTHLY_COST: computed_monthly_cost_usd={computed_monthly} "
                    f"!= hourly_unit_cost_usd * 730 ({true_monthly_cost:.2f})"
                )
                if "computed_monthly_cost_usd" not in rec_fields:
                    rec_fields.append("computed_monthly_cost_usd")

        if enforce_policy_invariants and exceeds_budget and decision != "HOLD_FOR_FINOPS_APPROVAL":
            violations.append(
                "INVARIANT_BUDGET_CAP_HOLD_REQUIRED: monthly cost > team_monthly_budget_cap_usd "
                "requires provisioning_decision == 'HOLD_FOR_FINOPS_APPROVAL'"
            )
            if "provisioning_decision" not in rec_fields:
                rec_fields.append("provisioning_decision")

        gpu_count = payload.get("requested_gpu_count")
        if (
            auth_env in ("dev", "staging")
            and isinstance(gpu_count, int)
            and not isinstance(gpu_count, bool)
            and gpu_count > 2
        ):
            violations.append(
                f"INVARIANT_NONPROD_GPU_QUOTA: environment '{auth_env}' limits "
                f"requested_gpu_count <= 2 (got {gpu_count})"
            )
            if "requested_gpu_count" not in rec_fields:
                rec_fields.append("requested_gpu_count")

        if violations:
            return ContractValidationResult(
                verdict=ContractVerdict.RECOVERABLE_VIOLATION,
                domain=DomainName.CLOUD_FINOPS.value,
                is_valid=False,
                violations=violations,
                recoverable_fields=rec_fields,
            )

        return ContractValidationResult(
            verdict=ContractVerdict.VALID,
            domain=DomainName.CLOUD_FINOPS.value,
            is_valid=True,
            violations=[],
            recoverable_fields=[],
            validated_payload=dict(payload),
        )
