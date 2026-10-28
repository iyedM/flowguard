"""Core data models, enums, and epistemic execution labels for FlowGuard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ExecutionModeLabel(str, Enum):
    """Explicit epistemic labels distinguishing execution modes across artifacts."""

    DETERMINISTIC_HARNESS = "deterministic_harness"
    STATEFUL_SIMULATED_SINK = "stateful_simulated_sink"
    LIVE_LLM_INFERENCE = "live_llm_inference"
    EXPORTABLE_N8N_WORKFLOW_JSON = "exportable_n8n_workflow_json"


class DomainName(str, Enum):
    """Supported agentic workflow domains."""

    AIOPS = "aiops_incident_remediation"
    DEVSECOPS = "devsecops_cve_triage"
    CLOUD_FINOPS = "cloud_finops_provisioning"


class ContractVerdict(str, Enum):
    """3-state deterministic contract & cross-field invariant verdict."""

    VALID = "VALID"
    RECOVERABLE_VIOLATION = "RECOVERABLE_VIOLATION"
    UNSAFE_POLICY_BLOCK = "UNSAFE_POLICY_BLOCK"


class IdempotencyState(str, Enum):
    """4-state transactional idempotency lifecycle."""

    PENDING_IN_FLIGHT = "PENDING_IN_FLIGHT"
    COMMITTED = "COMMITTED"
    FAILED_SAFE_TO_RETRY = "FAILED_SAFE_TO_RETRY"
    AMBIGUOUS_REQUIRES_RECONCILIATION = "AMBIGUOUS_REQUIRES_RECONCILIATION"


class FaultClass(str, Enum):
    """Controlled benchmark fault classes (F0 through F5)."""

    F0_NOMINAL = "F0_NOMINAL"
    F1_TRANSIENT_AND_AMBIGUOUS_HTTP = "F1_TRANSIENT_AND_AMBIGUOUS_HTTP"
    F2_SCHEMA_DRIFT = "F2_SCHEMA_DRIFT"
    F3_LLM_MALFORMED = "F3_LLM_MALFORMED"
    F4_DUPLICATE_AND_CONCURRENT_EVENTS = "F4_DUPLICATE_AND_CONCURRENT_EVENTS"
    F5_ADVERSARIAL_INPUT = "F5_ADVERSARIAL_INPUT"


class StrategyMode(str, Enum):
    """Evaluated workflow execution strategies."""

    B1_NATIVE_N8N = "B1_NATIVE_N8N"
    B2_NAIVE_RETRY = "B2_NAIVE_RETRY"
    B3_CONTRACT_ONLY = "B3_CONTRACT_ONLY"
    FLOWGUARD_FULL = "FLOWGUARD_FULL"


class AblationConfig(str, Enum):
    """5-way ablation study configurations for FlowGuard mechanisms."""

    FULL_FLOWGUARD = "full_flowguard"
    NO_TIER1_DRIFT_NORMALIZER = "no_tier1_drift_normalizer"
    NO_TIER2_REPAIR = "no_tier2_repair"
    NO_IDEMPOTENCY_RECONCILIATION = "no_idempotency_reconciliation"
    NO_DETERMINISTIC_POLICY_GUARD = "no_deterministic_policy_guard"


@dataclass
class ContractValidationResult:
    """Result emitted by Mechanism A (Deterministic Contract & Invariant Validator)."""

    verdict: ContractVerdict
    domain: str
    is_valid: bool
    violations: List[str] = field(default_factory=list)
    recoverable_fields: List[str] = field(default_factory=list)
    policy_violation_reason: Optional[str] = None
    validated_payload: Optional[Dict[str, Any]] = None
    execution_mode_label: str = ExecutionModeLabel.DETERMINISTIC_HARNESS.value

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        return data


@dataclass
class TaintSignal:
    """Diagnostic/audit signal from fallible prompt-injection & untrusted text inspection.

    IMPORTANT SCIENTIFIC INVARIANT:
    `is_authoritative_boundary` is strictly False. Taint signals provide observability
    and audit telemetry; they are NEVER relied upon as the sole security boundary.
    """

    detected: bool
    matched_patterns: List[str] = field(default_factory=list)
    untrusted_fields_scanned: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    is_authoritative_boundary: bool = False
    execution_mode_label: str = ExecutionModeLabel.DETERMINISTIC_HARNESS.value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyDecision:
    """Deterministic least-privilege & authoritative attribute policy decision (Mechanism D)."""

    allowed: bool
    domain: str
    action: str
    violations: List[str] = field(default_factory=list)
    enforced_invariants: List[str] = field(default_factory=list)
    taint_signal: Optional[TaintSignal] = None
    requires_human_approval: bool = False
    execution_mode_label: str = ExecutionModeLabel.DETERMINISTIC_HARNESS.value

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.taint_signal is not None:
            data["taint_signal"] = self.taint_signal.to_dict()
        return data


@dataclass
class RecoveryAttempt:
    """Single bounded recovery attempt (Tier-1 symbolic or Tier-2 repair)."""

    tier: int
    turn: int
    strategy_description: str
    candidate_payload: Optional[Dict[str, Any]]
    validation_verdict: ContractVerdict
    remaining_violations: List[str] = field(default_factory=list)
    tokens_used: int = 0
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["validation_verdict"] = self.validation_verdict.value
        return data


@dataclass
class RecoveryResult:
    """Composite outcome of Mechanism B (Two-Tier Bounded Recovery Controller)."""

    recovered: bool
    final_verdict: ContractVerdict
    final_payload: Optional[Dict[str, Any]]
    tier1_applied: bool = False
    tier1_resolved: bool = False
    tier2_turns_used: int = 0
    total_tokens_used: int = 0
    escalated_to_human: bool = False
    terminal_state: str = "UNRECOVERED"
    attempts: List[RecoveryAttempt] = field(default_factory=list)
    execution_mode_label: str = ExecutionModeLabel.DETERMINISTIC_HARNESS.value

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["final_verdict"] = self.final_verdict.value
        data["attempts"] = [a.to_dict() for a in self.attempts]
        return data


@dataclass
class IdempotencyRecord:
    """Row in the 4-state SQLite WAL idempotency ledger (Mechanism C)."""

    idem_key: str
    workflow_id: str
    entity_id: str
    operation: str
    payload_hash: str
    state: IdempotencyState
    attempt_count: int = 1
    sink_receipt: Optional[Dict[str, Any]] = None
    reconciled: bool = False
    created_at: float = 0.0
    updated_at: float = 0.0
    execution_mode_label: str = ExecutionModeLabel.DETERMINISTIC_HARNESS.value

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data


@dataclass
class SinkMutationReceipt:
    """Receipt returned by stateful simulated sink or idempotency proxy."""

    idem_key: str
    entity_id: str
    operation: str
    applied: bool
    idempotency_state: IdempotencyState
    replayed_from_ledger: bool = False
    reconciled_after_timeout: bool = False
    concurrent_duplicate_blocked: bool = False
    halted_for_reconciliation: bool = False
    mutation_count_for_entity: int = 0
    ground_truth_snapshot: Dict[str, Any] = field(default_factory=dict)
    execution_mode_label: str = ExecutionModeLabel.STATEFUL_SIMULATED_SINK.value

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["idempotency_state"] = self.idempotency_state.value
        return data


@dataclass
class TelemetrySpan:
    """OpenTelemetry-compatible span recorded to results/telemetry_events.jsonl."""

    trace_id: str
    span_id: str
    name: str
    workflow_id: str
    domain: str
    status: str
    duration_ms: float
    timestamp_iso: str
    parent_span_id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    execution_mode_label: str = ExecutionModeLabel.DETERMINISTIC_HARNESS.value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowExecutionRecord:
    """End-to-end execution record for a single scenario under a specific strategy."""

    scenario_id: str
    domain: str
    fault_class: str
    strategy: str
    ablation_config: str
    is_nominal_input: bool
    expected_safe_outcome: str
    actual_outcome: str
    state_verified_success: bool
    fault_injected: bool
    fault_recovered: bool
    unsafe_side_effect_occurred: bool
    contract_violation_escaped: bool
    false_rejection_occurred: bool
    escalated_to_human: bool
    duplicate_mutation_prevented: bool
    reconciled_post_commit_timeout: bool
    tier1_used: bool
    tier2_turns: int
    tokens_consumed: int
    latency_ms: float
    idempotency_final_state: str
    taint_detected: bool
    notes: str = ""
    execution_mode_label: str = ExecutionModeLabel.DETERMINISTIC_HARNESS.value

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
