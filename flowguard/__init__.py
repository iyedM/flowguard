"""FlowGuard: Contract-Aware Runtime Verification, Bounded Recovery & Side-Effect Idempotency for Agentic n8n Workflows.

Author: Iyed Mohamed (ORCID: 0009-0008-9493-7510, ESPRIT School of Engineering)
"""

from flowguard.models import (
    AblationConfig,
    ContractValidationResult,
    ContractVerdict,
    DomainName,
    ExecutionModeLabel,
    FaultClass,
    IdempotencyRecord,
    IdempotencyState,
    PolicyDecision,
    RecoveryAttempt,
    RecoveryResult,
    SinkMutationReceipt,
    StrategyMode,
    TaintSignal,
    TelemetrySpan,
    WorkflowExecutionRecord,
)

__version__ = "0.1.0"
__author__ = "Iyed Mohamed"
__orcid__ = "0009-0008-9493-7510"

__all__ = [
    "AblationConfig",
    "ContractValidationResult",
    "ContractVerdict",
    "DomainName",
    "ExecutionModeLabel",
    "FaultClass",
    "IdempotencyRecord",
    "IdempotencyState",
    "PolicyDecision",
    "RecoveryAttempt",
    "RecoveryResult",
    "SinkMutationReceipt",
    "StrategyMode",
    "TaintSignal",
    "TelemetrySpan",
    "WorkflowExecutionRecord",
]
