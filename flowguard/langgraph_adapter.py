"""LangGraph & Agent State Graph Middleware Adapter for FlowGuard (`FlowGuardMiddleware`)."""

from __future__ import annotations

import copy
from typing import Any, Callable, Dict, Optional

from flowguard.contracts import ContractValidator
from flowguard.idempotency import IdempotencyLedger
from flowguard.models import ContractVerdict, IdempotencyState
from flowguard.policy_guard import PolicyGuard
from flowguard.recovery import RecoveryController
from flowguard.telemetry import TelemetryRecorder


class FlowGuardMiddleware:
    """Drop-in middleware wrapping LangGraph/agentic workflow nodes with FlowGuard."""

    def __init__(
        self,
        domain: str,
        workflow_id: str = "langgraph-wf",
        max_repair_turns: int = 2,
        telemetry: Optional[TelemetryRecorder] = None,
        ledger: Optional[IdempotencyLedger] = None,
    ) -> None:
        self.domain = domain
        self.workflow_id = workflow_id
        self.telemetry = telemetry
        self.validator = ContractValidator(telemetry=telemetry)
        self.policy_guard = PolicyGuard(telemetry=telemetry)
        self.recovery = RecoveryController(
            validator=self.validator,
            max_repair_turns=max_repair_turns,
            telemetry=telemetry,
        )
        self.ledger = ledger or IdempotencyLedger(telemetry=telemetry)

    def process_agent_state(
        self,
        state: Dict[str, Any],
        mutate_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
        reconcile_fn: Optional[Callable[[str, str], Optional[Dict[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """Verify, recover, policy-check, and idempotently execute an agent graph state."""
        new_state = copy.deepcopy(state)
        context = new_state.get("authoritative_context", {})
        raw_output = new_state.get("agent_output")
        entity_id = str(new_state.get("entity_id", "entity-default"))

        rec_res = self.recovery.recover(
            domain=self.domain,
            raw_payload=raw_output,
            context=context,
            workflow_id=self.workflow_id,
        )
        new_state["flowguard_recovery"] = rec_res.to_dict()

        if (
            rec_res.final_verdict == ContractVerdict.UNSAFE_POLICY_BLOCK
            or not rec_res.recovered
            or rec_res.final_payload is None
        ):
            new_state["flowguard_status"] = "HALTED_SAFE_ESCALATION"
            new_state["escalated_to_human"] = True
            return new_state

        pol_res = self.policy_guard.evaluate(
            domain=self.domain,
            payload=rec_res.final_payload,
            context=context,
            workflow_id=self.workflow_id,
        )
        new_state["flowguard_policy"] = pol_res.to_dict()

        if not pol_res.allowed:
            new_state["flowguard_status"] = "BLOCKED_BY_POLICY"
            new_state["escalated_to_human"] = True
            return new_state

        new_state["validated_payload"] = rec_res.final_payload
        new_state["escalated_to_human"] = False

        if mutate_fn is not None:
            operation = str(
                rec_res.final_payload.get("action")
                or rec_res.final_payload.get("merge_decision")
                or rec_res.final_payload.get("provisioning_decision")
                or "mutate"
            )
            receipt = self.ledger.execute_through_proxy(
                workflow_id=self.workflow_id,
                domain=self.domain,
                entity_id=entity_id,
                operation=operation,
                payload=rec_res.final_payload,
                mutate_fn=mutate_fn,
                reconcile_fn=reconcile_fn,
            )
            new_state["flowguard_idempotency_receipt"] = receipt.to_dict()
            new_state["flowguard_status"] = (
                "COMMITTED"
                if receipt.idempotency_state == IdempotencyState.COMMITTED
                else receipt.idempotency_state.value
            )
        else:
            new_state["flowguard_status"] = "VERIFIED_READY"

        return new_state
