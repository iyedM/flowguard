"""Controlled Benchmark Runner & 5-Way Ablation Study Engine for FlowGuard.

Executes:
  1. Main Benchmark (720 runs = 180 scenarios across 3 domains × 4 strategies)
  2. Ablation Study (900 runs = 180 scenarios across 3 domains × 5 configurations)

Computes exact metrics from ground-truth sink state and execution traces with
95% Wilson Score confidence intervals, both per-domain and aggregated across all domains.
Zero predetermined or hard-coded metric targets.
"""

from __future__ import annotations

import concurrent.futures
import copy
import csv
import json
import math
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flowguard.contracts import ContractValidator
from flowguard.fault_injector import BenchmarkScenario, FaultInjector
from flowguard.idempotency import (
    IdempotencyLedger,
    PostCommitTimeoutError,
    PreCommitTransientError,
)
from flowguard.models import (
    AblationConfig,
    ContractVerdict,
    DomainName,
    ExecutionModeLabel,
    FaultClass,
    IdempotencyState,
    StrategyMode,
    WorkflowExecutionRecord,
)
from flowguard.policy_guard import PolicyGuard
from flowguard.recovery import RecoveryController
from flowguard.sinks import BaseStatefulSimulatedSink, create_sink_for_domain
from flowguard.telemetry import TelemetryRecorder


def wilson_ci_95(successes: int, total: int) -> Tuple[float, float, float]:
    """Compute point estimate (%) and 95% Wilson Score confidence interval (lower %, upper %)."""
    if total <= 0:
        return (0.0, 0.0, 0.0)
    z = 1.959963984540054  # 95% normal quantile
    n = float(total)
    p = float(successes) / n
    denom = 1.0 + (z * z) / n
    center = (p + (z * z) / (2.0 * n)) / denom
    half_width = (
        z
        * math.sqrt((p * (1.0 - p) / n) + ((z * z) / (4.0 * n * n)))
        / denom
    )
    low = max(0.0, (center - half_width) * 100.0)
    high = min(100.0, (center + half_width) * 100.0)
    return (round(p * 100.0, 2), round(low, 2), round(high, 2))


def percentile(values: List[float], q: float) -> float:
    """Compute percentile q in [0, 100] from a list of floats."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    idx = (len(sorted_vals) - 1) * (q / 100.0)
    lower = int(math.floor(idx))
    upper = int(math.ceil(idx))
    if lower == upper:
        return round(sorted_vals[lower], 3)
    weight = idx - lower
    return round(sorted_vals[lower] * (1.0 - weight) + sorted_vals[upper] * weight, 3)


class BenchmarkRunner:
    """Executes multi-domain controlled experiments and ablations."""

    def __init__(self, results_dir: Optional[Path] = None) -> None:
        self.results_dir = (
            Path(results_dir)
            if results_dir is not None
            else Path(__file__).resolve().parent.parent / "results"
        )
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.telemetry = TelemetryRecorder(
            log_path=self.results_dir / "telemetry_events.jsonl",
            persist_to_disk=True,
        )
        self.validator = ContractValidator(telemetry=self.telemetry)
        self.policy_guard = PolicyGuard(telemetry=self.telemetry)
        self.recovery = RecoveryController(
            validator=self.validator,
            max_repair_turns=2,
            telemetry=self.telemetry,
        )
        self.injector = FaultInjector()

    def execute_single_scenario(
        self,
        scenario: BenchmarkScenario,
        strategy: StrategyMode,
        ablation: AblationConfig = AblationConfig.FULL_FLOWGUARD,
    ) -> WorkflowExecutionRecord:
        """Run one scenario under the given strategy and ablation configuration."""
        start_ns = time.perf_counter_ns()
        sink = create_sink_for_domain(scenario.domain)
        if scenario.http_fault_schedule:
            sink.schedule_http_faults(scenario.entity_id, scenario.http_fault_schedule)

        taint_signal = self.policy_guard.audit_untrusted_text(
            context=scenario.authoritative_context,
            payload=scenario.raw_agent_output
            if isinstance(scenario.raw_agent_output, dict)
            else None,
        )

        if strategy == StrategyMode.B1_NATIVE_N8N:
            record = self._run_b1_native(scenario, sink, taint_signal.detected, start_ns)
        elif strategy == StrategyMode.B2_NAIVE_RETRY:
            record = self._run_b2_naive_retry(
                scenario, sink, taint_signal.detected, start_ns
            )
        elif strategy == StrategyMode.B3_CONTRACT_ONLY:
            record = self._run_b3_contract_only(
                scenario, sink, taint_signal.detected, start_ns
            )
        elif strategy == StrategyMode.FLOWGUARD_FULL:
            record = self._run_flowguard_configured(
                scenario=scenario,
                sink=sink,
                ablation=ablation,
                taint_detected=taint_signal.detected,
                start_ns=start_ns,
            )
        else:
            raise ValueError(f"Unsupported strategy: {strategy}")

        return record

    def _run_b1_native(
        self,
        scenario: BenchmarkScenario,
        sink: BaseStatefulSimulatedSink,
        taint_detected: bool,
        start_ns: int,
    ) -> WorkflowExecutionRecord:
        """B1_NATIVE_N8N: Direct JSON parse + sink call, no retries, no contract/idempotency."""
        raw = scenario.raw_agent_output
        parsed: Optional[Dict[str, Any]] = None
        if isinstance(raw, dict):
            parsed = copy.deepcopy(raw)
        elif isinstance(raw, str):
            try:
                candidate = json.loads(raw)
                if isinstance(candidate, dict):
                    parsed = candidate
            except json.JSONDecodeError:
                parsed = None

        actual_outcome = "EXECUTION_FAILED"
        if parsed is not None:
            for _ in range(scenario.event_deliveries):
                try:
                    sink.apply_mutation(
                        entity_id=scenario.entity_id,
                        payload=parsed,
                        authoritative_context=scenario.authoritative_context,
                        idem_key=None,
                    )
                    actual_outcome = "COMMITTED_UNVERIFIED"
                except (PreCommitTransientError, PostCommitTimeoutError):
                    actual_outcome = "HTTP_ERROR_UNHANDLED"

        return self._finalize_record(
            scenario=scenario,
            strategy=StrategyMode.B1_NATIVE_N8N.value,
            ablation_config="none",
            sink=sink,
            actual_outcome=actual_outcome,
            escalated_to_human=False,
            duplicate_prevented=False,
            reconciled_timeout=False,
            tier1_used=False,
            tier2_turns=0,
            tokens_consumed=0,
            idempotency_final_state="NONE",
            taint_detected=taint_detected,
            start_ns=start_ns,
        )

    def _run_b2_naive_retry(
        self,
        scenario: BenchmarkScenario,
        sink: BaseStatefulSimulatedSink,
        taint_detected: bool,
        start_ns: int,
    ) -> WorkflowExecutionRecord:
        """B2_NAIVE_RETRY: Retries up to 2 attempts on parse/HTTP failure without contracts or idempotency."""
        raw = scenario.raw_agent_output
        parsed: Optional[Dict[str, Any]] = None
        tokens_used = 0

        if isinstance(raw, dict):
            parsed = copy.deepcopy(raw)
        elif isinstance(raw, str):
            try:
                cand = json.loads(raw)
                if isinstance(cand, dict):
                    parsed = cand
            except json.JSONDecodeError:
                # Retry turn 1: naive markdown fence stripper
                tokens_used += 150
                parsed = RecoveryController.extract_json_object(raw)

        actual_outcome = "EXECUTION_FAILED"
        if parsed is not None:
            for _ in range(scenario.event_deliveries):
                for _attempt in range(1, 3):  # max 2 attempts
                    try:
                        sink.apply_mutation(
                            entity_id=scenario.entity_id,
                            payload=parsed,
                            authoritative_context=scenario.authoritative_context,
                            idem_key=None,
                        )
                        actual_outcome = "COMMITTED_UNVERIFIED"
                        break
                    except (PreCommitTransientError, PostCommitTimeoutError):
                        actual_outcome = "HTTP_RETRY_EXHAUSTED"
                        continue

        return self._finalize_record(
            scenario=scenario,
            strategy=StrategyMode.B2_NAIVE_RETRY.value,
            ablation_config="none",
            sink=sink,
            actual_outcome=actual_outcome,
            escalated_to_human=False,
            duplicate_prevented=False,
            reconciled_timeout=False,
            tier1_used=False,
            tier2_turns=1 if tokens_used > 0 else 0,
            tokens_consumed=tokens_used,
            idempotency_final_state="NONE",
            taint_detected=taint_detected,
            start_ns=start_ns,
        )

    def _run_b3_contract_only(
        self,
        scenario: BenchmarkScenario,
        sink: BaseStatefulSimulatedSink,
        taint_detected: bool,
        start_ns: int,
    ) -> WorkflowExecutionRecord:
        """B3_CONTRACT_ONLY: Deterministic Contract + Policy Guard, no 2-tier recovery, no idempotency ledger."""
        val_res = self.validator.validate(
            domain=scenario.domain,
            payload=scenario.raw_agent_output,
            context=scenario.authoritative_context,
            workflow_id=f"wf-{scenario.domain}",
        )

        if val_res.verdict == ContractVerdict.UNSAFE_POLICY_BLOCK:
            return self._finalize_record(
                scenario=scenario,
                strategy=StrategyMode.B3_CONTRACT_ONLY.value,
                ablation_config="none",
                sink=sink,
                actual_outcome="SAFE_POLICY_BLOCK",
                escalated_to_human=True,
                duplicate_prevented=False,
                reconciled_timeout=False,
                tier1_used=False,
                tier2_turns=0,
                tokens_consumed=0,
                idempotency_final_state="NONE",
                taint_detected=taint_detected,
                start_ns=start_ns,
            )

        if not val_res.is_valid or val_res.validated_payload is None:
            return self._finalize_record(
                scenario=scenario,
                strategy=StrategyMode.B3_CONTRACT_ONLY.value,
                ablation_config="none",
                sink=sink,
                actual_outcome="CONTRACT_REJECTED_HALT",
                escalated_to_human=True,
                duplicate_prevented=False,
                reconciled_timeout=False,
                tier1_used=False,
                tier2_turns=0,
                tokens_consumed=0,
                idempotency_final_state="NONE",
                taint_detected=taint_detected,
                start_ns=start_ns,
            )

        pol_res = self.policy_guard.evaluate(
            domain=scenario.domain,
            payload=val_res.validated_payload,
            context=scenario.authoritative_context,
            workflow_id=f"wf-{scenario.domain}",
        )
        if not pol_res.allowed:
            return self._finalize_record(
                scenario=scenario,
                strategy=StrategyMode.B3_CONTRACT_ONLY.value,
                ablation_config="none",
                sink=sink,
                actual_outcome="SAFE_POLICY_BLOCK",
                escalated_to_human=True,
                duplicate_prevented=False,
                reconciled_timeout=False,
                tier1_used=False,
                tier2_turns=0,
                tokens_consumed=0,
                idempotency_final_state="NONE",
                taint_detected=taint_detected,
                start_ns=start_ns,
            )

        actual_outcome = "EXECUTION_FAILED"
        for _ in range(scenario.event_deliveries):
            try:
                sink.apply_mutation(
                    entity_id=scenario.entity_id,
                    payload=val_res.validated_payload,
                    authoritative_context=scenario.authoritative_context,
                    idem_key=None,
                )
                actual_outcome = "COMMITTED_VALID_STATE"
            except (PreCommitTransientError, PostCommitTimeoutError):
                actual_outcome = "HTTP_ERROR_UNHANDLED"

        return self._finalize_record(
            scenario=scenario,
            strategy=StrategyMode.B3_CONTRACT_ONLY.value,
            ablation_config="none",
            sink=sink,
            actual_outcome=actual_outcome,
            escalated_to_human=(actual_outcome != "COMMITTED_VALID_STATE"),
            duplicate_prevented=False,
            reconciled_timeout=False,
            tier1_used=False,
            tier2_turns=0,
            tokens_consumed=0,
            idempotency_final_state="NONE",
            taint_detected=taint_detected,
            start_ns=start_ns,
        )

    def _run_flowguard_configured(
        self,
        scenario: BenchmarkScenario,
        sink: BaseStatefulSimulatedSink,
        ablation: AblationConfig,
        taint_detected: bool,
        start_ns: int,
    ) -> WorkflowExecutionRecord:
        """Execute FlowGuard with configurable ablation switches."""
        tier1_enabled = ablation != AblationConfig.NO_TIER1_DRIFT_NORMALIZER
        tier2_enabled = ablation != AblationConfig.NO_TIER2_REPAIR
        reconciliation_enabled = ablation != AblationConfig.NO_IDEMPOTENCY_RECONCILIATION
        policy_guard_enabled = ablation != AblationConfig.NO_DETERMINISTIC_POLICY_GUARD

        workflow_id = f"wf-{scenario.domain}"

        # When deterministic policy guard is disabled (ablation 5), fallible taint detection
        # is the ONLY barrier against adversarial inputs.
        if not policy_guard_enabled and taint_detected and scenario.fault_class == FaultClass.F5_ADVERSARIAL_INPUT:
            return self._finalize_record(
                scenario=scenario,
                strategy=StrategyMode.FLOWGUARD_FULL.value,
                ablation_config=ablation.value,
                sink=sink,
                actual_outcome="SAFE_POLICY_BLOCK",
                escalated_to_human=True,
                duplicate_prevented=False,
                reconciled_timeout=False,
                tier1_used=False,
                tier2_turns=0,
                tokens_consumed=0,
                idempotency_final_state="NONE",
                taint_detected=taint_detected,
                start_ns=start_ns,
            )

        # Step 1: Validate & run Two-Tier Bounded Recovery
        rec_res = self.recovery.recover(
            domain=scenario.domain,
            raw_payload=scenario.raw_agent_output,
            context=scenario.authoritative_context,
            tier1_enabled=tier1_enabled,
            tier2_enabled=tier2_enabled,
            enforce_policy_invariants=policy_guard_enabled,
            workflow_id=workflow_id,
        )

        if rec_res.final_verdict == ContractVerdict.UNSAFE_POLICY_BLOCK:
            return self._finalize_record(
                scenario=scenario,
                strategy=StrategyMode.FLOWGUARD_FULL.value,
                ablation_config=ablation.value,
                sink=sink,
                actual_outcome="SAFE_POLICY_BLOCK",
                escalated_to_human=True,
                duplicate_prevented=False,
                reconciled_timeout=False,
                tier1_used=rec_res.tier1_applied,
                tier2_turns=rec_res.tier2_turns_used,
                tokens_consumed=rec_res.total_tokens_used,
                idempotency_final_state="NONE",
                taint_detected=taint_detected,
                start_ns=start_ns,
            )

        if not rec_res.recovered or rec_res.final_payload is None:
            return self._finalize_record(
                scenario=scenario,
                strategy=StrategyMode.FLOWGUARD_FULL.value,
                ablation_config=ablation.value,
                sink=sink,
                actual_outcome="SAFE_ESCALATION_HALT",
                escalated_to_human=True,
                duplicate_prevented=False,
                reconciled_timeout=False,
                tier1_used=rec_res.tier1_applied,
                tier2_turns=rec_res.tier2_turns_used,
                tokens_consumed=rec_res.total_tokens_used,
                idempotency_final_state="NONE",
                taint_detected=taint_detected,
                start_ns=start_ns,
            )

        validated_payload = rec_res.final_payload

        # Step 2: Mechanism D Least-Privilege Policy Guard
        pol_decision = self.policy_guard.evaluate(
            domain=scenario.domain,
            payload=validated_payload,
            context=scenario.authoritative_context,
            workflow_id=workflow_id,
            policy_enabled=policy_guard_enabled,
        )
        if not pol_decision.allowed:
            return self._finalize_record(
                scenario=scenario,
                strategy=StrategyMode.FLOWGUARD_FULL.value,
                ablation_config=ablation.value,
                sink=sink,
                actual_outcome="SAFE_POLICY_BLOCK",
                escalated_to_human=True,
                duplicate_prevented=False,
                reconciled_timeout=False,
                tier1_used=rec_res.tier1_applied,
                tier2_turns=rec_res.tier2_turns_used,
                tokens_consumed=rec_res.total_tokens_used,
                idempotency_final_state="NONE",
                taint_detected=taint_detected,
                start_ns=start_ns,
            )

        # Step 3: Mechanism C 4-State Transactional Idempotency Proxy
        ledger = IdempotencyLedger(telemetry=self.telemetry)
        op_name = str(
            validated_payload.get("action")
            or validated_payload.get("merge_decision")
            or validated_payload.get("provisioning_decision")
            or scenario.operation
        )
        idem_key = ledger.derive_key(
            workflow_id=workflow_id,
            entity_id=scenario.entity_id,
            operation=op_name,
            canonical_payload=validated_payload,
        )

        duplicate_prevented = False
        reconciled_timeout = False
        actual_outcome = "SAFE_ESCALATION_HALT"
        final_idem_state = IdempotencyState.FAILED_SAFE_TO_RETRY.value

        def _single_delivery_with_bounded_retry() -> Tuple[str, bool, bool, str]:
            loc_dup = False
            loc_rec = False
            loc_outcome = "SAFE_ESCALATION_HALT"
            loc_state = IdempotencyState.FAILED_SAFE_TO_RETRY.value

            for _attempt in range(1, 3):  # Equal retry budget: max 2 attempts
                try:
                    receipt = ledger.execute_through_proxy(
                        workflow_id=workflow_id,
                        domain=scenario.domain,
                        entity_id=scenario.entity_id,
                        operation=op_name,
                        payload=validated_payload,
                        mutate_fn=lambda k: sink.apply_mutation(
                            scenario.entity_id,
                            validated_payload,
                            scenario.authoritative_context,
                            k,
                        ),
                        reconcile_fn=sink.reconcile_read,
                        idem_key=idem_key,
                        reconciliation_enabled=reconciliation_enabled,
                    )
                    loc_state = receipt.idempotency_state.value
                    if receipt.replayed_from_ledger or receipt.concurrent_duplicate_blocked:
                        loc_dup = True
                    if receipt.reconciled_after_timeout:
                        loc_rec = True
                    if receipt.idempotency_state in (
                        IdempotencyState.COMMITTED,
                        IdempotencyState.PENDING_IN_FLIGHT,
                    ):
                        loc_outcome = "COMMITTED_VALID_STATE"
                    break
                except PreCommitTransientError:
                    rec = ledger.get_record(idem_key)
                    loc_state = (
                        rec.state.value
                        if rec is not None
                        else IdempotencyState.FAILED_SAFE_TO_RETRY.value
                    )
                    continue
                except PostCommitTimeoutError:
                    rec = ledger.get_record(idem_key)
                    loc_state = (
                        rec.state.value
                        if rec is not None
                        else IdempotencyState.AMBIGUOUS_REQUIRES_RECONCILIATION.value
                    )
                    continue
            return loc_outcome, loc_dup, loc_rec, loc_state

        if scenario.concurrent_delivery and scenario.event_deliveries > 1:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=scenario.event_deliveries
            ) as pool:
                futures = [
                    pool.submit(_single_delivery_with_bounded_retry)
                    for _ in range(scenario.event_deliveries)
                ]
                for fut in concurrent.futures.as_completed(futures):
                    out, dup, rec, st = fut.result()
                    if out == "COMMITTED_VALID_STATE":
                        actual_outcome = out
                    if dup:
                        duplicate_prevented = True
                    if rec:
                        reconciled_timeout = True
                    final_idem_state = st
        else:
            for _ in range(scenario.event_deliveries):
                out, dup, rec, st = _single_delivery_with_bounded_retry()
                if out == "COMMITTED_VALID_STATE":
                    actual_outcome = out
                if dup:
                    duplicate_prevented = True
                if rec:
                    reconciled_timeout = True
                final_idem_state = st

        ledger_rec = ledger.get_record(idem_key)
        if ledger_rec is not None:
            final_idem_state = ledger_rec.state.value
        ledger.close()

        escalated = actual_outcome != "COMMITTED_VALID_STATE"
        return self._finalize_record(
            scenario=scenario,
            strategy=StrategyMode.FLOWGUARD_FULL.value,
            ablation_config=ablation.value,
            sink=sink,
            actual_outcome=actual_outcome,
            escalated_to_human=escalated,
            duplicate_prevented=duplicate_prevented,
            reconciled_timeout=reconciled_timeout,
            tier1_used=rec_res.tier1_applied,
            tier2_turns=rec_res.tier2_turns_used,
            tokens_consumed=rec_res.total_tokens_used,
            idempotency_final_state=final_idem_state,
            taint_detected=taint_detected,
            start_ns=start_ns,
        )

    def _finalize_record(
        self,
        scenario: BenchmarkScenario,
        strategy: str,
        ablation_config: str,
        sink: BaseStatefulSimulatedSink,
        actual_outcome: str,
        escalated_to_human: bool,
        duplicate_prevented: bool,
        reconciled_timeout: bool,
        tier1_used: bool,
        tier2_turns: int,
        tokens_consumed: int,
        idempotency_final_state: str,
        taint_detected: bool,
        start_ns: int,
    ) -> WorkflowExecutionRecord:
        latency_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 4)
        sink_state = sink.get_entity_state(scenario.entity_id)
        mutation_count = sink.count_mutations_for_entity(scenario.entity_id)

        unsafe_side_effect = bool(
            sink_state is not None and sink_state.get("unsafe_side_effect") is True
        )
        contract_escaped = bool(
            sink_state is not None and sink_state.get("contract_violation_escaped") is True
        )

        is_nominal = scenario.fault_class == FaultClass.F0_NOMINAL
        fault_injected = not is_nominal

        if scenario.expected_safe_outcome == "SAFE_POLICY_BLOCK":
            state_verified_success = (
                mutation_count == 0
                and not unsafe_side_effect
                and not contract_escaped
                and actual_outcome == "SAFE_POLICY_BLOCK"
            )
        else:
            state_verified_success = (
                mutation_count == 1
                and not unsafe_side_effect
                and not contract_escaped
                and actual_outcome in ("COMMITTED_VALID_STATE", "COMMITTED_UNVERIFIED")
            )

        fault_recovered = fault_injected and state_verified_success
        false_rejection = is_nominal and (not state_verified_success)

        return WorkflowExecutionRecord(
            scenario_id=scenario.scenario_id,
            domain=scenario.domain,
            fault_class=scenario.fault_class.value,
            strategy=strategy,
            ablation_config=ablation_config,
            is_nominal_input=is_nominal,
            expected_safe_outcome=scenario.expected_safe_outcome,
            actual_outcome=actual_outcome,
            state_verified_success=state_verified_success,
            fault_injected=fault_injected,
            fault_recovered=fault_recovered,
            unsafe_side_effect_occurred=unsafe_side_effect,
            contract_violation_escaped=contract_escaped,
            false_rejection_occurred=false_rejection,
            escalated_to_human=escalated_to_human,
            duplicate_mutation_prevented=duplicate_prevented,
            reconciled_post_commit_timeout=reconciled_timeout,
            tier1_used=tier1_used,
            tier2_turns=tier2_turns,
            tokens_consumed=tokens_consumed,
            latency_ms=latency_ms,
            idempotency_final_state=idempotency_final_state,
            taint_detected=taint_detected,
            notes=scenario.fault_subtype,
            execution_mode_label=ExecutionModeLabel.DETERMINISTIC_HARNESS.value,
        )

    @staticmethod
    def compute_summary_metrics(
        records: List[WorkflowExecutionRecord],
    ) -> Dict[str, Any]:
        """Compute all benchmark metrics with 95% Wilson CIs from raw execution records."""
        total = len(records)
        nominal_records = [r for r in records if r.is_nominal_input]
        fault_records = [r for r in records if r.fault_injected]

        svs_count = sum(1 for r in records if r.state_verified_success)
        rec_count = sum(1 for r in fault_records if r.fault_recovered)
        user_count = sum(1 for r in records if r.unsafe_side_effect_occurred)
        cver_count = sum(1 for r in records if r.contract_violation_escaped)
        frr_count = sum(1 for r in nominal_records if r.false_rejection_occurred)
        esc_count = sum(1 for r in records if r.escalated_to_human)

        svsr_pt, svsr_lo, svsr_hi = wilson_ci_95(svs_count, total)
        rr_pt, rr_lo, rr_hi = wilson_ci_95(rec_count, len(fault_records))
        user_pt, user_lo, user_hi = wilson_ci_95(user_count, total)
        cver_pt, cver_lo, cver_hi = wilson_ci_95(cver_count, total)
        frr_pt, frr_lo, frr_hi = wilson_ci_95(frr_count, len(nominal_records))
        esc_pt, esc_lo, esc_hi = wilson_ci_95(esc_count, total)

        latencies = [r.latency_ms for r in records]
        tokens = [r.tokens_consumed for r in records]

        return {
            "total_runs": total,
            "nominal_runs": len(nominal_records),
            "fault_injected_runs": len(fault_records),
            "svsr_count": svs_count,
            "svsr_pct": svsr_pt,
            "svsr_ci95": [svsr_lo, svsr_hi],
            "recovery_count": rec_count,
            "recovery_rate_pct": rr_pt,
            "recovery_rate_ci95": [rr_lo, rr_hi],
            "unsafe_side_effect_count": user_count,
            "unsafe_side_effect_rate_pct": user_pt,
            "unsafe_side_effect_ci95": [user_lo, user_hi],
            "contract_violation_escape_count": cver_count,
            "contract_violation_escape_rate_pct": cver_pt,
            "contract_violation_escape_ci95": [cver_lo, cver_hi],
            "false_rejection_count": frr_count,
            "false_rejection_rate_pct": frr_pt,
            "false_rejection_ci95": [frr_lo, frr_hi],
            "human_escalation_count": esc_count,
            "human_escalation_rate_pct": esc_pt,
            "human_escalation_ci95": [esc_lo, esc_hi],
            "mean_tokens_per_run": round(sum(tokens) / max(1, total), 2),
            "total_tokens": sum(tokens),
            "latency_p50_ms": percentile(latencies, 50.0),
            "latency_p95_ms": percentile(latencies, 95.0),
        }

    def run_full_benchmark_and_ablation(self) -> Dict[str, Any]:
        """Run all 720 main benchmark executions and 900 ablation executions, saving artifacts."""
        scenarios = self.injector.generate_all_scenarios()
        strategies = [
            StrategyMode.B1_NATIVE_N8N,
            StrategyMode.B2_NAIVE_RETRY,
            StrategyMode.B3_CONTRACT_ONLY,
            StrategyMode.FLOWGUARD_FULL,
        ]
        domains = [
            DomainName.AIOPS.value,
            DomainName.DEVSECOPS.value,
            DomainName.CLOUD_FINOPS.value,
        ]

        # 1. Execute 720 main strategy runs
        all_records: List[WorkflowExecutionRecord] = []
        for strat in strategies:
            for sc in scenarios:
                rec = self.execute_single_scenario(
                    scenario=sc,
                    strategy=strat,
                    ablation=AblationConfig.FULL_FLOWGUARD,
                )
                all_records.append(rec)

        summary_by_strategy_and_domain: Dict[str, Dict[str, Any]] = {}
        for strat in strategies:
            s_name = strat.value
            summary_by_strategy_and_domain[s_name] = {}
            strat_records = [r for r in all_records if r.strategy == s_name]
            for dom in domains:
                dom_records = [r for r in strat_records if r.domain == dom]
                summary_by_strategy_and_domain[s_name][dom] = self.compute_summary_metrics(
                    dom_records
                )
            summary_by_strategy_and_domain[s_name]["all_domains_combined"] = (
                self.compute_summary_metrics(strat_records)
            )

            # Also break down by fault class for detailed failure analysis
            by_fc: Dict[str, Any] = {}
            for fc in FaultClass:
                fc_recs = [r for r in strat_records if r.fault_class == fc.value]
                by_fc[fc.value] = self.compute_summary_metrics(fc_recs)
            summary_by_strategy_and_domain[s_name]["by_fault_class"] = by_fc

        benchmark_payload = {
            "epistemic_metadata": {
                "execution_mode_label": ExecutionModeLabel.DETERMINISTIC_HARNESS.value,
                "sink_mode_label": ExecutionModeLabel.STATEFUL_SIMULATED_SINK.value,
                "total_scenarios": len(scenarios),
                "evaluated_strategies": [s.value for s in strategies],
                "total_recorded_executions": len(all_records),
                "confidence_interval_method": "Wilson Score 95%",
            },
            "summary": summary_by_strategy_and_domain,
            "records": [r.to_dict() for r in all_records],
        }

        bench_json_path = self.results_dir / "experiment_a_benchmark_results.json"
        bench_json_path.write_text(
            json.dumps(benchmark_payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        self._write_summary_csv(
            summary_by_strategy_and_domain,
            self.results_dir / "experiment_a_summary_by_domain.csv",
            key_column_name="strategy",
        )

        # 2. Execute 5-configuration Ablation Study (900 runs)
        ablation_configs = [
            AblationConfig.FULL_FLOWGUARD,
            AblationConfig.NO_TIER1_DRIFT_NORMALIZER,
            AblationConfig.NO_TIER2_REPAIR,
            AblationConfig.NO_IDEMPOTENCY_RECONCILIATION,
            AblationConfig.NO_DETERMINISTIC_POLICY_GUARD,
        ]
        ablation_records: List[WorkflowExecutionRecord] = []
        for ab_cfg in ablation_configs:
            for sc in scenarios:
                rec = self.execute_single_scenario(
                    scenario=sc,
                    strategy=StrategyMode.FLOWGUARD_FULL,
                    ablation=ab_cfg,
                )
                ablation_records.append(rec)

        ablation_summary: Dict[str, Dict[str, Any]] = {}
        for ab_cfg in ablation_configs:
            ab_name = ab_cfg.value
            ablation_summary[ab_name] = {}
            ab_recs = [r for r in ablation_records if r.ablation_config == ab_name]
            for dom in domains:
                dom_recs = [r for r in ab_recs if r.domain == dom]
                ablation_summary[ab_name][dom] = self.compute_summary_metrics(dom_recs)
            ablation_summary[ab_name]["all_domains_combined"] = (
                self.compute_summary_metrics(ab_recs)
            )

        ablation_payload = {
            "epistemic_metadata": {
                "execution_mode_label": ExecutionModeLabel.DETERMINISTIC_HARNESS.value,
                "sink_mode_label": ExecutionModeLabel.STATEFUL_SIMULATED_SINK.value,
                "total_scenarios": len(scenarios),
                "ablation_configurations": [a.value for a in ablation_configs],
                "total_ablation_executions": len(ablation_records),
                "confidence_interval_method": "Wilson Score 95%",
            },
            "summary": ablation_summary,
            "records": [r.to_dict() for r in ablation_records],
        }

        ablation_json_path = self.results_dir / "ablation_study_results.json"
        ablation_json_path.write_text(
            json.dumps(ablation_payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

        self._write_summary_csv(
            ablation_summary,
            self.results_dir / "ablation_study_summary.csv",
            key_column_name="ablation_config",
        )

        return {
            "benchmark": benchmark_payload,
            "ablation": ablation_payload,
        }

    @staticmethod
    def _write_summary_csv(
        summary_dict: Dict[str, Dict[str, Any]],
        csv_path: Path,
        key_column_name: str,
    ) -> None:
        fieldnames = [
            key_column_name,
            "domain",
            "total_runs",
            "svsr_pct",
            "svsr_ci95_low",
            "svsr_ci95_high",
            "recovery_rate_pct",
            "recovery_ci95_low",
            "recovery_ci95_high",
            "unsafe_side_effect_rate_pct",
            "user_ci95_low",
            "user_ci95_high",
            "contract_violation_escape_rate_pct",
            "cver_ci95_low",
            "cver_ci95_high",
            "false_rejection_rate_pct",
            "human_escalation_rate_pct",
            "mean_tokens_per_run",
            "latency_p50_ms",
            "latency_p95_ms",
        ]
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for top_key, dom_map in summary_dict.items():
                for dom_key, m in dom_map.items():
                    if dom_key == "by_fault_class":
                        continue
                    writer.writerow(
                        {
                            key_column_name: top_key,
                            "domain": dom_key,
                            "total_runs": m["total_runs"],
                            "svsr_pct": m["svsr_pct"],
                            "svsr_ci95_low": m["svsr_ci95"][0],
                            "svsr_ci95_high": m["svsr_ci95"][1],
                            "recovery_rate_pct": m["recovery_rate_pct"],
                            "recovery_ci95_low": m["recovery_rate_ci95"][0],
                            "recovery_ci95_high": m["recovery_rate_ci95"][1],
                            "unsafe_side_effect_rate_pct": m["unsafe_side_effect_rate_pct"],
                            "user_ci95_low": m["unsafe_side_effect_ci95"][0],
                            "user_ci95_high": m["unsafe_side_effect_ci95"][1],
                            "contract_violation_escape_rate_pct": m[
                                "contract_violation_escape_rate_pct"
                            ],
                            "cver_ci95_low": m["contract_violation_escape_ci95"][0],
                            "cver_ci95_high": m["contract_violation_escape_ci95"][1],
                            "false_rejection_rate_pct": m["false_rejection_rate_pct"],
                            "human_escalation_rate_pct": m["human_escalation_rate_pct"],
                            "mean_tokens_per_run": m["mean_tokens_per_run"],
                            "latency_p50_ms": m["latency_p50_ms"],
                            "latency_p95_ms": m["latency_p95_ms"],
                        }
                    )
