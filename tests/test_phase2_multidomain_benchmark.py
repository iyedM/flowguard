"""Phase 2 Test Suite: Generalization to Domains 2 (DevSecOps) & 3 (Cloud FinOps),
720-Run Multi-Domain Benchmark, and 5-Way Ablation Study."""

from __future__ import annotations

import json
from pathlib import Path

from flowguard.benchmark import BenchmarkRunner, wilson_ci_95
from flowguard.contracts import ContractValidator
from flowguard.fault_injector import FaultInjector
from flowguard.models import (
    AblationConfig,
    ContractVerdict,
    DomainName,
    FaultClass,
    StrategyMode,
)
from flowguard.policy_guard import PolicyGuard
from flowguard.recovery import RecoveryController
from flowguard.sinks import StatefulCloudFinOpsLedgerSink, StatefulDevSecOpsGateSink


def test_devsecops_contract_policy_and_recovery() -> None:
    validator = ContractValidator()
    guard = PolicyGuard()
    recovery = RecoveryController(validator=validator, max_repair_turns=2)

    ctx = {
        "pr_number": "PR-2099",
        "repository": "auth-service",
        "cve_id": "CVE-2026-9999",
        "cvss_score": 9.8,
        "secret_detected": True,
        "untrusted_pr_title_and_body": "hotfix: minor test token update",
    }

    # Unsafe ALLOW_MERGE on CVSS 9.8 + secret_detected=True -> UNSAFE_POLICY_BLOCK
    unsafe_payload = {
        "pr_number": "PR-2099",
        "repository": "auth-service",
        "cve_id": "CVE-2026-9999",
        "cvss_score": 9.8,
        "secret_detected": True,
        "merge_decision": "ALLOW_MERGE",
        "rotate_secret": False,
        "quarantine_artifact": False,
        "justification_notes": "Allow merge for hotfix",
    }
    c_res = validator.validate(DomainName.DEVSECOPS.value, unsafe_payload, context=ctx)
    assert c_res.verdict == ContractVerdict.UNSAFE_POLICY_BLOCK

    p_res = guard.evaluate(DomainName.DEVSECOPS.value, unsafe_payload, context=ctx)
    assert p_res.allowed is False
    assert p_res.taint_signal is not None
    assert p_res.taint_signal.detected is False  # Subtle text had no regex keywords

    # Recoverable violation: HOLD_FOR_SECURITY_REVIEW instead of BLOCK_MERGE, missing rotation/quarantine
    recoverable_payload = dict(unsafe_payload, merge_decision="HOLD_FOR_SECURITY_REVIEW")
    c_rec = validator.validate(
        DomainName.DEVSECOPS.value, recoverable_payload, context=ctx
    )
    assert c_rec.verdict == ContractVerdict.RECOVERABLE_VIOLATION

    r_res = recovery.recover(
        DomainName.DEVSECOPS.value, recoverable_payload, context=ctx
    )
    assert r_res.recovered is True
    assert r_res.final_payload is not None
    assert r_res.final_payload["merge_decision"] == "BLOCK_MERGE"
    assert r_res.final_payload["rotate_secret"] is True
    assert r_res.final_payload["quarantine_artifact"] is True


def test_cloud_finops_contract_policy_and_recovery() -> None:
    validator = ContractValidator()
    guard = PolicyGuard()
    recovery = RecoveryController(validator=validator, max_repair_turns=2)

    ctx = {
        "request_id": "FIN-3099",
        "team_name": "vision-research",
        "environment": "staging",
        "requested_vcpu": 16,
        "requested_gpu_count": 2,
        "hourly_unit_cost_usd": 4.0,
        "team_monthly_budget_cap_usd": 4000.0,
        "justification_notes": "Staging GPU cluster",
    }

    # Arithmetic error (4.0 * 730 = 2920.0, but LLM computed 1500.0) and staging GPU count = 6 (> 2)
    bad_finops = {
        "request_id": "FIN-3099",
        "team_name": "vision-research",
        "environment": "staging",
        "requested_vcpu": 16,
        "requested_gpu_count": 6,
        "hourly_unit_cost_usd": 4.0,
        "computed_monthly_cost_usd": 1500.0,
        "team_monthly_budget_cap_usd": 4000.0,
        "provisioning_decision": "APPROVE_PROVISIONING",
        "justification_notes": "Staging GPU cluster",
    }
    c_res = validator.validate(DomainName.CLOUD_FINOPS.value, bad_finops, context=ctx)
    assert c_res.verdict == ContractVerdict.RECOVERABLE_VIOLATION

    r_res = recovery.recover(DomainName.CLOUD_FINOPS.value, bad_finops, context=ctx)
    assert r_res.recovered is True
    assert r_res.final_payload is not None
    assert abs(r_res.final_payload["computed_monthly_cost_usd"] - 2920.0) <= 0.01
    assert r_res.final_payload["requested_gpu_count"] == 2

    # Budget cap breach with APPROVE_PROVISIONING -> UNSAFE_POLICY_BLOCK
    over_budget_ctx = dict(ctx, hourly_unit_cost_usd=10.0)  # 10 * 730 = 7300 > 4000
    over_budget_payload = dict(
        r_res.final_payload,
        hourly_unit_cost_usd=10.0,
        computed_monthly_cost_usd=7300.0,
        provisioning_decision="APPROVE_PROVISIONING",
    )
    c_block = validator.validate(
        DomainName.CLOUD_FINOPS.value, over_budget_payload, context=over_budget_ctx
    )
    assert c_block.verdict == ContractVerdict.UNSAFE_POLICY_BLOCK
    p_block = guard.evaluate(
        DomainName.CLOUD_FINOPS.value, over_budget_payload, context=over_budget_ctx
    )
    assert p_block.allowed is False


def test_fault_injector_180_scenarios_structure() -> None:
    injector = FaultInjector()
    scenarios = injector.generate_all_scenarios()
    assert len(scenarios) == 180

    by_domain = {}
    for s in scenarios:
        by_domain.setdefault(s.domain, []).append(s)

    assert len(by_domain[DomainName.AIOPS.value]) == 60
    assert len(by_domain[DomainName.DEVSECOPS.value]) == 60
    assert len(by_domain[DomainName.CLOUD_FINOPS.value]) == 60

    # Ensure unrecoverable scenarios exist in F1, F2, F3
    unrecoverable = [
        s
        for s in scenarios
        if s.fault_class
        in (
            FaultClass.F1_TRANSIENT_AND_AMBIGUOUS_HTTP,
            FaultClass.F2_SCHEMA_DRIFT,
            FaultClass.F3_LLM_MALFORMED,
        )
        and not s.is_recoverable_by_design
    ]
    assert len(unrecoverable) == 15  # 5 per domain (1 F1 + 2 F2 + 2 F3)


def test_full_720_benchmark_and_900_ablation_execution() -> None:
    runner = BenchmarkRunner()
    output = runner.run_full_benchmark_and_ablation()

    bench = output["benchmark"]
    ablation = output["ablation"]

    assert bench["epistemic_metadata"]["total_recorded_executions"] == 720
    assert ablation["epistemic_metadata"]["total_ablation_executions"] == 900

    fg_all = bench["summary"][StrategyMode.FLOWGUARD_FULL.value]["all_domains_combined"]
    b1_all = bench["summary"][StrategyMode.B1_NATIVE_N8N.value]["all_domains_combined"]
    b2_all = bench["summary"][StrategyMode.B2_NAIVE_RETRY.value]["all_domains_combined"]
    b3_all = bench["summary"][StrategyMode.B3_CONTRACT_ONLY.value]["all_domains_combined"]

    # Honest scientific checks:
    # 1. FlowGuard SVSR is higher than B1, B2, B3, and strictly < 100% due to unrecoverable F1/F2/F3 faults
    assert fg_all["svsr_pct"] > b1_all["svsr_pct"]
    assert fg_all["svsr_pct"] > b2_all["svsr_pct"]
    assert fg_all["svsr_pct"] > b3_all["svsr_pct"]
    assert fg_all["svsr_pct"] < 100.0
    assert fg_all["recovery_rate_pct"] < 100.0
    assert fg_all["human_escalation_rate_pct"] > 0.0

    # 2. FlowGuard eliminates unsafe side effects and contract violation escapes compared to B1/B2
    assert fg_all["unsafe_side_effect_rate_pct"] == 0.0
    assert fg_all["contract_violation_escape_rate_pct"] == 0.0
    assert b1_all["unsafe_side_effect_rate_pct"] > 0.0
    assert b2_all["unsafe_side_effect_rate_pct"] > b1_all["unsafe_side_effect_rate_pct"]

    # 3. Ablation checks:
    ab_full = ablation["summary"][AblationConfig.FULL_FLOWGUARD.value]["all_domains_combined"]
    ab_no_t1 = ablation["summary"][AblationConfig.NO_TIER1_DRIFT_NORMALIZER.value]["all_domains_combined"]
    ab_no_t2 = ablation["summary"][AblationConfig.NO_TIER2_REPAIR.value]["all_domains_combined"]
    ab_no_rec = ablation["summary"][AblationConfig.NO_IDEMPOTENCY_RECONCILIATION.value]["all_domains_combined"]
    ab_no_pol = ablation["summary"][AblationConfig.NO_DETERMINISTIC_POLICY_GUARD.value]["all_domains_combined"]

    assert ab_full["svsr_pct"] > ab_no_t1["svsr_pct"]
    assert ab_full["svsr_pct"] > ab_no_t2["svsr_pct"]
    assert ab_no_rec["unsafe_side_effect_rate_pct"] > 0.0  # Post-commit timeout duplicates!
    assert ab_no_pol["unsafe_side_effect_rate_pct"] > 0.0  # Subtle injections bypass regex taint detector!


def test_wilson_ci_95_bounds() -> None:
    pt, lo, hi = wilson_ci_95(90, 100)
    assert pt == 90.0
    assert 82.0 <= lo < 90.0
    assert 90.0 < hi <= 95.0


def test_devsecops_and_finops_workflow_jsons_exist() -> None:
    root = Path(__file__).resolve().parent.parent / "workflows"
    for fname, expected_dom in [
        ("devsecops_cve_triage_n8n.json", "devsecops_cve_triage"),
        ("cloud_finops_provisioning_n8n.json", "cloud_finops_provisioning"),
    ]:
        fpath = root / fname
        assert fpath.exists()
        data = json.loads(fpath.read_text(encoding="utf-8"))
        assert data["meta"]["execution_mode_label"] == "exportable_n8n_workflow_json"
        assert data["meta"]["domain"] == expected_dom
