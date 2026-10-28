"""Generate 3 publication-grade SVG figures in `docs/figures/` directly from `results/*.json`.

Zero hard-coded metric percentages: every bar height, error bar (95% Wilson CI),
and label is computed dynamically from the recorded JSON artifacts in `results/`.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List


def _esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


def generate_fig1_strategy_comparison(
    bench_data: Dict[str, Any],
    out_path: Path,
) -> None:
    """Figure 1: Per-Domain & Combined Strategy Comparison with 95% Wilson CIs."""
    summary = bench_data["summary"]
    strategies = [
        ("B1_NATIVE_N8N", "B1: Native n8n", "#64748b"),
        ("B2_NAIVE_RETRY", "B2: Naive Retry", "#f59e0b"),
        ("B3_CONTRACT_ONLY", "B3: Contract Only", "#0284c7"),
        ("FLOWGUARD_FULL", "FlowGuard (Full)", "#10b981"),
    ]
    domain_groups = [
        ("aiops_incident_remediation", "Domain 1: AIOps"),
        ("devsecops_cve_triage", "Domain 2: DevSecOps"),
        ("cloud_finops_provisioning", "Domain 3: Cloud FinOps"),
        ("all_domains_combined", "All Domains (N=180)"),
    ]

    width, height = 1040, 560
    svg: List[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="system-ui, -apple-system, sans-serif">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        '<text x="520" y="34" text-anchor="middle" font-size="17" font-weight="700" fill="#0f172a">Figure 1: End-to-End Performance Across Workflow Domains (720 Controlled Runs, 95% Wilson CIs)</text>',
        '<text x="520" y="54" text-anchor="middle" font-size="12" fill="#475569">Epistemic Scope: deterministic_harness + stateful_simulated_sink | Left: State-Verified Success Rate (SVSR %) | Right: Unsafe Side-Effect &amp; Escape Rates (%)</text>',
    ]

    # Legend
    lx = 180
    for _s_key, s_label, color in strategies:
        svg.append(f'<rect x="{lx}" y="70" width="14" height="14" rx="2" fill="{color}"/>')
        svg.append(f'<text x="{lx + 20}" y="82" font-size="12" font-weight="600" fill="#1e293b">{_esc(s_label)}</text>')
        lx += 185

    # Panel A (Left): SVSR (%) by Domain
    p1_x, p1_y, p1_w, p1_h = 70, 115, 430, 340
    svg.append(f'<text x="{p1_x + p1_w/2}" y="{p1_y - 10}" text-anchor="middle" font-size="13" font-weight="700" fill="#0f172a">A. State-Verified Success Rate (SVSR % — Higher is Better)</text>')

    for pct in (0, 20, 40, 60, 80, 100):
        gy = p1_y + p1_h - (pct / 100.0) * p1_h
        svg.append(f'<line x1="{p1_x}" y1="{gy:.1f}" x2="{p1_x + p1_w}" y2="{gy:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'<text x="{p1_x - 8}" y="{gy + 4:.1f}" text-anchor="end" font-size="11" fill="#64748b">{pct}%</text>')

    group_w = p1_w / len(domain_groups)
    bar_w = 19
    for g_idx, (dom_key, dom_label) in enumerate(domain_groups):
        gx = p1_x + g_idx * group_w + 14
        for s_idx, (s_key, _s_label, color) in enumerate(strategies):
            m = summary[s_key][dom_key]
            val = float(m["svsr_pct"])
            ci_lo, ci_hi = float(m["svsr_ci95"][0]), float(m["svsr_ci95"][1])
            bx = gx + s_idx * (bar_w + 3)
            bh = (val / 100.0) * p1_h
            by = p1_y + p1_h - bh
            svg.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w}" height="{bh:.1f}" fill="{color}" rx="2"/>')

            # Error bar (95% Wilson CI)
            ey_lo = p1_y + p1_h - (ci_lo / 100.0) * p1_h
            ey_hi = p1_y + p1_h - (ci_hi / 100.0) * p1_h
            ecx = bx + bar_w / 2.0
            svg.append(f'<line x1="{ecx:.1f}" y1="{ey_hi:.1f}" x2="{ecx:.1f}" y2="{ey_lo:.1f}" stroke="#0f172a" stroke-width="1.3"/>')
            svg.append(f'<line x1="{ecx - 3.5:.1f}" y1="{ey_hi:.1f}" x2="{ecx + 3.5:.1f}" y2="{ey_hi:.1f}" stroke="#0f172a" stroke-width="1.3"/>')
            svg.append(f'<line x1="{ecx - 3.5:.1f}" y1="{ey_lo:.1f}" x2="{ecx + 3.5:.1f}" y2="{ey_lo:.1f}" stroke="#0f172a" stroke-width="1.3"/>')
            svg.append(f'<text x="{ecx:.1f}" y="{max(p1_y + 10, ey_hi - 5):.1f}" text-anchor="middle" font-size="9.5" font-weight="600" fill="#0f172a">{val:.1f}</text>')

        svg.append(f'<text x="{gx + 40:.1f}" y="{p1_y + p1_h + 20}" text-anchor="middle" font-size="11" font-weight="600" fill="#1e293b">{_esc(dom_label)}</text>')

    # Panel B (Right): Combined Metrics Comparison (SVSR, Recovery Rate, Unsafe Side-Effect Rate, Contract Escape Rate, Escalation Rate)
    p2_x, p2_y, p2_w, p2_h = 560, 115, 440, 340
    svg.append(f'<text x="{p2_x + p2_w/2}" y="{p2_y - 10}" text-anchor="middle" font-size="13" font-weight="700" fill="#0f172a">B. Combined Multi-Domain Metrics (N=180 per Strategy)</text>')

    for pct in (0, 20, 40, 60, 80, 100):
        gy = p2_y + p2_h - (pct / 100.0) * p2_h
        svg.append(f'<line x1="{p2_x}" y1="{gy:.1f}" x2="{p2_x + p2_w}" y2="{gy:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'<text x="{p2_x - 8}" y="{gy + 4:.1f}" text-anchor="end" font-size="11" fill="#64748b">{pct}%</text>')

    metric_Specs = [
        ("recovery_rate_pct", "recovery_rate_ci95", "Recovery Rate"),
        ("unsafe_side_effect_rate_pct", "unsafe_side_effect_ci95", "Unsafe Side-Effect"),
        ("contract_violation_escape_rate_pct", "contract_violation_escape_ci95", "Contract Escape"),
        ("human_escalation_rate_pct", "human_escalation_ci95", "Human Escalation"),
    ]
    m_group_w = p2_w / len(metric_Specs)
    for m_idx, (m_key, ci_key, m_label) in enumerate(metric_Specs):
        gx = p2_x + m_idx * m_group_w + 14
        for s_idx, (s_key, _s_label, color) in enumerate(strategies):
            m = summary[s_key]["all_domains_combined"]
            val = float(m[m_key])
            ci_lo, ci_hi = float(m[ci_key][0]), float(m[ci_key][1])
            bx = gx + s_idx * (bar_w + 3)
            bh = (val / 100.0) * p2_h
            by = p2_y + p2_h - bh
            svg.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w}" height="{max(1.5, bh):.1f}" fill="{color}" rx="2"/>')

            ey_lo = p2_y + p2_h - (ci_lo / 100.0) * p2_h
            ey_hi = p2_y + p2_h - (ci_hi / 100.0) * p2_h
            ecx = bx + bar_w / 2.0
            svg.append(f'<line x1="{ecx:.1f}" y1="{ey_hi:.1f}" x2="{ecx:.1f}" y2="{ey_lo:.1f}" stroke="#0f172a" stroke-width="1.3"/>')
            svg.append(f'<text x="{ecx:.1f}" y="{max(p2_y + 10, ey_hi - 5):.1f}" text-anchor="middle" font-size="9.5" font-weight="600" fill="#0f172a">{val:.1f}</text>')

        svg.append(f'<text x="{gx + 40:.1f}" y="{p2_y + p2_h + 20}" text-anchor="middle" font-size="11" font-weight="600" fill="#1e293b">{_esc(m_label)}</text>')

    # Footer note
    fg_comb = summary["FLOWGUARD_FULL"]["all_domains_combined"]
    svg.append(
        f'<text x="520" y="520" text-anchor="middle" font-size="11.5" fill="#334155">'
        f'Recorded FlowGuard Combined SVSR: {fg_comb["svsr_pct"]}% (95% CI: [{fg_comb["svsr_ci95"][0]}%, {fg_comb["svsr_ci95"][1]}%]) | '
        f'Recovery Rate: {fg_comb["recovery_rate_pct"]}% | Unsafe Side-Effect Rate: {fg_comb["unsafe_side_effect_rate_pct"]}% | '
        f'Human Escalation Rate: {fg_comb["human_escalation_rate_pct"]}% (unrecoverable faults + policy blocks)</text>'
    )
    svg.append("</svg>")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(svg), encoding="utf-8")


def generate_fig2_ablation_and_tradeoffs(
    ablation_data: Dict[str, Any],
    out_path: Path,
) -> None:
    """Figure 2: 5-Way Ablation Study & Token/Safety Trade-Offs."""
    summary = ablation_data["summary"]
    configs = [
        ("full_flowguard", "Full FlowGuard", "#10b981"),
        ("no_tier1_drift_normalizer", "No Tier-1 Drift Norm.", "#3b82f6"),
        ("no_tier2_repair", "No Tier-2 Repair", "#6366f1"),
        ("no_idempotency_reconciliation", "No Idem. Reconcil.", "#f59e0b"),
        ("no_deterministic_policy_guard", "No Det. Policy Guard", "#ef4444"),
    ]

    width, height = 1040, 540
    svg: List[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="system-ui, -apple-system, sans-serif">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        '<text x="520" y="34" text-anchor="middle" font-size="17" font-weight="700" fill="#0f172a">Figure 2: Five-Way Ablation Study Across 900 Executions (180 Scenarios × 5 Configurations)</text>',
        '<text x="520" y="54" text-anchor="middle" font-size="12" fill="#475569">Isolating Mechanism Contributions to SVSR (%), Unsafe Side-Effect Rate (%), and Repair Token Overhead</text>',
    ]

    # Left panel: SVSR (%) and Unsafe Side-Effect Rate (%) per ablation config
    p1_x, p1_y, p1_w, p1_h = 75, 105, 520, 330
    svg.append(f'<text x="{p1_x + p1_w/2}" y="{p1_y - 12}" text-anchor="middle" font-size="13" font-weight="700" fill="#0f172a">A. State-Verified Success Rate vs. Unsafe Side-Effect Rate (%)</text>')

    for pct in (0, 20, 40, 60, 80, 100):
        gy = p1_y + p1_h - (pct / 100.0) * p1_h
        svg.append(f'<line x1="{p1_x}" y1="{gy:.1f}" x2="{p1_x + p1_w}" y2="{gy:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'<text x="{p1_x - 8}" y="{gy + 4:.1f}" text-anchor="end" font-size="11" fill="#64748b">{pct}%</text>')

    gw = p1_w / len(configs)
    for idx, (c_key, c_label, color) in enumerate(configs):
        m = summary[c_key]["all_domains_combined"]
        svsr = float(m["svsr_pct"])
        svsr_lo, svsr_hi = float(m["svsr_ci95"][0]), float(m["svsr_ci95"][1])
        user = float(m["unsafe_side_effect_rate_pct"])

        gx = p1_x + idx * gw + 18
        # SVSR bar
        bh1 = (svsr / 100.0) * p1_h
        by1 = p1_y + p1_h - bh1
        svg.append(f'<rect x="{gx:.1f}" y="{by1:.1f}" width="28" height="{bh1:.1f}" fill="{color}" rx="2"/>')
        ey_lo = p1_y + p1_h - (svsr_lo / 100.0) * p1_h
        ey_hi = p1_y + p1_h - (svsr_hi / 100.0) * p1_h
        ecx = gx + 14.0
        svg.append(f'<line x1="{ecx:.1f}" y1="{ey_hi:.1f}" x2="{ecx:.1f}" y2="{ey_lo:.1f}" stroke="#0f172a" stroke-width="1.4"/>')
        svg.append(f'<text x="{ecx:.1f}" y="{ey_hi - 6:.1f}" text-anchor="middle" font-size="10" font-weight="700" fill="#0f172a">{svsr:.1f}%</text>')

        # USER bar (Unsafe Side-Effect Rate)
        bx2 = gx + 34
        bh2 = (user / 100.0) * p1_h
        by2 = p1_y + p1_h - bh2
        svg.append(f'<rect x="{bx2:.1f}" y="{by2:.1f}" width="24" height="{max(2.0, bh2):.1f}" fill="#dc2626" opacity="0.85" rx="2"/>')
        svg.append(f'<text x="{bx2 + 12:.1f}" y="{by2 - 6:.1f}" text-anchor="middle" font-size="9.5" font-weight="700" fill="#991b1b">{user:.1f}%</text>')

        svg.append(f'<text x="{gx + 28:.1f}" y="{p1_y + p1_h + 22}" text-anchor="middle" font-size="10.5" font-weight="600" fill="#1e293b">{_esc(c_label)}</text>')

    # Right panel: Mean Repair Tokens per Run & Escalation Rate
    p2_x, p2_y, p2_w, p2_h = 655, 105, 345, 330
    svg.append(f'<text x="{p2_x + p2_w/2}" y="{p2_y - 12}" text-anchor="middle" font-size="13" font-weight="700" fill="#0f172a">B. Mean Repair Tokens / Run (Cost Trade-Off)</text>')

    max_tok = 200.0
    for tok_tick in (0, 50, 100, 150, 200):
        gy = p2_y + p2_h - (tok_tick / max_tok) * p2_h
        svg.append(f'<line x1="{p2_x}" y1="{gy:.1f}" x2="{p2_x + p2_w}" y2="{gy:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'<text x="{p2_x - 8}" y="{gy + 4:.1f}" text-anchor="end" font-size="11" fill="#64748b">{tok_tick}</text>')

    gw2 = p2_w / len(configs)
    for idx, (c_key, c_label, color) in enumerate(configs):
        m = summary[c_key]["all_domains_combined"]
        tok = float(m["mean_tokens_per_run"])
        bx = p2_x + idx * gw2 + 18
        bh = min(p2_h, (tok / max_tok) * p2_h)
        by = p2_y + p2_h - bh
        svg.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="32" height="{max(2.0, bh):.1f}" fill="{color}" rx="2"/>')
        svg.append(f'<text x="{bx + 16:.1f}" y="{by - 6:.1f}" text-anchor="middle" font-size="10" font-weight="700" fill="#0f172a">{tok:.1f}</text>')
        svg.append(f'<text x="{bx + 16:.1f}" y="{p2_y + p2_h + 22}" text-anchor="middle" font-size="9.5" font-weight="600" fill="#1e293b">{_esc(c_label.split()[0] + " " + c_label.split()[1])}</text>')

    no_t1 = summary["no_tier1_drift_normalizer"]["all_domains_combined"]
    full_m = summary["full_flowguard"]["all_domains_combined"]
    no_rec = summary["no_idempotency_reconciliation"]["all_domains_combined"]
    no_pol = summary["no_deterministic_policy_guard"]["all_domains_combined"]
    svg.append(
        f'<text x="520" y="505" text-anchor="middle" font-size="11.5" fill="#334155">'
        f'Key Findings: Removing Tier-1 increases token usage from {full_m["mean_tokens_per_run"]} to {no_t1["mean_tokens_per_run"]} tokens/run; '
        f'removing post-commit reconciliation raises Unsafe Side-Effects to {no_rec["unsafe_side_effect_rate_pct"]}%; '
        f'relying solely on taint regex raises Unsafe Side-Effects to {no_pol["unsafe_side_effect_rate_pct"]}%.</text>'
    )
    svg.append("</svg>")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(svg), encoding="utf-8")


def generate_fig3_live_llm_and_fault_breakdown(
    bench_data: Dict[str, Any],
    live_data: Dict[str, Any],
    out_path: Path,
) -> None:
    """Figure 3: Per-Fault-Class Recovery Profile & Live Local GPU (`llama3:latest`) Evaluation."""
    by_fc = bench_data["summary"]["FLOWGUARD_FULL"]["by_fault_class"]
    live_sum = live_data["summary"]
    model_name = live_data["epistemic_metadata"]["model_metadata"].get("name", "llama3:latest")

    width, height = 1040, 540
    svg: List[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="system-ui, -apple-system, sans-serif">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="520" y="34" text-anchor="middle" font-size="17" font-weight="700" fill="#0f172a">Figure 3: Fault-Class Breakdown (F0–F5) &amp; Live Local GPU Evaluation ({_esc(model_name)} on RTX 2050)</text>',
        '<text x="520" y="54" text-anchor="middle" font-size="12" fill="#475569">Left: FlowGuard SVSR &amp; Escalation by Fault Class (deterministic_harness) | Right: Experiment B Live GPU Inference (live_llm_inference)</text>',
    ]

    # Panel A (Left): FlowGuard SVSR & Human Escalation across F0..F5
    p1_x, p1_y, p1_w, p1_h = 70, 105, 480, 330
    svg.append(f'<text x="{p1_x + p1_w/2}" y="{p1_y - 12}" text-anchor="middle" font-size="13" font-weight="700" fill="#0f172a">A. FlowGuard Outcome by Fault Class (30 Scenarios / Class)</text>')

    for pct in (0, 20, 40, 60, 80, 100):
        gy = p1_y + p1_h - (pct / 100.0) * p1_h
        svg.append(f'<line x1="{p1_x}" y1="{gy:.1f}" x2="{p1_x + p1_w}" y2="{gy:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'<text x="{p1_x - 8}" y="{gy + 4:.1f}" text-anchor="end" font-size="11" fill="#64748b">{pct}%</text>')

    fault_classes = [
        ("F0_NOMINAL", "F0: Nominal"),
        ("F1_TRANSIENT_AND_AMBIGUOUS_HTTP", "F1: HTTP/Ambig"),
        ("F2_SCHEMA_DRIFT", "F2: Drift"),
        ("F3_LLM_MALFORMED", "F3: Malformed"),
        ("F4_DUPLICATE_AND_CONCURRENT_EVENTS", "F4: Duplicate"),
        ("F5_ADVERSARIAL_INPUT", "F5: Adversarial"),
    ]
    gw = p1_w / len(fault_classes)
    for idx, (fc_key, fc_label) in enumerate(fault_classes):
        m = by_fc[fc_key]
        svsr = float(m["svsr_pct"])
        esc = float(m["human_escalation_rate_pct"])
        gx = p1_x + idx * gw + 12

        bh1 = (svsr / 100.0) * p1_h
        by1 = p1_y + p1_h - bh1
        svg.append(f'<rect x="{gx:.1f}" y="{by1:.1f}" width="24" height="{bh1:.1f}" fill="#10b981" rx="2"/>')
        svg.append(f'<text x="{gx + 12:.1f}" y="{by1 - 5:.1f}" text-anchor="middle" font-size="9.5" font-weight="700" fill="#065f46">{svsr:.0f}%</text>')

        bx2 = gx + 28
        bh2 = (esc / 100.0) * p1_h
        by2 = p1_y + p1_h - bh2
        svg.append(f'<rect x="{bx2:.1f}" y="{by2:.1f}" width="24" height="{max(1.5, bh2):.1f}" fill="#6366f1" rx="2"/>')
        svg.append(f'<text x="{bx2 + 12:.1f}" y="{by2 - 5:.1f}" text-anchor="middle" font-size="9.5" font-weight="700" fill="#3730a3">{esc:.0f}%</text>')

        svg.append(f'<text x="{gx + 26:.1f}" y="{p1_y + p1_h + 20}" text-anchor="middle" font-size="10" font-weight="600" fill="#1e293b">{_esc(fc_label)}</text>')

    # Panel B (Right): Live GPU Experiment B (B2_NAIVE_RETRY vs FLOWGUARD_FULL)
    p2_x, p2_y, p2_w, p2_h = 610, 105, 390, 330
    svg.append(f'<text x="{p2_x + p2_w/2}" y="{p2_y - 12}" text-anchor="middle" font-size="13" font-weight="700" fill="#0f172a">B. Experiment B: Live {model_name} GPU Evaluation</text>')

    for pct in (0, 20, 40, 60, 80, 100):
        gy = p2_y + p2_h - (pct / 100.0) * p2_h
        svg.append(f'<line x1="{p2_x}" y1="{gy:.1f}" x2="{p2_x + p2_w}" y2="{gy:.1f}" stroke="#e2e8f0" stroke-width="1"/>')
        svg.append(f'<text x="{p2_x - 8}" y="{gy + 4:.1f}" text-anchor="end" font-size="11" fill="#64748b">{pct}%</text>')

    live_metrics = [
        ("svsr_pct", "SVSR (%)"),
        ("unsafe_side_effect_rate_pct", "Unsafe Side-Effect (%)"),
        ("contract_violation_escape_rate_pct", "Contract Escape (%)"),
    ]
    gw2 = p2_w / len(live_metrics)
    b2_live = live_sum["B2_NAIVE_RETRY"]["all_domains_combined"]
    fg_live = live_sum["FLOWGUARD_FULL"]["all_domains_combined"]

    for idx, (m_key, m_label) in enumerate(live_metrics):
        gx = p2_x + idx * gw2 + 24
        v_b2 = float(b2_live[m_key])
        v_fg = float(fg_live[m_key])

        bh_b2 = (v_b2 / 100.0) * p2_h
        by_b2 = p2_y + p2_h - bh_b2
        svg.append(f'<rect x="{gx:.1f}" y="{by_b2:.1f}" width="32" height="{max(2.0, bh_b2):.1f}" fill="#f59e0b" rx="2"/>')
        svg.append(f'<text x="{gx + 16:.1f}" y="{by_b2 - 6:.1f}" text-anchor="middle" font-size="10.5" font-weight="700" fill="#92400e">{v_b2:.1f}%</text>')

        bx_fg = gx + 38
        bh_fg = (v_fg / 100.0) * p2_h
        by_fg = p2_y + p2_h - bh_fg
        svg.append(f'<rect x="{bx_fg:.1f}" y="{by_fg:.1f}" width="32" height="{max(2.0, bh_fg):.1f}" fill="#10b981" rx="2"/>')
        svg.append(f'<text x="{bx_fg + 16:.1f}" y="{by_fg - 6:.1f}" text-anchor="middle" font-size="10.5" font-weight="700" fill="#065f46">{v_fg:.1f}%</text>')

        svg.append(f'<text x="{gx + 35:.1f}" y="{p2_y + p2_h + 20}" text-anchor="middle" font-size="10.5" font-weight="600" fill="#1e293b">{_esc(m_label)}</text>')

    svg.append(
        f'<text x="520" y="505" text-anchor="middle" font-size="11.5" fill="#334155">'
        f'Live {model_name} Summary (30 Runs across 3 Domains): B2 Naive Retry SVSR={b2_live["svsr_pct"]}% (Unsafe={b2_live["unsafe_side_effect_rate_pct"]}%) vs. '
        f'FlowGuard SVSR={fg_live["svsr_pct"]}% (Unsafe={fg_live["unsafe_side_effect_rate_pct"]}%, p50={fg_live["latency_p50_ms"]} ms, p95={fg_live["latency_p95_ms"]} ms).</text>'
    )
    svg.append("</svg>")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(svg), encoding="utf-8")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    results_dir = root / "results"
    figures_dir = root / "docs" / "figures"

    bench_data = json.loads(
        (results_dir / "experiment_a_benchmark_results.json").read_text(encoding="utf-8")
    )
    ablation_data = json.loads(
        (results_dir / "ablation_study_results.json").read_text(encoding="utf-8")
    )
    live_data = json.loads(
        (results_dir / "experiment_b_live_results.json").read_text(encoding="utf-8")
    )

    generate_fig1_strategy_comparison(
        bench_data, figures_dir / "fig1_strategy_comparison_by_domain.svg"
    )
    generate_fig2_ablation_and_tradeoffs(
        ablation_data, figures_dir / "fig2_ablation_and_idempotency_tradeoffs.svg"
    )
    generate_fig3_live_llm_and_fault_breakdown(
        bench_data, live_data, figures_dir / "fig3_live_llm_and_fault_breakdown.svg"
    )
    print(f"Generated 3 SVG figures in {figures_dir}")


if __name__ == "__main__":
    main()
