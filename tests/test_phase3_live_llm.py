"""Phase 3 Test Suite: Live Local GPU LLM Provider (`llama3:latest`) & Experiment B Artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flowguard.llm_provider import OllamaLLMProvider, validate_ollama_base_url
from flowguard.models import ExecutionModeLabel, StrategyMode


def test_ollama_url_ssrf_validation() -> None:
    assert validate_ollama_base_url("http://127.0.0.1:11434") == "http://127.0.0.1:11434"
    assert validate_ollama_base_url("http://localhost:11434/") == "http://localhost:11434"

    with pytest.raises(ValueError, match="SSRF_SCHEME_BLOCKED"):
        validate_ollama_base_url("file:///etc/passwd")

    with pytest.raises(ValueError, match="SSRF_SCHEME_BLOCKED"):
        validate_ollama_base_url("ftp://127.0.0.1:21/model")

    with pytest.raises(ValueError, match="SSRF_METADATA_IP_BLOCKED"):
        validate_ollama_base_url("http://169.254.169.254/latest/meta-data")

    with pytest.raises(ValueError, match="SSRF_HOST_NOT_ALLOWLISTED"):
        validate_ollama_base_url("http://10.99.88.77:11434")


def test_experiment_b_live_artifacts_integrity() -> None:
    results_dir = Path(__file__).resolve().parent.parent / "results"
    json_path = results_dir / "experiment_b_live_results.json"
    csv_path = results_dir / "experiment_b_summary.csv"

    assert json_path.exists(), "experiment_b_live_results.json must exist"
    assert csv_path.exists(), "experiment_b_summary.csv must exist"

    data = json.loads(json_path.read_text(encoding="utf-8"))
    meta = data["epistemic_metadata"]
    assert meta["execution_mode_label"] == ExecutionModeLabel.LIVE_LLM_INFERENCE.value
    assert meta["model_metadata"]["name"] == "llama3:latest"
    assert meta["total_live_scenarios"] == 15
    assert meta["total_evaluated_runs"] == 30

    fg_summary = data["summary"][StrategyMode.FLOWGUARD_FULL.value]["all_domains_combined"]
    b2_summary = data["summary"][StrategyMode.B2_NAIVE_RETRY.value]["all_domains_combined"]

    assert fg_summary["svsr_pct"] > b2_summary["svsr_pct"]
    assert fg_summary["unsafe_side_effect_rate_pct"] == 0.0
    assert fg_summary["contract_violation_escape_rate_pct"] == 0.0
    assert b2_summary["unsafe_side_effect_rate_pct"] > 0.0
    assert fg_summary["latency_p50_ms"] > 10.0  # Real GPU latency in hundreds/thousands of ms

    # Verify raw LLM responses and tokens are recorded on every run
    for rec in data["records"]:
        assert isinstance(rec["initial_raw_llm_response"], str)
        assert len(rec["initial_raw_llm_response"].strip()) > 0
        assert rec["total_tokens"] > 0
        assert rec["total_latency_ms"] > 0.0
