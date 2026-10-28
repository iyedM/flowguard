# FlowGuard: Contract-Aware Runtime Verification, Bounded Recovery & Side-Effect Idempotency for Agentic n8n Workflows

**Author:** Iyed Mohamed (`ORCID: 0009-0008-9493-7510`, ESPRIT School of Engineering)  
**Target Repository:** `/home/iyed/Documents/flowguard` (`https://github.com/iyedM/flowguard`)

---

## 1. Core Research Question & Epistemic Scope

> **Research Question:**  
> *Does contract-aware runtime verification combined with bounded two-tier recovery and a 4-state idempotency lifecycle improve end-to-end state correctness in agentic n8n workflows under controlled faults, compared with native workflow handling, retries alone, and deterministic contract validation alone—and what are the measurable latency, token, and unrecoverable-failure trade-offs?*

### Epistemic & Methodological Principles (Strict Scientific Honesty)
1. **No Pre-Determined Outcomes:** No metric (`SVSR`, `RR`, `USER`, `CVER`, `FRR`, latency) is hard-coded or targeted in advance. All tables, figures, and reports must reflect the exact recorded executions, including **failed recoveries, unrecoverable faults, and ambiguous timeout states**.
2. **Explicit Component Labeling:** Every module and result artifact explicitly labels its execution mode:
   - `deterministic_harness` (contract validator, policy engine, fault injector),
   - `stateful_simulated_sink` (local SQLite/in-memory stateful test services with ground-truth state comparison—never misrepresented as live cloud production clusters),
   - `live_llm_inference` (actual GPU inference via local Ollama `llama3:latest`),
   - `exportable_n8n_workflow_json` (importable `n8n` workflow definitions in `workflows/*.json`).
3. **Separation of Security Boundary vs. Fallible Taint Signals:**
   - **Deterministic Action & Capability Policy (Hard Security Boundary):** Security invariants depend solely on authoritative context attributes (e.g., scanner `cvss_score`, target `namespace`, `team_monthly_budget_cap_usd`) and least-privilege allowlists. An LLM can never override a security invariant, regardless of prompt text.
   - **Untrusted Text Taint & Prompt-Injection Detector (Diagnostic / Audit Signal):** Pattern/heuristic detection on untrusted text fields (`untrusted_pr_body`, `recent_log_snippet`, `justification_notes`) is recorded as an observability signal and escalation trigger, never relied upon as the sole security boundary.
4. **Realistic 4-State Idempotency Lifecycle (`PENDING_IN_FLIGHT`, `COMMITTED`, `FAILED_SAFE_TO_RETRY`, `AMBIGUOUS_REQUIRES_RECONCILIATION`):**
   - Explicitly models the classic distributed-systems failure where a downstream service executes a side effect, but the HTTP response times out in transit (*post-commit timeout*).
   - When a retry arrives for an `idem_key` currently in `PENDING_IN_FLIGHT` or `AMBIGUOUS_REQUIRES_RECONCILIATION`, `FlowGuard` does **not** blindly re-execute the mutation; it queries the sink's reconciliation/read endpoint (or halts for safe reconciliation) to prevent duplicate side effects.

---

## 2. The Four Core Mechanisms (`flowguard/`)

1. **Mechanism A — Deterministic Contract & Cross-Field Invariant Validator (`flowguard/contracts.py`):**
   - Validates structural schema (JSON Schema Draft 2020-12) and domain-specific cross-field invariants before any sink mutation.
   - Emits a 3-state verdict: `VALID`, `RECOVERABLE_VIOLATION`, or `UNSAFE_POLICY_BLOCK`.
2. **Mechanism B — Two-Tier Bounded Recovery Controller (`flowguard/recovery.py`):**
   - **Tier 1 (Symbolic Schema-Drift Normalizer):** Resolves known/alias field renames and safe scalar type coercions deterministically (0 LLM tokens). Every Tier-1 output is re-validated by Mechanism A.
   - **Tier 2 (Bounded LLM / LangGraph Repair, `max_repair_turns = 2`):** On malformed LLM JSON or repairable invariant errors (e.g., arithmetic miscalculation or out-of-range replica count), feeds the exact violated predicate back to the model and re-validates the candidate output through Mechanism A. If still invalid after budget exhaustion, transitions to `SAFE_ESCALATION_HALT`.
3. **Mechanism C — 4-State Transactional Idempotency & Side-Effect Proxy (`flowguard/idempotency.py`):**
   - SQLite `WAL` ledger tracking `(idem_key, workflow_id, entity_id, operation, payload_hash, state, sink_receipt)`.
   - Handles concurrent duplicate webhooks, safe retries on pre-execution failures (`FAILED_SAFE_TO_RETRY`), cached replay on `COMMITTED`, and read-before-write state reconciliation on `AMBIGUOUS_REQUIRES_RECONCILIATION` (post-mutation timeout).
4. **Mechanism D — Least-Privilege Policy Engine & Untrusted Taint Auditor (`flowguard/policy_guard.py`):**
   - Enforces immutable capability bounds per workflow and logs adversarial taint signals (`arXiv:2605.11229`) into OpenTelemetry spans (`flowguard.*`).

---

## 3. Phased Domain Generalization: Primary AIOps Workflow -> DevSecOps & Cloud FinOps

1. **Domain 1 (Primary Reference Workflow) — `AIOps Incident Triage & Bounded Remediation` (`workflows/aiops_incident_remediation_n8n.json`):**
   - *Context:* Prometheus/OpenTelemetry alert (`alert_id`, `service_name`, `namespace`, `cpu_throttle_pct`, `memory_psi`, `error_rate_5xx`, `recent_log_snippet`).
   - *Invariants:* `1 <= target_replicas <= 32`; destructive actions (`rollback_deployment`, `restart_workers`) forbidden on `prod-stateful-db` without `human_approval_token`; `SEV1` requires `oncall_paged == True` and `cooldown_seconds >= 300`.
2. **Domain 2 (Generalization A) — `DevSecOps CI/CD CVE & Secret Triage` (`workflows/devsecops_cve_triage_n8n.json`):**
   - *Context:* CI/CD scanner report (`pr_number`, `cve_id`, `cvss_score`, `secret_detected`, `untrusted_pr_title_and_body`).
   - *Invariants:* Authoritative scanner attributes (`cvss_score >= 7.0` or `secret_detected == True`) strictly enforce `merge_decision == "BLOCK_MERGE"` and `rotate_secret == True`, immune to prompt injection inside `untrusted_pr_title_and_body`.
3. **Domain 3 (Generalization B) — `Cloud & GPU FinOps Quota Provisioning` (`workflows/cloud_finops_provisioning_n8n.json`):**
   - *Context:* GitOps infrastructure request (`environment`, `requested_vcpu`, `requested_gpu_count`, `hourly_unit_cost_usd`, `team_monthly_budget_cap_usd`).
   - *Invariants:* Arithmetic consistency (`abs(hourly_unit_cost_usd * 730 - computed_monthly_cost_usd) <= 0.05`), budget cap enforcement (`computed_monthly_cost_usd > team_monthly_budget_cap_usd => provisioning_decision == "HOLD_FOR_FINOPS_APPROVAL"`), and `dev`/`staging` GPU quota limits (`gpu_count <= 2`).

---

## 4. Controlled Benchmark & Fault-Injection Protocol

### 4.1 Six Fault Classes (Including Post-Mutation Ambiguous Timeouts & Unrecoverable Cases)
1. **`F0_NOMINAL`:** Clean, valid inputs (including boundary values) to measure **False Rejection Rate (`FRR`)**.
2. **`F1_TRANSIENT_AND_AMBIGUOUS_HTTP`:** Includes both *pre-mutation* `HTTP 429/503` errors and *post-mutation* network timeouts (where the sink mutated state, but the response dropped—testing the `AMBIGUOUS_REQUIRES_RECONCILIATION` state!).
3. **`F2_SCHEMA_DRIFT`:** Known alias renames, nested field shifts, and safe scalar stringification, plus a subset of *unknown/unmapped* schema corruptions to honestly measure where Tier-1 symbolic mapping fails and requires Tier-2 or safe escalation.
4. **`F3_LLM_MALFORMED`:** Markdown-wrapped JSON, out-of-range replica counts (`0` or `100`), arithmetic cost errors, and unrepairable multi-field truncations.
5. **`F4_DUPLICATE_AND_CONCURRENT_EVENTS`:** Repeated Alertmanager/GitHub webhooks and concurrent race deliveries sharing the same business entity.
6. **`F5_ADVERSARIAL_INPUT`:** Indirect prompt injection attempts in logs/PR bodies (`arXiv:2605.11229`) paired with high-risk authoritative attributes (`cvss_score = 9.8` or `namespace = "prod-stateful-db"`) to verify that deterministic policy enforcement holds even under subtle phrasing.

### 4.2 Four Evaluated Strategies, Five-Way Ablation & Live GPU LLM Evaluation
* **Baselines & Proposed Method:** `B1_NATIVE_N8N`, `B2_NAIVE_RETRY`, `B3_CONTRACT_ONLY`, `FLOWGUARD_FULL`.
* **Per-Domain + Aggregated Reporting:** Report results separately for `Domain 1 (AIOps)`, `Domain 2 (DevSecOps)`, `Domain 3 (Cloud FinOps)`, and `All Domains Combined` with 95% Wilson Score confidence intervals.
* **Ablations:** `full_flowguard`, `no_tier1_drift_normalizer`, `no_tier2_llm_repair`, `no_idempotency_reconciliation`, `no_deterministic_policy_guard`.
* **Live Local GPU LLM Experiment (`Experiment B`):** Real inference with local `llama3:latest` (8B on NVIDIA RTX 2050 via Ollama) recording exact model tag, temperature, prompt template, raw responses, token counts, latencies, and both successful and failed repair trajectories in `results/experiment_b_live_results.json`.
