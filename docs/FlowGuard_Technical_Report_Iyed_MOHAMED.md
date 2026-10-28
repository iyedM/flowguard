# FlowGuard: Contract-Aware Runtime Verification, Bounded Two-Tier Recovery, and 4-State Transactional Idempotency for Agentic Workflows

**Author:** Iyed Mohamed — Final-Year Computer Engineering Student (Master 2 Equivalent, CTI / EUR-ACE Accredited), ESPRIT School of Engineering, Tunis, Tunisia  
**ORCID:** [`0009-0008-9493-7510`](https://orcid.org/0009-0008-9493-7510) | **GitHub Repository:** [`https://github.com/iyedM/flowguard`](https://github.com/iyedM/flowguard) | **Companion Research:** *CEGAR-Harness* ([`DOI: 10.5281/zenodo.23731911`](https://doi.org/10.5281/zenodo.23731911))  
**Date:** October 28, 2026 | **Version:** `v0.2.0` (46/46 Automated Verification & Security Hardening Tests Passing)

---

## Abstract

Low-code and code-first workflow engines such as **n8n**, **LangGraph**, and **Model Context Protocol (MCP)** tool servers increasingly embed Large Language Models (LLMs) inside operational automation loops across **AIOps incident remediation**, **DevSecOps vulnerability/secret triage**, and **Cloud/GPU FinOps quota provisioning**. While traditional workflow orchestrators ensure graph-level message routing, they lack formal runtime verification at the boundary where stochastic LLM reasoning triggers external state-mutating APIs. Consequently, operational agentic workflows suffer from four compound failure modes: (1) *schema drift and markdown-wrapped JSON truncation*, (2) *silent cross-field semantic invariant violations*, (3) *duplicate state mutations caused by blind retries after post-commit HTTP timeouts*, and (4) *indirect prompt-injection attacks embedded in untrusted logs, pull requests, or tickets*.

We present **FlowGuard**, a neuro-symbolic verification, bounded recovery, and transactional idempotency middleware for agentic workflows. FlowGuard interposes four mechanisms between untrusted LLM outputs and downstream side-effect sinks: **(A) Deterministic Contract & Cross-Field Invariant Validation** (JSON Schema Draft 2020-12 paired with domain-specific semantic invariants emitting a 3-state verdict: `VALID`, `RECOVERABLE_VIOLATION`, or `UNSAFE_POLICY_BLOCK`); **(B) Bounded Two-Tier Recovery** combining a 0-token Tier-1 symbolic schema-drift normalizer with a bounded Tier-2 predicate-guided repair loop (`max_repair_turns = 2`) and linear-time $O(N)$ `JSONDecoder.raw_decode` extraction; **(C) A 4-State SQLite WAL Transactional Idempotency Machine** (`PENDING_IN_FLIGHT`, `COMMITTED`, `FAILED_SAFE_TO_RETRY`, and `AMBIGUOUS_REQUIRES_RECONCILIATION`) with read-before-write reconciliation and IETF `Idempotency-Key` payload-hash conflict detection; and **(D) Strict Separation of the Deterministic Security Policy Boundary from Fallible Untrusted Taint Signals** (`is_authoritative_boundary = False`).

Across a **720-run controlled multi-domain benchmark** (180 scenarios $\times$ 4 strategies), FlowGuard lifts the State-Verified Success Rate (SVSR) from **18.89%** [95% Wilson CI: 13.84%, 25.23%] (native n8n) and **27.22%** [21.25%, 34.15%] (naive retry) to **91.67%** [86.71%, 94.89%], while reducing the Unsafe Side-Effect Rate from **67.78%** to **0.00%**. A **900-run 5-way ablation study** isolates the exact contribution of each mechanism. Finally, in **30 live local GPU runs** using `llama3:latest` (8B Q4_0 via Ollama on an NVIDIA RTX 2050), FlowGuard achieves **93.33% SVSR** [70.18%, 98.81%] (14/15 scenarios, cleanly escalating 1 unrecoverable schema drift) and **0.00% unsafe side-effects** compared to **20.00% SVSR** and **73.33% unsafe side-effects** under naive retry.

---

## 1. Introduction, Research Question & Explicit Epistemic Labeling

### 1.1 Central Research Question
> **Research Question (RQ):** *Does contract-aware runtime verification combined with bounded two-tier recovery and a 4-state transactional idempotency lifecycle improve end-to-end state correctness in agentic workflows under controlled faults, compared with native workflow handling (`B1`), naive LLM/HTTP retries (`B2`), and deterministic contract rejection alone (`B3`)—and what are the measurable latency, token, and unrecoverable-failure trade-offs?*

### 1.2 Explicit Epistemic Labeling (`ExecutionModeLabel`)
To eliminate any ambiguity between deterministic test harnesses, simulated stateful services, and real GPU LLM inference, every execution trace, JSON artifact, and OpenTelemetry span in FlowGuard is tagged with one of four mutually exclusive epistemic labels (`flowguard/models.py`):
1. `deterministic_harness`: Pure Python runtime verification (`ContractValidator`, `PolicyGuard`, `RecoveryController` Tier-1, and deterministic fault-injection scheduling).
2. `stateful_simulated_sink`: Local in-memory/SQLite-backed stateful emulators (`StatefulAIOpsClusterSink`, `StatefulDevSecOpsGateSink`, `StatefulCloudFinOpsLedgerSink`) that track ground-truth entity state, pre-commit HTTP 429/503 transient errors, and post-commit HTTP network timeouts. These are explicitly labeled as local stateful test services and never misrepresented as live cloud production clusters.
3. `live_llm_inference`: Real stochastic LLM inference executed over HTTP against a local Ollama GPU server (`llama3:latest`, digest `365c0bd3c000a25d...`, 8.0B parameters, Q4_0 quantization, `temperature=0.0`).
4. `exportable_n8n_workflow_json`: Importable n8n workflow JSON topologies (`workflows/*.json`) wiring webhook triggers, LLM decision nodes, and FlowGuard verification gates.

---

## 2. Formal Architecture & The Four Runtime Mechanisms

### 2.1 Mechanism A: Deterministic Contract & Cross-Field Invariant Validator (`flowguard/contracts.py`)
Given an authoritative workflow context $C$ (sourced from trusted telemetry, CI/CD scanners, or cloud billing catalogs) and an untrusted candidate payload $P$ produced by an LLM node, Mechanism A evaluates structural conformance against a strict JSON Schema Draft 2020-12 specification $\mathcal{S}_d$ (`additionalProperties: False`) and a domain-specific set of cross-field relational invariants $\mathcal{I}_d(P, C)$:
- **Domain 1 (`aiops_incident_remediation`):**
  1. *Context Binding:* $P.\text{alert\_id} = C.\text{alert\_id}$, $P.\text{namespace} = C.\text{namespace}$, and $P.\text{severity} = C.\text{severity}$.
  2. *Replica Safety Bounds:* $P.\text{action} = \texttt{scale\_replicas} \implies P.\text{target\_replicas} \in [1, 32]$.
  3. *SEV1 Escalation & Cooldown Invariant:* $C.\text{severity} = \texttt{SEV1} \implies (P.\text{oncall\_paged} = \texttt{true} \land P.\text{cooldown\_seconds} \ge 300)$.
  4. *Stateful Production Database Protection:* $(C.\text{namespace} = \texttt{prod-stateful-db} \land P.\text{action} \in \{\texttt{rollback\_deployment}, \texttt{restart\_workers}\})$ requires a valid cryptographic/authoritative approval token in $C.\text{human\_approval\_token}$ matching $P.\text{human\_approval\_token}$ via constant-time `hmac.compare_digest`.
- **Domain 2 (`devsecops_cve_triage`):**
  1. *Scanner Ground-Truth Binding:* $P.\text{pr\_number} = C.\text{pr\_number}$, $|P.\text{cvss\_score} - C.\text{cvss\_score}| \le 10^{-4}$, and $P.\text{secret\_detected} = C.\text{secret\_detected}$.
  2. *Mandatory High-Risk Merge Block:* $(C.\text{cvss\_score} \ge 7.0 \lor C.\text{secret\_detected} = \texttt{true}) \implies P.\text{merge\_decision} = \texttt{BLOCK\_MERGE}$.
  3. *Secret Rotation & Critical Quarantine:* $C.\text{secret\_detected} = \texttt{true} \implies P.\text{rotate\_secret} = \texttt{true}$, and $C.\text{cvss\_score} \ge 9.0 \implies P.\text{quarantine\_artifact} = \texttt{true}$.
- **Domain 3 (`cloud_finops_provisioning`):**
  1. *Arithmetic Monthly Cost Invariant:* $|P.\text{computed\_monthly\_cost\_usd} - \text{round}(C.\text{hourly\_unit\_cost\_usd} \times 730.0, 2)| \le 0.05$.
  2. *Budget Cap Governance:* $\text{round}(C.\text{hourly\_unit\_cost\_usd} \times 730.0, 2) > C.\text{team\_monthly\_budget\_cap\_usd} \implies P.\text{provisioning\_decision} = \texttt{HOLD\_FOR\_FINOPS\_APPROVAL}$.
  3. *Non-Production GPU Quota:* $C.\text{environment} \in \{\texttt{dev}, \texttt{staging}\} \implies P.\text{requested\_gpu\_count} \le 2$.

Mechanism A classifies every evaluation into a 3-state verdict: `VALID`, `RECOVERABLE_VIOLATION` (eligible for Mechanism B), or `UNSAFE_POLICY_BLOCK` (immediate halt and human escalation).

### 2.2 Mechanism B: Bounded Two-Tier Recovery Controller (`flowguard/recovery.py`)
When Mechanism A returns `RECOVERABLE_VIOLATION`, Mechanism B executes a strictly bounded two-tier recovery protocol:
- **Tier 1 (0-Token Symbolic Schema-Drift Normalizer):** Unwraps known single-key JSON envelopes (`remediation`, `triage`, `provisioning`, `payload`), maps known domain field aliases (e.g., `replicas -> target_replicas`, `cvss -> cvss_score`, `monthly_cost_usd -> computed_monthly_cost_usd`), and performs safe scalar coercions (`"4" -> 4`, `"true" -> True`) with **zero LLM tokens**. Crucially, Tier 1 *honestly fails* on unknown or unmapped multi-field schema drift.
- **Tier 2 (Bounded Predicate-Guided Repair Loop, `max_repair_turns = 2`):** Extracts JSON from markdown fences or prose using a linear-time $O(N)$ `json.JSONDecoder().raw_decode` scanner (`MAX_RAW_EXTRACT_CHARS = 65536`, eliminating quadratic regex backtracking / ReDoS) and feeds exact violated predicate identifiers back to the repair callback for at most 2 turns. Every candidate is re-validated through Mechanism A. If violations persist after Turn 2, FlowGuard halts cleanly in `SAFE_ESCALATION_HALT`.

### 2.3 Mechanism C: 4-State SQLite WAL Transactional Idempotency Proxy (`flowguard/idempotency.py`)
Standard 2-state idempotency caches (`NEW` vs. `DONE`) fail when an HTTP timeout occurs *after* the downstream service has already mutated state (`PostCommitTimeoutError`). FlowGuard implements a thread-safe SQLite WAL state machine (`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`) with four states:
1. `PENDING_IN_FLIGHT`: Acquired atomically before invoking the downstream sink; blocks concurrent duplicate webhook deliveries.
2. `COMMITTED`: Recorded alongside the canonical `payload_hash` and `sink_receipt_json`; subsequent retries with the same `idem_key` and `payload_hash` replay the cached receipt without re-mutating the sink. If a caller reuses an existing `idem_key` with a *different* `payload_hash`, FlowGuard raises `IdempotencyPayloadMismatchError` (HTTP `409 Conflict`, enforcing the IETF `Idempotency-Key` draft specification).
3. `FAILED_SAFE_TO_RETRY`: Recorded when the sink raises a pre-commit transient error (e.g., HTTP 429/503 before state mutation); safe to re-execute on retry.
4. `AMBIGUOUS_REQUIRES_RECONCILIATION`: Recorded when the sink call times out after request transmission (`PostCommitTimeoutError`). On retry, FlowGuard **forbids blind re-execution** and instead queries the sink's read-only reconciliation endpoint (`reconcile_read(entity_id, idem_key)`). If the sink confirms the mutation was already applied, FlowGuard transitions `AMBIGUOUS_REQUIRES_RECONCILIATION -> COMMITTED` without re-mutating; if the sink lacks a read endpoint, FlowGuard halts in `AMBIGUOUS_REQUIRES_RECONCILIATION` for operator inspection.

### 2.4 Mechanism D: Separation of Deterministic Policy Boundary vs. Fallible Taint Signal (`flowguard/policy_guard.py`)
A common design flaw in LLM guardrails is using regex or classifier-based prompt-injection detection on untrusted text (`recent_log_snippet`, `untrusted_pr_body`) as the primary security gate. Adversaries easily evade keyword filters using polite, domain-plausible paraphrases. In FlowGuard:
- The **Authoritative Security Boundary (`PolicyGuard.evaluate`)** is 100% deterministic and depends *exclusively* on authoritative context attributes ($C$) and capability allowlists.
- The **Untrusted Taint Auditor (`PolicyGuard.audit_untrusted_text`)** scans untrusted text fields and emits a `TaintSignal` explicitly marked `is_authoritative_boundary = False` into OpenTelemetry spans for security observability.

---

## 3. Experiment A: Multi-Domain Controlled Benchmark (720 Executions)

We evaluate **180 controlled scenarios** (60 per domain across AIOps, DevSecOps, and Cloud FinOps) spanning **6 fault classes** (`F0_NOMINAL`, `F1_FORMAT_DRIFT`, `F2_SEMANTIC_VIOLATION`, `F3_TRANSIENT_PRE_COMMIT`, `F4_POST_COMMIT_TIMEOUT`, `F5_ADVERSARIAL_INPUT`) under **4 strategies** ($180 \times 4 = 720$ runs):
- `B1_NATIVE_N8N`: Native workflow execution without contract checks, repair, or idempotency ledger.
- `B2_NAIVE_RETRY`: Unstructured retry loop (up to 2 retries on error/timeout) without contract predicates or post-commit reconciliation.
- `B3_CONTRACT_ONLY`: Deterministic JSON Schema + cross-field invariant gate (Mechanism A + D) that rejects invalid outputs immediately without Tier-1/Tier-2 recovery or 4-state timeout reconciliation.
- `FLOWGUARD_FULL`: Complete FlowGuard pipeline (Mechanisms A + B + C + D).

| Strategy | Domain | Runs | SVSR % [95% Wilson CI] | Recovery Rate % [95% CI] | Unsafe Side-Effect % | Contract Escape % | Human Escalation % | Mean Tokens | Latency p50 / p95 (ms) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `B1_NATIVE_N8N` | Domain 1: AIOps Remediation | 60 | **16.67%** [9.31, 28.03] | 0.00% [0.00, 7.13] | 58.33% | 41.67% | 0.00% | 0.00 | 0.030 / 0.041 |
| `B1_NATIVE_N8N` | Domain 2: DevSecOps Triage | 60 | **20.00%** [11.83, 31.78] | 4.00% [1.10, 13.46] | 55.00% | 38.33% | 0.00% | 0.00 | 0.021 / 0.041 |
| `B1_NATIVE_N8N` | Domain 3: Cloud FinOps | 60 | **20.00%** [11.83, 31.78] | 4.00% [1.10, 13.46] | 55.00% | 38.33% | 0.00% | 0.00 | 0.022 / 0.040 |
| `B1_NATIVE_N8N` | All Domains Combined | 180 | **18.89%** [13.84, 25.23] | 2.67% [1.04, 6.66] | 56.11% | 39.44% | 0.00% | 0.00 | 0.025 / 0.041 |
| `B2_NAIVE_RETRY` | Domain 1: AIOps Remediation | 60 | **25.00%** [15.78, 37.23] | 10.00% [4.35, 21.36] | 70.00% | 46.67% | 0.00% | 12.50 | 0.030 / 0.051 |
| `B2_NAIVE_RETRY` | Domain 2: DevSecOps Triage | 60 | **28.33%** [18.51, 40.77] | 14.00% [6.95, 26.19] | 66.67% | 43.33% | 0.00% | 12.50 | 0.030 / 0.056 |
| `B2_NAIVE_RETRY` | Domain 3: Cloud FinOps | 60 | **28.33%** [18.51, 40.77] | 14.00% [6.95, 26.19] | 66.67% | 43.33% | 0.00% | 12.50 | 0.025 / 0.041 |
| `B2_NAIVE_RETRY` | All Domains Combined | 180 | **27.22%** [21.25, 34.15] | 12.67% [8.26, 18.94] | 67.78% | 44.44% | 0.00% | 12.50 | 0.028 / 0.050 |
| `B3_CONTRACT_ONLY` | Domain 1: AIOps Remediation | 60 | **33.33%** [22.73, 45.94] | 20.00% [11.24, 33.04] | 16.67% | 0.00% | 66.67% | 0.00 | 0.141 / 0.215 |
| `B3_CONTRACT_ONLY` | Domain 2: DevSecOps Triage | 60 | **33.33%** [22.73, 45.94] | 20.00% [11.24, 33.04] | 16.67% | 0.00% | 66.67% | 0.00 | 0.129 / 0.213 |
| `B3_CONTRACT_ONLY` | Domain 3: Cloud FinOps | 60 | **33.33%** [22.73, 45.94] | 20.00% [11.24, 33.04] | 16.67% | 0.00% | 66.67% | 0.00 | 0.157 / 0.207 |
| `B3_CONTRACT_ONLY` | All Domains Combined | 180 | **33.33%** [26.86, 40.50] | 20.00% [14.38, 27.11] | 16.67% | 0.00% | 66.67% | 0.00 | 0.147 / 0.212 |
| `FLOWGUARD_FULL` | Domain 1: AIOps Remediation | 60 | **91.67%** [81.93, 96.39] | 90.00% [78.64, 95.65] | 0.00% | 0.00% | 25.00% | 90.33 | 0.659 / 1.552 |
| `FLOWGUARD_FULL` | Domain 2: DevSecOps Triage | 60 | **90.00%** [79.85, 95.34] | 88.00% [76.20, 94.38] | 0.00% | 0.00% | 26.67% | 103.17 | 0.626 / 1.379 |
| `FLOWGUARD_FULL` | Domain 3: Cloud FinOps | 60 | **93.33%** [84.07, 97.38] | 92.00% [81.16, 96.85] | 0.00% | 0.00% | 23.33% | 76.25 | 0.770 / 1.637 |
| `FLOWGUARD_FULL` | All Domains Combined | 180 | **91.67%** [86.71, 94.89] | 90.00% [84.16, 93.85] | 0.00% | 0.00% | 25.00% | 89.92 | 0.696 / 1.491 |

---

## 4. Five-Way Ablation Study (900 Executions)

To prove that no single mechanism is redundant, we execute a **900-run ablation study** ($180 \text{ scenarios} \times 5 \text{ configurations}$):

| Ablation Configuration | Scope | SVSR % [95% Wilson CI] | Recovery Rate % | Unsafe Side-Effect % | Contract Escape % | Human Escalation % | Mean Tokens/Run |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `full_flowguard` | All Domains (N=180) | **91.67%** [86.71, 94.89] | 90.00% | 0.00% | 0.00% | 25.00% | 89.92 |
| `no_tier1_drift_normalizer` | All Domains (N=180) | **81.67%** [75.37, 86.64] | 78.00% | 0.00% | 0.00% | 35.00% | 173.86 |
| `no_tier2_repair` | All Domains (N=180) | **75.00%** [68.20, 80.76] | 70.00% | 0.00% | 0.00% | 41.67% | 0.00 |
| `no_idempotency_reconciliation` | All Domains (N=180) | **85.00%** [79.06, 89.48] | 82.00% | 6.67% | 0.00% | 25.00% | 89.92 |
| `no_deterministic_policy_guard` | All Domains (N=180) | **78.89%** [72.36, 84.22] | 74.67% | 12.78% | 12.78% | 16.67% | 79.89 |

### Key Ablation Findings
1. **Removing Tier-1 Symbolic Drift Normalization (`no_tier1_drift_normalizer`):** SVSR drops from **91.67%** to **81.67%**, while average token consumption nearly doubles from **89.92** to **173.86 tokens/run** (+93.3% token overhead) because simple alias renames and string-to-scalar coercions are forced into Tier-2 LLM repair turns.
2. **Removing Tier-2 Bounded Repair (`no_tier2_repair`):** SVSR drops from **91.67%** to **75.00%**, and the Human Escalation Rate increases from **25.00%** to **41.67%** because cross-field semantic violations (`F2`) and markdown-wrapped JSON fences cannot be repaired by Tier-1 alias mapping alone.
3. **Removing Post-Commit Timeout Reconciliation (`no_idempotency_reconciliation`):** SVSR drops from **91.67%** to **85.00%**, and the **Unsafe Side-Effect Rate rises from 0.00% to 6.67%** (12/180 runs) because all 12 `F4_POST_COMMIT_TIMEOUT` scenarios suffer duplicate state mutations when retried blindly without `reconcile_read`.
4. **Removing the Deterministic Policy Guard (`no_deterministic_policy_guard`):** Relying solely on the regex taint detector allows subtle semantic injections (which avoid keywords like `"ignore previous instructions"`) and LLM context-spoofing faults to escape into the sink, causing a **12.78% Unsafe Side-Effect Rate** (23/180 runs) and a **12.78% Contract Escape Rate**.

---

## 5. Experiment B: Live Local GPU Evaluation with `llama3:latest` (30 Runs)

To evaluate FlowGuard under genuine stochastic LLM generation, Experiment B runs **15 live scenarios** (5 per domain) across `B2_NAIVE_RETRY` and `FLOWGUARD_FULL` ($15 \times 2 = 30$ live GPU runs) against local `llama3:latest` (digest `365c0bd3c000a25d25ddbf732fe1c6add414de7275464c4e4d1c3b5fcb5d8ad1`, 8.0B parameters, Q4_0, `temperature=0.0`) on an NVIDIA GeForce RTX 2050 GPU.

| Live Strategy | Domain | Runs | SVSR % [95% Wilson CI] | Unsafe Side-Effect % | Contract Escape % | Human Escalation % | Mean Tokens | GPU Latency p50 / p95 (ms) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `B2_NAIVE_RETRY` | D1: AIOps (N=5) | 5 | **20.00%** [3.62, 62.45] | 80.00% | 60.00% | 0.00% | 201.6 | 13998.3 / 15775.0 |
| `B2_NAIVE_RETRY` | D2: DevSecOps (N=5) | 5 | **20.00%** [3.62, 62.45] | 80.00% | 60.00% | 0.00% | 211.6 | 15126.8 / 16296.9 |
| `B2_NAIVE_RETRY` | D3: FinOps (N=5) | 5 | **20.00%** [3.62, 62.45] | 60.00% | 80.00% | 0.00% | 229.8 | 19106.3 / 20195.3 |
| `B2_NAIVE_RETRY` | All Domains Combined (N=15) | 15 | **20.00%** [7.05, 45.19] | 73.33% | 66.67% | 0.00% | 214.3 | 15126.8 / 20028.6 |
| `FLOWGUARD_FULL` | D1: AIOps (N=5) | 5 | **100.00%** [56.55, 100.00] | 0.00% | 0.00% | 20.00% | 355.6 | 14615.2 / 43646.9 |
| `FLOWGUARD_FULL` | D2: DevSecOps (N=5) | 5 | **100.00%** [56.55, 100.00] | 0.00% | 0.00% | 20.00% | 364.2 | 15984.2 / 46501.1 |
| `FLOWGUARD_FULL` | D3: FinOps (N=5) | 5 | **80.00%** [37.55, 96.38] | 0.00% | 0.00% | 40.00% | 667.6 | 19106.8 / 82141.0 |
| `FLOWGUARD_FULL` | All Domains Combined (N=15) | 15 | **93.33%** [70.18, 98.81] | 0.00% | 0.00% | 26.67% | 462.5 | 16065.7 / 67130.9 |

### Complete 30-Run Live GPU Trajectory Log (`results/experiment_b_live_results.json`)

| Scenario ID | Strategy | Fault Class | SVSR | Unsafe SE | Terminal State | Tokens | GPU Latency (ms) |
| :--- | :--- | :--- | :---: | :---: | :--- | :---: | :---: |


---

## 6. Security Hardening & Adversarial Audit Matrix (46 Automated `pytest` Tests)

FlowGuard includes a 20-test adversarial security hardening suite (`tests/test_security_hardening.py`, part of the 46-test `pytest` suite):
1. **Post-Commit Timeout Reconciliation (`test_01`, `test_02`, `test_20`):** Verifies `AMBIGUOUS_REQUIRES_RECONCILIATION -> COMMITTED` via `reconcile_read`, safe halt when `reconcile_read` is unavailable, and strict per-key isolation across distinct `idem_key` values on the same entity.
2. **Thread-Safe SQLite WAL Concurrency (`test_03`):** 10 concurrent threads firing identical webhook deliveries; exactly 1 sink mutation occurs (`mutation_count == 1`).
3. **Subtle Prompt Injection Bypassing Taint Regex (`test_04`, `test_05`, `test_06`):** Verifies that polite, keyword-free adversarial notes (`TaintSignal.detected == False`) attempting unauthorized `prod-stateful-db` rollbacks, `CVSS 9.8` merges, or FinOps budget breaches are 100% blocked by `PolicyGuard`.
4. **Constant-Time Token Verification & Anti-Spoofing (`test_07`, `test_08`):** Rejects forged approval tokens using `hmac.compare_digest` and blocks LLM namespace spoofing.
5. **Anti-SSRF URL Validation (`test_09`):** Blocks `file://`, `ftp://`, `gopher://`, cloud metadata IPs (`169.254.169.254`, `metadata.google.internal`), and non-allowlisted hosts.
6. **CWE-22 Path Traversal Prevention (`test_10`):** Enforces `Path.resolve().is_relative_to(base_dir)` against `../`, URL-encoded `%2e%2e%2f`, backslash, and null-byte payloads.
7. **HTTP Sidecar Hardening & Mandatory Pre-Execution Gating (`test_11`–`test_14`, `test_18`):** Enforces `CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, 1 MB body cap (`HTTP 413`), HTML escaping, and mandatory `ContractValidator` (`HTTP 422`) + `PolicyGuard` (`HTTP 403`) + `IdempotencyPayloadMismatchError` (`HTTP 409`) checks on `POST /api/v1/idempotent-execute`.
8. **MCP JSON-RPC 2.0 Fuzzing & 2 MB Cap (`test_15`)** and **Linear-Time $O(N)$ `raw_decode` Extraction (`test_19`)** preventing quadratic regex backtracking (ReDoS).

---

## 7. Observed Failure Cases, Limitations & Threats to Validity

1. **Unrecoverable Multi-Field Schema Drift & Severe Truncation (15/180 Runs in Exp. A; 1/15 in Exp. B):** FlowGuard does not claim 100% recovery. In Experiment A, 15 scenarios (8.33% of all runs; 10.00% of fault-injected runs) fail recovery and transition cleanly to `SAFE_ESCALATION_HALT`: 3 persistent HTTP 503 outages exceeding the retry budget, 6 catastrophic unknown schema drifts (3+ unmapped proprietary keys), and 6 severely truncated JSON streams cut off mid-token. In Experiment B, `LIVE-FINOPS-04` (unmapped proprietary keys `{"cloud_ticket": ..., "gpu_cards_wanted": ...}`) similarly escalates to a human operator (`SVSR = 93.33%`, 14/15 scenarios).
2. **Dependency on Downstream Read Endpoints for Timeout Reconciliation:** Transitioning out of `AMBIGUOUS_REQUIRES_RECONCILIATION` after a post-commit HTTP timeout requires the downstream sink to expose a query/read endpoint (`reconcile_fn`). For write-only webhooks lacking state inspection APIs, FlowGuard cannot automatically confirm whether the timed-out mutation took effect and must halt for human reconciliation.
3. **Threats to Validity:**
   - *Internal Validity:* Experiment A uses deterministic fault schedules and predicate-guided repair traces to enable exact 720-run and 900-run ablation comparisons; Experiment B complements this with live GPU inference (`llama3:latest`), though on a smaller sample ($N = 30$ runs) due to local GPU latency (`p50 = 16.07 s`).
   - *External Validity:* The downstream sinks (`stateful_simulated_sink`) are local stateful emulators of Kubernetes, GitHub/Trivy gates, and cloud FinOps ledgers rather than distributed multi-region production clusters.
   - *Construct Validity:* Heuristic taint detection (`TaintSignal`) has limited recall against novel semantic paraphrases, which is why FlowGuard never uses taint detection as an authoritative security gate.
