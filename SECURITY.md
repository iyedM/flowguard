# Security Policy & Architecture Guarantees (`FlowGuard`)

## Supported Versions

| Version | Supported |
| ------- | --------- |
| `0.1.x` | Yes       |

## Core Architectural Security Invariants

1. **Strict Separation of Security Boundary vs. Fallible Taint Detection**
   - **Hard Security Boundary (`flowguard/policy_guard.py`, `flowguard/contracts.py`):** Enforced deterministically via capability allowlists and authoritative context attributes (`namespace`, `human_approval_token`, `cvss_score`, `secret_detected`, `team_monthly_budget_cap_usd`, `environment`). An LLM output can never override an authoritative security invariant regardless of phrasing.
   - **Fallible Untrusted Taint Auditor (`TaintSignal.is_authoritative_boundary = False`):** Heuristic scanning of untrusted text fields (`recent_log_snippet`, `untrusted_pr_title_and_body`, `justification_notes`) is recorded strictly as an observability and OpenTelemetry diagnostic signal, never relied upon as the sole security barrier.

2. **4-State Transactional Idempotency & Post-Commit Timeout Reconciliation (`flowguard/idempotency.py`)**
   - Uses a thread-safe SQLite `WAL` ledger (`busy_timeout=5000`, `threading.RLock()`) tracking `PENDING_IN_FLIGHT`, `COMMITTED`, `FAILED_SAFE_TO_RETRY`, and `AMBIGUOUS_REQUIRES_RECONCILIATION`.
   - On post-commit HTTP timeouts, FlowGuard transitions to `AMBIGUOUS_REQUIRES_RECONCILIATION` and performs read-before-write state reconciliation (or halts safely if no read endpoint exists) to prevent duplicate destructive side effects.

3. **Interface & Transport Hardening**
   - **Anti-SSRF (`flowguard/llm_provider.py`):** Restricts inference endpoints to `http`/`https` schemes and an explicit local host allowlist (`127.0.0.1`, `localhost`, `::1`, `host.docker.internal`), blocking `file://`, `ftp://`, `gopher://`, and cloud metadata IP `169.254.169.254`.
   - **Path Traversal Prevention (`CWE-22`, `flowguard/ui_server.py`):** Resolves artifact paths via `Path.resolve().is_relative_to(allowed_root)` and rejects `..`, backslashes, and null bytes with `HTTP 403`.
   - **HTTP & MCP Resource Caps:** Enforces `MAX_POST_BODY_BYTES = 1 MB` (`HTTP 413`) on the Web UI/Sidecar server with mandatory `CSP`, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff` headers, and `MAX_JSONRPC_LINE_BYTES = 2 MB` on the `stdio` MCP server.

## Reporting a Vulnerability

Please report security issues via GitHub Security Advisories on `https://github.com/iyedM/flowguard/security/advisories` or contact Iyed Mohamed (`iyed.mohamed0103@gmail.com`).
