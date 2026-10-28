"""Hardened Local Web Dashboard & Sidecar Verification Server (`flowguard ui --port 8090`).

Implements strict security controls:
  - `MAX_POST_BODY_BYTES = 1 * 1024 * 1024` (1 MB) -> HTTP 413 Payload Too Large
  - Malformed/negative `Content-Length` -> HTTP 400 Bad Request
  - Path traversal prevention (CWE-22) via `Path.resolve().is_relative_to(...)`
  - Mandatory security headers: `Content-Security-Policy`, `X-Frame-Options: DENY`,
    `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`
  - Server-side `escape_html` and client-side `escapeHtml`
"""

from __future__ import annotations

import html
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from flowguard.contracts import ContractValidator
from flowguard.idempotency import IdempotencyLedger, IdempotencyPayloadMismatchError
from flowguard.models import DomainName
from flowguard.policy_guard import PolicyGuard
from flowguard.recovery import RecoveryController
from flowguard.sinks import BaseStatefulSimulatedSink, create_sink_for_domain

MAX_POST_BODY_BYTES: int = 1 * 1024 * 1024  # 1 MB hard cap

SECURITY_HEADERS: Dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def escape_html(raw: Any) -> str:
    """Server-side HTML escaping preventing XSS."""
    return html.escape(str(raw), quote=True)


def resolve_safe_artifact_path(base_dir: Path, requested_rel_path: str) -> Path:
    """Resolve `requested_rel_path` strictly inside `base_dir` (CWE-22 protection)."""
    if not isinstance(requested_rel_path, str) or not requested_rel_path.strip():
        raise PermissionError("CWE22_PATH_TRAVERSAL_BLOCKED: Empty artifact path")
    unquoted = urllib.parse.unquote(requested_rel_path).lstrip("/")
    if "\x00" in unquoted or "\\" in unquoted or ".." in Path(unquoted).parts:
        raise PermissionError(
            f"CWE22_PATH_TRAVERSAL_BLOCKED: Illegal traversal segment in '{requested_rel_path}'"
        )
    root_resolved = base_dir.resolve()
    candidate = (root_resolved / unquoted).resolve()
    if not candidate.is_relative_to(root_resolved) or candidate == root_resolved:
        raise PermissionError(
            f"CWE22_PATH_TRAVERSAL_BLOCKED: Path '{requested_rel_path}' escapes '{root_resolved}'"
        )
    return candidate


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>FlowGuard Runtime Verification &amp; Idempotency Dashboard</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; margin: 2rem; background: #0f172a; color: #f8fafc; }
    h1, h2 { color: #38bdf8; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.25rem; }
    pre { background: #020617; padding: 0.9rem; border-radius: 6px; overflow-x: auto; color: #e2e8f0; }
    .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; background: #0284c7; color: #fff; font-size: 0.85rem; }
  </style>
</head>
<body>
  <h1>FlowGuard: Contract-Aware Runtime Verification &amp; 4-State Idempotency</h1>
  <div class="card">
    <span class="badge">deterministic_harness</span>
    <span class="badge">stateful_simulated_sink</span>
    <span class="badge">live_llm_inference (llama3:latest)</span>
    <span class="badge">exportable_n8n_workflow_json</span>
    <p>Author: Iyed Mohamed (ORCID: 0009-0008-9493-7510, ESPRIT School of Engineering)</p>
  </div>
  <div class="card">
    <h2>Live Verification Playground</h2>
    <pre id="status-box">Ready.</pre>
  </div>
  <script>
    function escapeHtml(unsafe) {
      return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }
    fetch('/api/v1/health')
      .then(r => r.json())
      .then(d => {
        document.getElementById('status-box').innerHTML = escapeHtml(JSON.stringify(d, null, 2));
      });
  </script>
</body>
</html>
"""


class FlowGuardAppState:
    """Shared thread-safe state for the sidecar verification HTTP server."""

    def __init__(self, results_dir: Optional[Path] = None) -> None:
        self.results_dir = (
            Path(results_dir)
            if results_dir is not None
            else Path(__file__).resolve().parent.parent / "results"
        )
        self.validator = ContractValidator()
        self.policy_guard = PolicyGuard()
        self.recovery = RecoveryController(validator=self.validator, max_repair_turns=2)
        self.ledger = IdempotencyLedger()
        self.sinks: Dict[str, BaseStatefulSimulatedSink] = {
            d.value: create_sink_for_domain(d.value) for d in DomainName
        }


def make_handler_class(app_state: FlowGuardAppState):
    class FlowGuardHTTPHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return  # Quiet structured test logs

        def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for hk, hv in SECURITY_HEADERS.items():
                self.send_header(hk, hv)
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, status_code: int, html_text: str) -> None:
            body = html_text.encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for hk, hv in SECURITY_HEADERS.items():
                self.send_header(hk, hv)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed_url = urllib.parse.urlparse(self.path)
            route = parsed_url.path

            if route == "/" or route == "/index.html":
                self._send_html(200, DASHBOARD_HTML)
                return

            if route == "/api/v1/health":
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "service": "flowguard-sidecar",
                        "version": "0.1.0",
                        "supported_domains": [d.value for d in DomainName],
                    },
                )
                return

            if route == "/api/v1/benchmark-summary":
                bench_file = app_state.results_dir / "experiment_a_benchmark_results.json"
                if not bench_file.exists():
                    self._send_json(404, {"error": "Benchmark summary not generated yet"})
                    return
                data = json.loads(bench_file.read_text(encoding="utf-8"))
                self._send_json(
                    200,
                    {
                        "epistemic_metadata": data.get("epistemic_metadata"),
                        "summary": data.get("summary"),
                    },
                )
                return

            if route.startswith("/api/v1/artifacts/"):
                rel = route[len("/api/v1/artifacts/") :]
                try:
                    safe_path = resolve_safe_artifact_path(app_state.results_dir, rel)
                except PermissionError as exc:
                    self._send_json(403, {"error": str(exc)})
                    return
                if not safe_path.exists() or not safe_path.is_file():
                    self._send_json(404, {"error": "Artifact not found"})
                    return
                self._send_json(
                    200,
                    {
                        "artifact": safe_path.name,
                        "size_bytes": safe_path.stat().st_size,
                    },
                )
                return

            self._send_json(404, {"error": f"Route not found: {escape_html(route)}"})

        def do_POST(self) -> None:
            raw_cl = self.headers.get("Content-Length")
            if raw_cl is None:
                self._send_json(400, {"error": "Missing Content-Length header"})
                return
            try:
                content_length = int(raw_cl)
            except ValueError:
                self._send_json(400, {"error": "Invalid Content-Length header"})
                return

            if content_length < 0:
                self._send_json(400, {"error": "Negative Content-Length is invalid"})
                return

            if content_length > MAX_POST_BODY_BYTES:
                self._send_json(
                    413,
                    {
                        "error": f"Payload Too Large: {content_length} exceeds MAX_POST_BODY_BYTES ({MAX_POST_BODY_BYTES})"
                    },
                )
                return

            raw_body = self.rfile.read(content_length)
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._send_json(400, {"error": f"Malformed JSON body: {exc}"})
                return

            if not isinstance(body, dict):
                self._send_json(400, {"error": "JSON body must be an object"})
                return

            parsed_url = urllib.parse.urlparse(self.path)
            route = parsed_url.path

            if route == "/api/v1/verify-and-recover":
                domain = body.get("domain")
                if not isinstance(domain, str) or domain not in app_state.sinks:
                    self._send_json(400, {"error": "Invalid or unsupported domain"})
                    return
                context = body.get("context", {})
                if not isinstance(context, dict):
                    self._send_json(400, {"error": "'context' must be an object"})
                    return
                raw_payload = body.get("raw_payload")
                rec_res = app_state.recovery.recover(
                    domain=domain, raw_payload=raw_payload, context=context
                )
                pol_res = None
                if rec_res.recovered and rec_res.final_payload is not None:
                    pol_res = app_state.policy_guard.evaluate(
                        domain=domain,
                        payload=rec_res.final_payload,
                        context=context,
                    )
                self._send_json(
                    200,
                    {
                        "recovery": rec_res.to_dict(),
                        "policy": pol_res.to_dict() if pol_res is not None else None,
                        "final_verdict": rec_res.final_verdict.value,
                        "final_payload": rec_res.final_payload,
                    },
                )
                return

            if route == "/api/v1/idempotent-execute":
                domain = body.get("domain")
                entity_id = body.get("entity_id")
                operation = body.get("operation", "execute")
                payload = body.get("payload")
                context = body.get("context", {})
                idem_key = body.get("idem_key")
                if (
                    not isinstance(domain, str)
                    or domain not in app_state.sinks
                    or not isinstance(entity_id, str)
                    or not isinstance(payload, dict)
                ):
                    self._send_json(
                        400,
                        {"error": "Requires valid domain, entity_id, and payload object"},
                    )
                    return

                ctx_dict = context if isinstance(context, dict) else {}
                val_res = app_state.validator.validate(
                    domain=domain, payload=payload, context=ctx_dict
                )
                if not val_res.is_valid:
                    self._send_json(
                        422,
                        {
                            "error": "Contract validation failed prior to idempotent execution",
                            "verdict": val_res.verdict.value,
                            "violations": val_res.violations,
                        },
                    )
                    return

                pol_res = app_state.policy_guard.evaluate(
                    domain=domain, payload=payload, context=ctx_dict
                )
                if not pol_res.allowed:
                    self._send_json(
                        403,
                        {
                            "error": "PolicyGuard blocked unsafe side-effect prior to execution",
                            "violations": pol_res.violations,
                        },
                    )
                    return

                sink = app_state.sinks[domain]
                try:
                    receipt = app_state.ledger.execute_through_proxy(
                        workflow_id=str(body.get("workflow_id", f"wf-{domain}")),
                        domain=domain,
                        entity_id=entity_id,
                        operation=str(operation),
                        payload=payload,
                        mutate_fn=lambda k: sink.apply_mutation(
                            entity_id, payload, ctx_dict, k
                        ),
                        reconcile_fn=sink.reconcile_read,
                        idem_key=idem_key if isinstance(idem_key, str) else None,
                    )
                except IdempotencyPayloadMismatchError as exc:
                    self._send_json(409, {"error": str(exc)})
                    return
                self._send_json(200, receipt.to_dict())
                return

            self._send_json(404, {"error": f"Unknown POST route: {escape_html(route)}"})

    return FlowGuardHTTPHandler


def create_http_server(
    host: str = "127.0.0.1",
    port: int = 8090,
    results_dir: Optional[Path] = None,
) -> Tuple[ThreadingHTTPServer, FlowGuardAppState]:
    state = FlowGuardAppState(results_dir=results_dir)
    handler_cls = make_handler_class(state)
    server = ThreadingHTTPServer((host, port), handler_cls)
    return server, state
