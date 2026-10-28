"""Model Context Protocol (MCP) JSON-RPC 2.0 Server over stdio (`flowguard mcp-serve`).

Implements strict JSON-RPC 2.0 validation:
  - Line size cap: `MAX_JSONRPC_LINE_BYTES = 2 * 1024 * 1024` (2 MB)
  - `-32700`: Parse error
  - `-32600`: Invalid Request
  - `-32601`: Method not found
  - `-32602`: Invalid params
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, IO, Optional

from flowguard.contracts import ContractValidator
from flowguard.idempotency import IdempotencyLedger
from flowguard.models import DomainName
from flowguard.policy_guard import PolicyGuard
from flowguard.recovery import RecoveryController

MAX_JSONRPC_LINE_BYTES: int = 2 * 1024 * 1024  # 2 MB hard cap

SUPPORTED_DOMAINS = {d.value for d in DomainName}


class FlowGuardMCPServer:
    """JSON-RPC 2.0 MCP Server exposing FlowGuard verification, recovery, and policy tools."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.validator = ContractValidator()
        self.policy_guard = PolicyGuard()
        self.recovery = RecoveryController(validator=self.validator, max_repair_turns=2)
        self.ledger = IdempotencyLedger(db_path=db_path)

    @staticmethod
    def _error_response(
        req_id: Any,
        code: int,
        message: str,
        data: Optional[Any] = None,
    ) -> Dict[str, Any]:
        err: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": err,
        }

    @staticmethod
    def _success_response(req_id: Any, result: Any) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }

    def handle_raw_line(self, raw_line: bytes | str) -> Dict[str, Any]:
        """Validate and process a single JSON-RPC 2.0 request line."""
        raw_bytes = (
            raw_line.encode("utf-8", errors="replace")
            if isinstance(raw_line, str)
            else raw_line
        )
        if len(raw_bytes) > MAX_JSONRPC_LINE_BYTES:
            return self._error_response(
                None,
                -32600,
                f"Invalid Request: JSON-RPC payload exceeds MAX_JSONRPC_LINE_BYTES ({MAX_JSONRPC_LINE_BYTES} bytes).",
            )

        try:
            text = raw_bytes.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            return self._error_response(None, -32700, f"Parse error: invalid UTF-8 ({exc})")

        if not text:
            return self._error_response(None, -32600, "Invalid Request: empty line")

        try:
            req = json.loads(text)
        except json.JSONDecodeError as exc:
            return self._error_response(None, -32700, f"Parse error: {exc.msg}")

        if not isinstance(req, dict):
            return self._error_response(
                None, -32600, "Invalid Request: top-level JSON value must be an object"
            )

        req_id = req.get("id")
        if req.get("jsonrpc") != "2.0":
            return self._error_response(
                req_id, -32600, "Invalid Request: missing or invalid 'jsonrpc' == '2.0'"
            )

        method = req.get("method")
        if not isinstance(method, str) or not method.strip():
            return self._error_response(
                req_id, -32600, "Invalid Request: 'method' must be a non-empty string"
            )

        params = req.get("params", {})
        if params is not None and not isinstance(params, dict):
            return self._error_response(
                req_id, -32602, "Invalid params: 'params' must be a JSON object"
            )
        params = params or {}

        return self._dispatch_method(req_id, method, params)

    def _dispatch_method(
        self,
        req_id: Any,
        method: str,
        params: Dict[str, Any],
    ) -> Dict[str, Any]:
        if method == "initialize":
            return self._success_response(
                req_id,
                {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "flowguard-mcp", "version": "0.1.0"},
                    "capabilities": {"tools": {}},
                },
            )

        if method == "tools/list":
            return self._success_response(
                req_id,
                {
                    "tools": [
                        {
                            "name": "flowguard_verify_contract",
                            "description": "Validate agent payload against JSON Schema Draft 2020-12 and domain cross-field invariants.",
                            "inputSchema": {
                                "type": "object",
                                "required": ["domain", "payload"],
                                "properties": {
                                    "domain": {"type": "string", "enum": sorted(SUPPORTED_DOMAINS)},
                                    "payload": {"type": "object"},
                                    "context": {"type": "object"},
                                },
                            },
                        },
                        {
                            "name": "flowguard_recover_payload",
                            "description": "Run Two-Tier Bounded Recovery (Tier-1 symbolic drift normalizer + Tier-2 bounded repair).",
                            "inputSchema": {
                                "type": "object",
                                "required": ["domain", "raw_payload"],
                                "properties": {
                                    "domain": {"type": "string", "enum": sorted(SUPPORTED_DOMAINS)},
                                    "raw_payload": {},
                                    "context": {"type": "object"},
                                },
                            },
                        },
                        {
                            "name": "flowguard_audit_policy",
                            "description": "Evaluate deterministic security policy invariants and fallible untrusted taint signals.",
                            "inputSchema": {
                                "type": "object",
                                "required": ["domain", "payload", "context"],
                                "properties": {
                                    "domain": {"type": "string", "enum": sorted(SUPPORTED_DOMAINS)},
                                    "payload": {"type": "object"},
                                    "context": {"type": "object"},
                                },
                            },
                        },
                    ]
                },
            )

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments")
            if not isinstance(tool_name, str) or not isinstance(arguments, dict):
                return self._error_response(
                    req_id,
                    -32602,
                    "Invalid params: 'tools/call' requires string 'name' and object 'arguments'",
                )
            return self._call_tool(req_id, tool_name, arguments)

        return self._error_response(
            req_id, -32601, f"Method not found: '{method}'"
        )

    def _call_tool(
        self,
        req_id: Any,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        domain = arguments.get("domain")
        if not isinstance(domain, str) or domain not in SUPPORTED_DOMAINS:
            return self._error_response(
                req_id,
                -32602,
                f"Invalid params: 'domain' must be one of {sorted(SUPPORTED_DOMAINS)}",
            )

        context = arguments.get("context", {})
        if not isinstance(context, dict):
            return self._error_response(
                req_id, -32602, "Invalid params: 'context' must be an object"
            )

        if tool_name == "flowguard_verify_contract":
            if "payload" not in arguments or not isinstance(arguments["payload"], dict):
                return self._error_response(
                    req_id, -32602, "Invalid params: 'payload' object is required"
                )
            res = self.validator.validate(
                domain=domain, payload=arguments["payload"], context=context
            )
            return self._success_response(req_id, res.to_dict())

        if tool_name == "flowguard_recover_payload":
            if "raw_payload" not in arguments:
                return self._error_response(
                    req_id, -32602, "Invalid params: 'raw_payload' is required"
                )
            res = self.recovery.recover(
                domain=domain, raw_payload=arguments["raw_payload"], context=context
            )
            return self._success_response(req_id, res.to_dict())

        if tool_name == "flowguard_audit_policy":
            if "payload" not in arguments or not isinstance(arguments["payload"], dict):
                return self._error_response(
                    req_id, -32602, "Invalid params: 'payload' object is required"
                )
            res = self.policy_guard.evaluate(
                domain=domain, payload=arguments["payload"], context=context
            )
            return self._success_response(req_id, res.to_dict())

        return self._error_response(
            req_id, -32601, f"Tool not found: '{tool_name}'"
        )

    def serve_stdio(
        self,
        in_stream: Optional[IO[bytes]] = None,
        out_stream: Optional[IO[str]] = None,
    ) -> None:
        """Read newline-delimited JSON-RPC messages from stdin and write responses to stdout."""
        reader = in_stream if in_stream is not None else sys.stdin.buffer
        writer = out_stream if out_stream is not None else sys.stdout

        while True:
            line = reader.readline(MAX_JSONRPC_LINE_BYTES + 1024)
            if not line:
                break
            resp = self.handle_raw_line(line)
            writer.write(json.dumps(resp, sort_keys=True) + "\n")
            writer.flush()
