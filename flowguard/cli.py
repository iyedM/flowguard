"""Command-Line Interface (`flowguard`) for Benchmark, Live GPU Eval, MCP Server, and UI."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from flowguard.benchmark import BenchmarkRunner
from flowguard.llm_provider import LiveExperimentRunner
from flowguard.mcp_server import FlowGuardMCPServer
from flowguard.ui_server import create_http_server


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="flowguard",
        description="FlowGuard: Contract-Aware Runtime Verification, Bounded Recovery & Side-Effect Idempotency for Agentic n8n Workflows",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "benchmark",
        help="Run the 720-execution multi-domain controlled benchmark and 900-execution 5-way ablation study",
    )
    sub.add_parser(
        "live-eval",
        help="Run Experiment B live evaluation against local Ollama llama3:latest on GPU",
    )
    sub.add_parser(
        "mcp-serve",
        help="Start the JSON-RPC 2.0 Model Context Protocol (MCP) server over stdio",
    )

    ui_parser = sub.add_parser(
        "ui",
        help="Start the hardened local FlowGuard Web Dashboard and sidecar verification server",
    )
    ui_parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    ui_parser.add_argument("--port", type=int, default=8090, help="Bind port (default: 8090)")

    args = parser.parse_args(argv)

    if args.command == "benchmark":
        runner = BenchmarkRunner()
        res = runner.run_full_benchmark_and_ablation()
        fg = res["benchmark"]["summary"]["FLOWGUARD_FULL"]["all_domains_combined"]
        print(
            json.dumps(
                {
                    "status": "completed",
                    "total_benchmark_runs": res["benchmark"]["epistemic_metadata"][
                        "total_recorded_executions"
                    ],
                    "total_ablation_runs": res["ablation"]["epistemic_metadata"][
                        "total_ablation_executions"
                    ],
                    "flowguard_full_combined_svsr_pct": fg["svsr_pct"],
                    "flowguard_full_combined_recovery_rate_pct": fg["recovery_rate_pct"],
                },
                indent=2,
            )
        )
        return 0

    if args.command == "live-eval":
        runner = LiveExperimentRunner()
        res = runner.run_experiment_b()
        fg = res["summary"]["FLOWGUARD_FULL"]["all_domains_combined"]
        print(
            json.dumps(
                {
                    "status": "completed",
                    "model": res["epistemic_metadata"]["model_metadata"].get("name"),
                    "total_evaluated_runs": res["epistemic_metadata"]["total_evaluated_runs"],
                    "flowguard_full_live_svsr_pct": fg["svsr_pct"],
                },
                indent=2,
            )
        )
        return 0

    if args.command == "mcp-serve":
        server = FlowGuardMCPServer()
        server.serve_stdio()
        return 0

    if args.command == "ui":
        server, _state = create_http_server(host=args.host, port=args.port)
        print(f"FlowGuard UI & Sidecar Verification Server listening on http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
