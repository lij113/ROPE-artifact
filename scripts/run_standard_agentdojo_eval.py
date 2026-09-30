#!/usr/bin/env python3
"""Run standard AgentDojo validation for ROPE."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.standard_agentdojo_eval import run_standard_agentdojo_eval  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default="agentdojo_standard_v1")
    parser.add_argument("--stage", choices=("smoke", "main"), default="smoke")
    parser.add_argument(
        "--routes",
        default="glm,minimax,ollama-4090,gpt-api,claude-api,deepseek-api",
        help="comma-separated route ids to include",
    )
    parser.add_argument("--no-force", action="store_true")
    args = parser.parse_args()
    route_ids = [item.strip() for item in args.routes.split(",") if item.strip()]
    summary = run_standard_agentdojo_eval(
        ROOT,
        run_id=args.run_id,
        stage=args.stage,
        route_ids=route_ids,
        force=not args.no_force,
    )
    print(
        "standard AgentDojo validation completed: "
        f"routes={summary['completed_route_count']}/{summary['attempted_route_count']}, "
        f"rows={summary['row_count']}, "
        f"base_asr={summary['agentdojo_asr']:.3f}, "
        f"rope_security={summary['rope_security']:.3f}"
    )


if __name__ == "__main__":
    main()
