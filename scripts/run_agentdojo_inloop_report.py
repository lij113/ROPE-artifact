#!/usr/bin/env python3
"""Aggregate an AgentDojo in-loop run into paper tables."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.agentdojo_inloop_report import summarize_agentdojo_inloop_run  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default="inloop_main_v2")
    args = parser.parse_args()
    summary = summarize_agentdojo_inloop_run(ROOT, run_id=args.run_id)
    print(
        "AgentDojo in-loop report: "
        f"route_status={summary['status']}, "
        f"matched_status={summary['matched_status']}"
    )
    print(f"attack rows: {summary['attack_rows']}, benign rows: {summary['benign_rows']}")


if __name__ == "__main__":
    main()
