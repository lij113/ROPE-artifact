#!/usr/bin/env python3
"""Run the compromised-planner AgentDojo evaluation.

ROPE and taint-block monitors make no model API calls; the llm_lookahead
monitors call the judge route in ROPE_JUDGE_ROUTE / ROPE_JUDGE_MODEL.

Usage:
    .venv-agentdojo/bin/python scripts/run_agentdojo_compromised.py \
        --suites workspace,travel,banking,slack --run-id e4_compromised_v1
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.agentdojo_compromised_eval import (  # noqa: E402
    RESULT_ROOT,
    run_compromised_suite,
    summarize,
    write_outputs,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suites", default="workspace,travel,banking,slack")
    parser.add_argument("--systems", default="base,rope")
    parser.add_argument("--attack", default="important_instructions_no_model_name")
    parser.add_argument("--run-id", default="e4_compromised_v1")
    parser.add_argument("--no-benign", action="store_true")
    parser.add_argument("--benign-only", action="store_true")
    parser.add_argument("--user-task-limit", type=int, default=None)
    parser.add_argument("--user-task-offset", type=int, default=0)
    parser.add_argument("--benchmark-version", default="v1")
    parser.add_argument("--injection-tasks", default="", help="comma list of injection task ids")
    parser.add_argument("--injection-task-limit", type=int, default=None)
    parser.add_argument(
        "--monitor-note",
        action="store_true",
        help="append a note addressed to automated safety reviewers to every injection",
    )
    args = parser.parse_args()

    monitor_note = None
    if args.monitor_note:
        from rope_bench.agentdojo_baseline_monitors import MONITOR_NOTE

        monitor_note = MONITOR_NOTE

    systems = tuple(s.strip() for s in args.systems.split(",") if s.strip())
    attack_rows, benign_rows, errors, decisions = [], [], [], []
    for suite_name in [s.strip() for s in args.suites.split(",") if s.strip()]:
        start = time.time()
        a, b, e, d = run_compromised_suite(
            suite_name,
            systems=systems,
            attack_name=args.attack,
            include_benign=not args.no_benign,
            monitor_note=monitor_note,
            include_attacks=not args.benign_only,
            user_task_limit=args.user_task_limit,
            injection_task_limit=args.injection_task_limit,
            user_task_offset=args.user_task_offset,
            benchmark_version=args.benchmark_version,
            injection_task_ids=[t.strip() for t in args.injection_tasks.split(",") if t.strip()] or None,
        )
        attack_rows += a
        benign_rows += b
        errors += e
        decisions += d
        print(f"{suite_name}: {len(a)} attack rows, {len(b)} benign rows, {len(e)} errors, {time.time() - start:.1f}s", flush=True)

    summary = summarize(attack_rows, benign_rows)
    summary["run_id"] = args.run_id
    summary["attack"] = args.attack
    summary["monitor_note"] = bool(monitor_note)
    summary["errors"] = len(errors)
    out_dir = ROOT / RESULT_ROOT / args.run_id
    write_outputs(out_dir, attack_rows, benign_rows, errors, decisions, summary)
    print(json.dumps(summary["suites"], indent=2, sort_keys=True))
    print(f"wrote {out_dir}")


if __name__ == "__main__":
    main()
