#!/usr/bin/env python3
"""Drive the in-loop ROPE-vs-base AgentDojo evaluation across suites and routes.

This is the headline external-validity experiment: ROPE is enforced inside the
live AgentDojo pipeline and scored by AgentDojo's own utility/security oracles.

Usage:
    python3 scripts/run_agentdojo_inloop.py \
        --suites workspace,travel --routes glm,gpt-api \
        --run-id inloop_main_v1
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT))

from rope_bench.agentdojo_inloop_eval import run_suite  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suites", default="workspace,travel")
    parser.add_argument("--routes", default="glm")
    parser.add_argument("--systems", default="base,rope")
    parser.add_argument("--run-id", default="inloop_main_v1")
    parser.add_argument("--attack", default="important_instructions_no_model_name")
    parser.add_argument("--user-task-limit", type=int, default=None)
    parser.add_argument("--injection-task-limit", type=int, default=None)
    parser.add_argument("--batch-timeout-seconds", type=int, default=1800)
    parser.add_argument("--no-hard-batch-timeout", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--no-benign", action="store_true")
    args = parser.parse_args()

    suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    routes = [r.strip() for r in args.routes.split(",") if r.strip()]
    systems = tuple(s.strip() for s in args.systems.split(",") if s.strip())

    all_summaries = []
    for route_id in routes:
        for suite_name in suites:
            print(f"=== route={route_id} suite={suite_name} ===", flush=True)
            try:
                summary = run_suite(
                    ROOT,
                    suite_name=suite_name,
                    route_id=route_id,
                    systems=systems,
                    run_id=args.run_id,
                    include_benign=not args.no_benign,
                    user_task_limit=args.user_task_limit,
                    injection_task_limit=args.injection_task_limit,
                    attack_name=args.attack,
                    batch_timeout_seconds=args.batch_timeout_seconds,
                    hard_batch_timeout=not args.no_hard_batch_timeout,
                    resume=args.resume,
                )
            except Exception as exc:  # noqa: BLE001
                summary = {
                    "suite": suite_name,
                    "route": route_id,
                    "fatal_error": f"{type(exc).__name__}: {str(exc)[:300]}",
                }
            all_summaries.append(summary)
            print(json.dumps(summary, indent=2, sort_keys=True), flush=True)

    out_dir = ROOT / "bench" / "results" / "agentdojo_inloop" / args.run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    summaries_path = out_dir / "all_summaries.json"
    if args.resume and summaries_path.exists():
        try:
            existing = json.loads(summaries_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = []
        merged = {
            (row.get("route"), row.get("suite")): row
            for row in existing
            if isinstance(row, dict)
        }
        for summary_path in sorted(out_dir.glob("summary_*.json")):
            if summary_path.name == "summary_aggregate.json":
                continue
            try:
                row = json.loads(summary_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and row.get("route") and row.get("suite"):
                merged[(row.get("route"), row.get("suite"))] = row
        for row in all_summaries:
            merged[(row.get("route"), row.get("suite"))] = row
        all_summaries = list(merged.values())
    summaries_path.write_text(
        json.dumps(all_summaries, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {summaries_path}", flush=True)


if __name__ == "__main__":
    main()
