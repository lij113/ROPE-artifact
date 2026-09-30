#!/usr/bin/env python3
"""Run targeted AgentDojo in-loop cells with immediate per-cell flushing."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.agentdojo_inloop_eval import (  # noqa: E402
    RESULT_ROOT,
    _drop_attack_batch_rows,
    _drop_batch_errors,
    _read_csv,
    _run_agentdojo_batch,
    _write_csv,
)
from rope_bench.standard_agentdojo_eval import _available_routes  # noqa: E402


def _items(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _summarize(rows: list[dict[str, Any]], errors: list[dict[str, Any]]) -> dict[str, Any]:
    systems = sorted({row["system"] for row in rows} | {row.get("system", "") for row in errors})
    out: dict[str, Any] = {"systems": {}, "errors": len(errors), "attack_rows": len(rows)}
    for system in systems:
        if not system:
            continue
        scoped = [row for row in rows if row["system"] == system]
        entry: dict[str, Any] = {"attack_cases": len(scoped)}
        if scoped:
            entry["asr"] = round(sum(int(row["attack_success"]) for row in scoped) / len(scoped), 4)
            entry["attacked_utility"] = round(sum(int(row["utility"]) for row in scoped) / len(scoped), 4)
        out["systems"][system] = entry
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", required=True)
    parser.add_argument("--route", required=True)
    parser.add_argument("--systems", default="base,rope")
    parser.add_argument("--attack", default="important_instructions_no_model_name")
    parser.add_argument("--user-tasks", required=True)
    parser.add_argument("--injection-tasks", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--batch-timeout-seconds", type=int, default=240)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    systems = _items(args.systems)
    user_tasks = _items(args.user_tasks)
    injection_tasks = _items(args.injection_tasks)
    routes = {route.route_id: route for route in _available_routes()}
    route = routes[args.route]

    out_dir = ROOT / RESULT_ROOT / args.run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    attack_path = out_dir / f"attack_rows_{args.suite}_{args.route}.csv"
    error_path = out_dir / f"errors_{args.suite}_{args.route}.csv"
    rows = _read_csv(attack_path) if args.resume else []
    errors = _read_csv(error_path) if args.resume else []

    for system in systems:
        decision_path = out_dir / f"decisions_{args.suite}_{system}_{args.route}.jsonl"
        decisions: list[dict[str, Any]] = []
        run_dir = out_dir / f"runs_{args.suite}_{system}_{args.route}"
        for injection_task in injection_tasks:
            for user_task in user_tasks:
                if args.resume and any(
                    row.get("system") == system
                    and row.get("injection_task") == injection_task
                    and row.get("user_task") == user_task
                    for row in rows
                ):
                    continue
                print(
                    f"=== {args.suite}/{args.route}/{system}/{args.attack}/"
                    f"{injection_task}/{user_task} ===",
                    flush=True,
                )
                try:
                    batch_rows, batch_decisions = _run_agentdojo_batch(
                        {
                            "batch_kind": "attack",
                            "suite_name": args.suite,
                            "route_id": args.route,
                            "system": system,
                            "run_dir": str(run_dir),
                            "attack_name": args.attack,
                            "user_tasks": [user_task],
                            "injection_task": injection_task,
                        },
                        args.batch_timeout_seconds,
                        hard_timeout=True,
                    )
                    decisions.extend(batch_decisions)
                    converted: list[dict[str, Any]] = []
                    for result_row in batch_rows:
                        injection_executed = bool(result_row["injection_executed"])
                        converted.append(
                            {
                                "system": system,
                                "route": args.route,
                                "model": route.model,
                                "suite": args.suite,
                                "attack_name": args.attack,
                                "user_task": result_row["user_task"],
                                "injection_task": result_row["injection_task"],
                                "utility": int(bool(result_row["utility"])),
                                "security_pass": int(not injection_executed),
                                "attack_success": int(injection_executed),
                            }
                        )
                    rows = [
                        *_drop_attack_batch_rows(rows, system, injection_task, [user_task]),
                        *converted,
                    ]
                    errors = _drop_batch_errors(errors, system, injection_task)
                except Exception as exc:  # noqa: BLE001
                    errors.append(
                        {
                            "system": system,
                            "suite": args.suite,
                            "route": args.route,
                            "attack_name": args.attack,
                            "user_task": user_task,
                            "injection_task": injection_task,
                            "error": f"{type(exc).__name__}: {str(exc)[:300]}",
                        }
                    )
                    print(errors[-1]["error"], flush=True)

                _write_csv(attack_path, rows)
                _write_csv(error_path, errors)
                _write_jsonl(decision_path, decisions)
                summary = _summarize(rows, errors)
                (out_dir / f"summary_{args.suite}_{args.route}.json").write_text(
                    json.dumps(summary, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                print(json.dumps(summary, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
