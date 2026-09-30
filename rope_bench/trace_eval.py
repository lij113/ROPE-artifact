from __future__ import annotations

import csv
import gzip
import io
import json
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from rope_bench.trace_monitors import SYSTEM_ORDER, monitor_factory
from rope_bench.trace_world import Scenario, run_scenario

RESULT_ROOT = Path("bench/results/trace_suites")
_CACHE: dict[tuple, list[Scenario]] = {}


def build_scenarios(root: Path, suite: str, *, attack_limit: int | None = None, benign_limit: int | None = None) -> list[Scenario]:
    key = (str(root), suite, attack_limit, benign_limit)
    if key in _CACHE:
        return _CACHE[key]
    if suite == "stress":
        from rope_bench.stress_suite import (
            attack_scenario,
            benign_scenario,
            build_pool,
            generate_attack_cases,
            generate_benign_cases,
            load_profiles,
        )

        profiles = load_profiles(root)
        pool = build_pool(profiles)
        attacks = generate_attack_cases(profiles)
        benign = generate_benign_cases(profiles)
        if attack_limit is not None:
            attacks = attacks[:: max(1, len(attacks) // attack_limit)][:attack_limit]
        if benign_limit is not None:
            # 步长取与类别数互质的值，抽样覆盖全部良性类别
            step = max(1, len(benign) // benign_limit)
            step += 1 if step % 2 == 0 else 0
            benign = benign[::step][:benign_limit]
        scenarios = [attack_scenario(case, pool) for case in attacks] + [benign_scenario(case, pool) for case in benign]
    elif suite == "controlled":
        from rope_bench.controlled_suite import controlled_scenarios

        scenarios = controlled_scenarios(root)
    elif suite == "cleanup":
        from rope_bench.controlled_suite import premature_cleanup_scenarios

        scenarios = premature_cleanup_scenarios(root)
    else:
        raise ValueError(f"unknown suite {suite}")
    _CACHE[key] = scenarios
    return scenarios


def _run_slice(job: tuple[str, str, str, int | None, int, int, int | None, int | None]) -> list[dict[str, Any]]:
    root, suite, system, max_depth, part, parts, attack_limit, benign_limit = job
    scenarios = build_scenarios(Path(root), suite, attack_limit=attack_limit, benign_limit=benign_limit)
    factory = monitor_factory(system, max_depth=max_depth)
    rows = []
    for scenario in scenarios[part::parts]:
        start = time.perf_counter()
        result = run_scenario(scenario, factory(scenario))
        elapsed = time.perf_counter() - start
        # 代理不自行恢复时（攻击之后不再继续任务）的任务完成情况
        persistent = run_scenario(scenario, factory(scenario), recover=False) if scenario.kind == "attack" else result
        attack_steps = [entry for entry in result["log"] if entry["role"] == "attack"]
        rows.append(
            {
                "suite": suite,
                "system": system,
                "max_depth": max_depth or "",
                "scenario_id": scenario.scenario_id,
                "kind": scenario.kind,
                "family": scenario.family,
                "workflow": scenario.meta.get("workflow", ""),
                "call_kind": scenario.meta.get("call_kind", ""),
                "source_class": scenario.meta.get("source_class", ""),
                "variant": "|".join(f"{k}={v}" for k, v in sorted(scenario.meta.items()) if k in ("recipient", "sink", "trust", "approval", "permission", "contract")),
                "attack_success": int(result["attack_success"]),
                "attack_goals": "+".join(result["attack_goals"]),
                "attack_steps_stopped": int(
                    bool(attack_steps) and all(entry["decision"] not in ("allow",) for entry in attack_steps)
                ),
                "task_complete": int(result["task_complete"]),
                "task_complete_persistent": int(persistent["task_complete"] and not persistent["attack_success"]),
                "repaired": int(any(entry["decision"] == "repair" for entry in persistent["log"])),
                "benign_violation": int(result["benign_violation"]),
                "first_stop_reason": next(
                    (entry.get("reason", entry["decision"]) for entry in result["log"] if entry["decision"] not in ("allow", "recorded", "observed")),
                    "",
                ),
                "seconds": round(elapsed, 6),
            }
        )
    return rows


def evaluate(
    root: Path,
    suite: str,
    *,
    systems: Sequence[str] = SYSTEM_ORDER,
    max_depths: Mapping[str, Sequence[int | None]] | None = None,
    workers: int = 8,
    attack_limit: int | None = None,
    benign_limit: int | None = None,
    run_id: str = "",
) -> dict[str, Any]:
    jobs = []
    for system in systems:
        for depth in (max_depths or {}).get(system, [None]):
            for part in range(workers):
                jobs.append((str(root), suite, system, depth, part, workers, attack_limit, benign_limit))
    rows: list[dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        for part in executor.map(_run_slice, jobs):
            rows.extend(part)
    # 按系统、搜索上界、用例排序，结果顺序与并行进程数无关
    rows.sort(key=lambda row: (row["system"], str(row["max_depth"]), row["scenario_id"]))
    out_dir = root / RESULT_ROOT / (run_id or suite)
    out_dir.mkdir(parents=True, exist_ok=True)
    # 逐条结果行按 gzip 存放；mtime 固定为 0，文件头不随运行时间变化
    with io.TextIOWrapper(gzip.GzipFile(out_dir / "rows.csv.gz", "wb", mtime=0), encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary = summarize(rows)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def summarize(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(rows)
    # 攻击集合：不设监控时确实达成攻击目标的用例；良性集合：不设监控时能完成任务的用例
    harmful = {
        row["scenario_id"]
        for row in rows
        if row["system"] == "none" and row["kind"] == "attack" and int(row["attack_success"])
    }
    completable = {
        row["scenario_id"]
        for row in rows
        if row["system"] == "none" and row["kind"] == "benign" and int(row["task_complete"])
    }
    by_system: dict[str, dict[str, Any]] = {}
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[(row["system"], str(row["max_depth"]))].append(row)
    for (system, depth), group in sorted(groups.items()):
        attacks = [row for row in group if row["kind"] == "attack" and row["scenario_id"] in harmful]
        benign = [row for row in group if row["kind"] == "benign" and row["scenario_id"] in completable]
        key = system if not depth else f"{system}@k={depth}"
        by_system[key] = {
            "attack_cases": len(attacks),
            "attack_successes": sum(int(row["attack_success"]) for row in attacks),
            "attack_success_rate": _rate(attacks, "attack_success"),
            "benign_cases": len(benign),
            "benign_completed": sum(int(row["task_complete"]) for row in benign),
            "benign_completion": _rate(benign, "task_complete"),
            "safe_completions_under_attack": sum(
                1 for row in attacks if not int(row["attack_success"]) and int(row["task_complete"])
            ),
            "safe_completion_under_attack": round(
                sum(1 for row in attacks if not int(row["attack_success"]) and int(row["task_complete"])) / len(attacks), 4
            )
            if attacks
            else 0.0,
            "safe_completion_persistent": round(
                sum(1 for row in attacks if not int(row["attack_success"]) and int(row["task_complete_persistent"])) / len(attacks), 4
            )
            if attacks
            else 0.0,
            "repaired_cases": sum(int(row["repaired"]) for row in attacks),
            "attack_success_by_family": _by(attacks, "family", "attack_success"),
            "attack_success_by_goal": dict(Counter(goal for row in attacks for goal in row["attack_goals"].split("+") if goal)),
            "benign_completion_by_family": _by(benign, "family", "task_complete"),
            "benign_stop_reasons": dict(
                Counter(row["first_stop_reason"] for row in benign if not int(row["task_complete"]))
            ),
            "attack_stop_reasons": dict(
                Counter(row["first_stop_reason"] for row in attacks if not int(row["attack_success"])).most_common(15)
            ),
            "median_seconds_per_scenario": _median([float(row["seconds"]) for row in group]),
            "p95_seconds_per_scenario": _percentile([float(row["seconds"]) for row in group], 0.95),
        }
    return {
        "attack_scenarios": len({row["scenario_id"] for row in rows if row["kind"] == "attack"}),
        "harmful_attack_scenarios": len(harmful),
        "harmful_goals": dict(
            Counter(
                goal
                for row in rows
                if row["system"] == "none" and row["kind"] == "attack"
                for goal in row["attack_goals"].split("+")
                if goal
            )
        ),
        "benign_scenarios": len({row["scenario_id"] for row in rows if row["kind"] == "benign"}),
        "completable_benign_scenarios": len(completable),
        "systems": by_system,
    }


def _rate(rows: Sequence[Mapping[str, Any]], key: str) -> float:
    return round(sum(int(row[key]) for row in rows) / len(rows), 4) if rows else 0.0


def _by(rows: Sequence[Mapping[str, Any]], field: str, key: str) -> dict[str, float]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row[field]].append(row)
    return {name: _rate(items, key) for name, items in sorted(grouped.items())}


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[len(ordered) // 2], 6)


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 6)
