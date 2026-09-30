import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.trace_eval import build_scenarios  # noqa: E402
from rope_bench.trace_world import run_scenario  # noqa: E402
from rope_core.runtime import HostRuntime, RuntimeConfig  # noqa: E402


class TimedRuntime(HostRuntime):
    # 记录每次调用判定与提权判定的耗时，以及后续搜索展开的抽象状态数
    samples: list[tuple[float, int, int]] = []

    def check_call(self, tool, args):
        start = time.perf_counter()
        decision = super().check_call(tool, args)
        search = decision.evidence.get("future_search", {})
        TimedRuntime.samples.append((time.perf_counter() - start, int(search.get("expanded", 0)), int(search.get("frontier_size", 0))))
        return decision

    def check_stepup(self, permission, bindings=None):
        start = time.perf_counter()
        decision = super().check_stepup(permission, bindings)
        search = decision.evidence.get("future_search", {})
        TimedRuntime.samples.append((time.perf_counter() - start, int(search.get("expanded", 0)), int(search.get("frontier_size", 0))))
        return decision


def main() -> None:
    parser = argparse.ArgumentParser(description="测量 ROPE 运行时单次判定的耗时与搜索规模")
    parser.add_argument("--suite", default="stress")
    parser.add_argument("--attack-limit", type=int, default=2000)
    parser.add_argument("--benign-limit", type=int, default=500)
    parser.add_argument("--k", type=int, nargs="+", default=[4, 6, 8, 10])
    parser.add_argument("--out", default="bench/results/trace_suites/decision_cost.json")
    args = parser.parse_args()
    scenarios = build_scenarios(ROOT, args.suite, attack_limit=args.attack_limit, benign_limit=args.benign_limit)
    report = {"suite": args.suite, "scenarios": len(scenarios), "by_k": {}}
    for k in args.k:
        TimedRuntime.samples = []
        config = RuntimeConfig(max_depth=k)
        for scenario in scenarios:
            run_scenario(scenario, TimedRuntime(scenario.spec, scenario.profiles, config))
        seconds = sorted(sample[0] for sample in TimedRuntime.samples)
        expanded = sorted(sample[1] for sample in TimedRuntime.samples)
        report["by_k"][str(k)] = {
            "decisions": len(seconds),
            "median_ms": round(1000 * statistics.median(seconds), 3),
            "p95_ms": round(1000 * seconds[int(0.95 * (len(seconds) - 1))], 3),
            "max_ms": round(1000 * seconds[-1], 3),
            "median_expanded": statistics.median(expanded),
            "p95_expanded": expanded[int(0.95 * (len(expanded) - 1))],
            "max_expanded": expanded[-1],
        }
        print(k, json.dumps(report["by_k"][str(k)]))
    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
