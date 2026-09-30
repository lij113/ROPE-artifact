import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.controlled_judge_probe import run_probe  # noqa: E402
from rope_bench.stress_suite import (  # noqa: E402
    build_pool,
    generate_attack_cases,
    generate_benign_cases,
    load_profiles,
    render_attack,
    render_benign,
)


def _show_sample(n: int) -> None:
    # 只打印渲染结果，不调用裁判，用于审阅渲染
    profiles = load_profiles(ROOT)
    pool = build_pool(profiles)
    by_family = defaultdict(list)
    for case in generate_attack_cases(profiles):
        by_family[case.family].append(case)
    for family in sorted(by_family):
        for case in by_family[family][:n]:
            task, traj, call = render_attack(case, pool)
            print("=" * 78)
            print(f"[attack/{family}] {case.profile.server_id}/{case.profile.tool}")
            print("USER TASK:", task)
            print(traj)
            print("PROPOSED CALL:", call)
    benign_by_family = defaultdict(list)
    for case in generate_benign_cases(profiles):
        benign_by_family[case.family].append(case)
    for family in sorted(benign_by_family):
        for case in benign_by_family[family][:n]:
            task, traj, call = render_benign(case, pool)
            print("=" * 78)
            print(f"[benign/{family}] {case.profile.server_id}/{case.profile.tool}")
            print("USER TASK:", task)
            print(traj)
            print("PROPOSED CALL:", call)


def main() -> None:
    parser = argparse.ArgumentParser(description="前瞻裁判与 ROPE 运行时在压力测试集抽样用例上的对比")
    parser.add_argument("--per-attack-family", type=int, default=10)
    parser.add_argument("--per-benign-family", type=int, default=6)
    parser.add_argument("--strict", action="store_true", help="critical 也算拦截")
    parser.add_argument("--show-sample", type=int, nargs="?", const=1, default=0)
    parser.add_argument("--workers", type=int, default=1, help="并发的裁判请求数")
    parser.add_argument("--online", action="store_true", help="缓存里没有的判定去调用裁判；默认只用缓存")
    args = parser.parse_args()

    if args.show_sample:
        _show_sample(args.show_sample)
        return

    summary = run_probe(
        ROOT,
        per_attack_family=args.per_attack_family,
        per_benign_family=args.per_benign_family,
        block_on=("unsafe", "critical") if args.strict else ("unsafe",),
        workers=args.workers,
        offline=not args.online,
    )
    print(
        "judge %s | attacks blocked %.3f (ROPE %.3f) of %d | benign blocked %.3f (ROPE %.3f) of %d | unparsed %d"
        % (
            summary["model"],
            summary["judge_attack_block_rate"],
            summary["rope_attack_block_rate"],
            summary["attack_cases"],
            summary["judge_benign_block_rate"],
            summary["rope_benign_block_rate"],
            summary["benign_cases"],
            summary["unparsed"],
        )
    )
    print("%-46s %5s %6s %6s %5s" % ("family", "n", "judge", "ROPE", "excl"))
    for key, entry in sorted(summary["per_family"].items()):
        print("%-46s %5d %6.2f %6.2f %5d" % (key, entry["cases"], entry["judge_block_rate"], entry["rope_block_rate"], entry["excluded"]))
    print(json.dumps({k: summary[k] for k in ("attack_cases_sampled", "attack_cases", "benign_cases", "unparsed")}))


if __name__ == "__main__":
    main()
