import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.trace_eval import evaluate  # noqa: E402
from rope_bench.trace_monitors import SYSTEM_ORDER  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="在转换后的轨迹用例上运行 ROPE 运行时与各基线")
    parser.add_argument("--suite", choices=("stress", "controlled", "cleanup"), required=True)
    parser.add_argument("--systems", default=",".join(SYSTEM_ORDER))
    parser.add_argument("--k-sweep", default="", help="ROPE 搜索上界扫描，例如 4,6,8,10")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--attack-limit", type=int, default=None)
    parser.add_argument("--benign-limit", type=int, default=None)
    parser.add_argument("--run-id", default="")
    args = parser.parse_args()
    systems = [s for s in args.systems.split(",") if s]
    depths = {"rope": [int(k) for k in args.k_sweep.split(",")]} if args.k_sweep else {}
    summary = evaluate(
        ROOT,
        args.suite,
        systems=systems,
        max_depths=depths,
        workers=args.workers,
        attack_limit=args.attack_limit,
        benign_limit=args.benign_limit,
        run_id=args.run_id,
    )
    print(json.dumps({k: v for k, v in summary.items() if k != "systems"}, indent=1))
    for name, row in summary["systems"].items():
        print(
            f"{name:30s} ASR={row['attack_successes']}/{row['attack_cases']}={row['attack_success_rate']:.4f} "
            f"benign={row['benign_completed']}/{row['benign_cases']} safeatk={row['safe_completion_under_attack']:.4f} "
            f"persistent={row['safe_completion_persistent']:.4f} repaired={row['repaired_cases']}"
        )


if __name__ == "__main__":
    main()
