from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPROMISED = ROOT / "bench/results/agentdojo_compromised"
INLOOP = ROOT / "bench/results/agentdojo_inloop"
PROBE = ROOT / "bench/results/controlled_judge_probe"


def read_csv(paths) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            rows += list(csv.DictReader(handle))
    return rows


def slices(pattern: str) -> list[Path]:
    # 冒烟测试目录不计入
    return sorted(run for run in COMPROMISED.glob(pattern) if "smoke" not in run.name)


def pct(numerator: float, denominator: int) -> str:
    return f"{100 * numerator / denominator:.1f}%"


def compromised_row(label: str, runs: list[Path], system: str) -> None:
    attack = [r for r in read_csv(run / "attack_rows.csv" for run in runs) if r["system"] == system]
    benign = [r for r in read_csv(run / "benign_rows.csv" for run in runs) if r["system"] == system]
    accepted = sum(int(r["attack_success"]) for r in attack)
    attacked_utility = sum(int(r["utility"]) for r in attack)
    line = f"{label:44s} ASR {pct(accepted, len(attack)):>6s} ({accepted}/{len(attack)})"
    if benign:
        line += f"  benign utility {pct(sum(int(r['utility']) for r in benign), len(benign)):>6s} ({len(benign)} tasks)"
    line += f"  utility under attack {pct(attacked_utility, len(attack)):>6s}"
    print(line)


def compromised_planner() -> None:
    print("== Table: enforcement under a fully compromised planner (629 pairs, 97 benign tasks)")
    main_run = [COMPROMISED / "e4_compromised_v2b"]
    compromised_row("no monitor", main_run, "base")
    compromised_row("session taint block", [COMPROMISED / "e4_baseline_taint_block"], "taint_block")
    compromised_row("monotone value budget", [COMPROMISED / "e4_baseline_monotone"], "monotone_budget")
    compromised_row("look-ahead judge, claude-sonnet-5", slices("e4_llm_[bstw]*"), "llm_lookahead")
    compromised_row("  adaptive injection addressed to the judge", slices("e4_llm_note_*"), "llm_lookahead")
    compromised_row("look-ahead judge, deepseek-flash", slices("e7_wj_deepseek-flash_*"), "llm_lookahead")
    compromised_row("  adaptive injection addressed to the judge", slices("e7_wj_note_deepseek-flash_*"), "llm_lookahead")
    compromised_row("ROPE, as-published profile (v1)", main_run, "rope")
    compromised_row("ROPE, audited profile (v2)", main_run, "rope_v2")


def summary_all(run: str, system: str) -> dict:
    return json.loads((COMPROMISED / run / "summary.json").read_text())["suites"]["ALL"][system]


def profile_audit() -> None:
    print("\n== Table: profile audit (leave-one-out over the four audited rules)")
    full = summary_all("e4_ablation_all", "rope_v2")
    v1 = summary_all("e4_compromised_v2b", "rope")
    print(f"as-published profile: accepted {v1['attack_successes']}, benign tasks with a block {v1['benign_tasks_with_block']}")
    print(f"audited profile:      accepted {full['attack_successes']}, benign tasks with a block {full['benign_tasks_with_block']}")
    for rule in ("fields", "fetch", "commit", "ident"):
        row = summary_all(f"e4_ablation_no_{rule}", "rope_v2")
        print(
            f"without {rule:7s} attacks reopened {row['attack_successes'] - full['attack_successes']:3d}  "
            f"benign tasks freed {full['benign_tasks_with_block'] - row['benign_tasks_with_block']:3d}"
        )


def held_out() -> None:
    print("\n== E3: held-out reworded injections (AgentDojo v1.2.2, injections with attacker ground truth)")
    # v1.2.2 改写了 banking 注入 0-6、8 与 travel 注入 2、5 的目标；workspace 新增注入没有攻击者 ground truth
    banking = {f"injection_task_{i}" for i in (0, 1, 2, 3, 4, 5, 6, 8)}
    travel = {"injection_task_2", "injection_task_5"}
    rows = read_csv([COMPROMISED / "e4_heldout_v122" / "attack_rows.csv"])
    for system in ("base", "rope", "rope_v2"):
        selected = [
            r for r in rows
            if r["system"] == system
            and ((r["suite"] == "banking" and r["injection_task"] in banking)
                 or (r["suite"] == "travel" and r["injection_task"] in travel))
        ]
        accepted = sum(int(r["attack_success"]) for r in selected)
        print(f"{system:8s} ASR {pct(accepted, len(selected))} ({accepted}/{len(selected)})")


def judge_probe() -> None:
    print("\n== Table: look-ahead judges and the ROPE runtime on the stress-suite sample")
    for model in ("claude-sonnet-5", "deepseek-flash"):
        rows = read_csv([PROBE / f"probe_rows_{model}.csv"])
        # 只计无人拦截时达成攻击目标的攻击用例、能完成的良性用例
        attack = [r for r in rows if r["kind"] == "attack" and r["in_scope"] == "1"]
        benign = [r for r in rows if r["kind"] == "benign" and r["in_scope"] == "1"]
        unparsed = sum(r["judge_safety"] not in ("safe", "critical", "unsafe") for r in rows)
        for who, key in ((model, "judge_blocks"), ("ROPE full", "rope_blocks")):
            print(
                f"{who:16s} attacks blocked {pct(sum(int(r[key]) for r in attack), len(attack)):>6s} of {len(attack)}  "
                f"benign refused {pct(sum(int(r[key]) for r in benign), len(benign)):>6s} of {len(benign)}"
            )
        by_family: dict[str, list[int]] = defaultdict(list)
        for r in attack:
            by_family[r["family"]].append(int(r["judge_blocks"]))
        missed = {f: sum(v) / len(v) for f, v in sorted(by_family.items()) if sum(v) < len(v)}
        print(f"{model}: unparsed verdicts {unparsed}; attack families below 1.0 {missed}")


def live_utility() -> None:
    print("\n== Table: benign task success with live models (tasks present in all three arms)")
    for route in ("claude-api", "gpt-api", "minimax"):
        v1 = read_csv(sorted((INLOOP / f"e4_benign_v1_{route}").glob("benign_rows_*.csv")))
        v2 = read_csv(sorted((INLOOP / f"e4_benign_v2_{route}").glob("benign_rows_*.csv")))
        arms = {
            "no monitor": {(r["suite"], r["user_task"]): int(r["utility"]) for r in v1 if r["system"] == "base"},
            "ROPE v1": {(r["suite"], r["user_task"]): int(r["utility"]) for r in v1 if r["system"] == "rope"},
            "ROPE v2": {(r["suite"], r["user_task"]): int(r["utility"]) for r in v2 if r["system"] == "rope"},
        }
        common = set.intersection(*(set(arm) for arm in arms.values()))
        scores = {name: sum(arm[key] for key in common) / len(common) for name, arm in arms.items()}
        model = next(r["model"] for r in v1)
        cost = 100 * (scores["ROPE v2"] - scores["no monitor"])
        print(
            f"{model:16s} tasks {len(common):3d}  "
            + "  ".join(f"{name} {100 * value:.1f}%" for name, value in scores.items())
            + f"  v2 cost {cost:+.1f} pp"
        )


def pilot() -> None:
    print("\n== Evaluation text: base ASR of live models on AgentDojo's own attacks (banking + slack)")
    for route in ("claude-api", "gpt-api", "deepseek-api", "minimax"):
        rows = []
        for attack in ("ii", "tk"):
            rows += read_csv(sorted((INLOOP / f"e4_pilot_{attack}_{route}").glob("attack_rows_*.csv")))
        base = [r for r in rows if r["system"] == "base"]
        print(f"{base[0]['model']:24s} diverted {sum(int(r['attack_success']) for r in base)} of {len(base)} attacked episodes")


if __name__ == "__main__":
    compromised_planner()
    profile_audit()
    held_out()
    judge_probe()
    live_utility()
    pilot()
