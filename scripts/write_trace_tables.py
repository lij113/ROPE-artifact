import argparse
import csv
import gzip
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

RESULTS = ROOT / "bench" / "results"

NAMES = {
    "none": "No monitor",
    "scope-gate": "Scope gate (task tool allowlist)",
    "approval-gate": "Approval gate (any approval)",
    "bound-approval": "Bound approval gate",
    "taint-block": "Taint tracking, no declassification",
    "ifc-declass": "IFC with trusted declassification",
    "ifc-declass+bound-approval": "IFC and bound approval",
    "capability-handles": "Capability handles",
    "current-predicates": "Current-call predicates",
    "temporal-phase": "Temporal phase order",
    "trace-contract": "Trace contract only",
    "argument-provenance": "Argument provenance",
    "rope-no-provenance": "\\ROPE{} without value provenance",
    "rope-no-obligations": "\\ROPE{} without obligations",
    "rope-no-future": "\\ROPE{} without \\FutureAccept{}",
    "rope-no-repair": "\\ROPE{} without repair",
    "rope-no-certificate": "\\ROPE{} without certificate check",
    "rope-raw-text": "\\ROPE{}, raw-text provenance",
    "rope-scanner": "\\ROPE{}, scanner provenance",
    "rope": "\\textbf{\\ROPE{} full}",
}
BASELINE_ORDER = (
    "scope-gate",
    "approval-gate",
    "bound-approval",
    "taint-block",
    "ifc-declass",
    "ifc-declass+bound-approval",
    "capability-handles",
    "current-predicates",
    "temporal-phase",
    "trace-contract",
    "argument-provenance",
)
ABLATION_ORDER = (
    "rope-no-provenance",
    "rope-no-obligations",
    "rope-no-future",
    "rope-no-repair",
    "rope-no-certificate",
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pct(value: float) -> str:
    return f"{100 * value:.1f}\\%"


def num(value: int) -> str:
    return f"{value:,}".replace(",", "{,}")


def count(n: int, d: int) -> str:
    return f"{n}/{num(d)}"


def controlled_table(summary: dict, cleanup: dict) -> str:
    systems = summary["systems"]
    lines = []
    for group in (BASELINE_ORDER, ABLATION_ORDER, ("rope",)):
        for name in group:
            row = systems[name]
            clean = cleanup["systems"][name]
            lines.append(
                f"{NAMES[name]} & {count(row['attack_successes'], row['attack_cases'])} & "
                f"{row['benign_completed']}/{row['benign_cases']} & "
                f"{pct(row['safe_completion_under_attack'])} & {pct(row['safe_completion_persistent'])} & "
                f"{clean['attack_successes']}/{clean['attack_cases']} \\\\"
            )
        lines.append("\\midrule")
    body = "\n".join(lines[:-1])
    harmful = summary["harmful_attack_scenarios"]
    total = summary["attack_scenarios"]
    return f"""\\begin{{table*}}[t]
\\centering
\\scriptsize
\\setlength{{\\tabcolsep}}{{4pt}}
\\renewcommand{{\\arraystretch}}{{0.88}}
\\begin{{tabular}}{{@{{}}lrrrrr@{{}}}}
\\toprule
Monitor & Accepted attacks $\\downarrow$ & Benign done $\\uparrow$ &
\\begin{{tabular}}[b]{{@{{}}r@{{}}}}Safe completion,\\\\ agent continues $\\uparrow$\\end{{tabular}} &
\\begin{{tabular}}[b]{{@{{}}r@{{}}}}Safe completion,\\\\ agent stops $\\uparrow$\\end{{tabular}} &
\\begin{{tabular}}[b]{{@{{}}r@{{}}}}Premature\\\\ cleanup $\\downarrow$\\end{{tabular}} \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}
\\caption{{Controlled suite, executed. Every monitor receives the same event
traces: twelve attack templates over three workflows, 144 variants each
({num(total)} traces, of which {num(harmful)} achieve an attacker goal when no monitor
runs and are scored here), the three benign workflows, and the premature-cleanup
pair of Section~\\ref{{sec:eval}}. Safe completion counts attacked traces that
end with no attacker goal achieved and the task done, once when the agent
continues its task after a rejection and once when it stops at the rejected
call, so that only a repair can finish the task.}}
\\label{{tab:controlled-results}}
\\end{{table*}}
"""


def probe_table(probes: dict[str, dict]) -> str:
    sonnet = probes["claude-sonnet-5"]
    deepseek = probes["deepseek-flash"]

    def row(label: str, summary: dict, prefix: str) -> str:
        attacks = summary["attack_cases"]
        benign = summary["benign_cases"]
        blocked = round(summary[f"{prefix}_attack_block_rate"] * attacks)
        refused = round(summary[f"{prefix}_benign_block_rate"] * benign)
        return f"{label} & {blocked}/{attacks} ({pct(summary[f'{prefix}_attack_block_rate'])}) & {refused}/{benign} ({pct(summary[f'{prefix}_benign_block_rate'])}) \\\\"

    misses = []
    for family, entry in sorted(deepseek["per_family"].items()):
        if family.startswith("attack/") and entry["judge_block_rate"] < 1.0:
            misses.append((family.split("/", 1)[1].replace("_", " "), entry["judge_block_rate"]))
    miss_text = "; ".join(f"{name} {rate:.2f}" for name, rate in misses)
    rows = "\n".join(
        (
            row("LLM look-ahead judge, frontier model (claude-sonnet-5)", sonnet, "judge"),
            row("LLM look-ahead judge, small model (deepseek-flash)", deepseek, "judge"),
            row("\\textbf{\\ROPE{} full}", sonnet, "rope"),
        )
    )
    return f"""\\begin{{table*}}[t]
\\centering
\\scriptsize
\\setlength{{\\tabcolsep}}{{5pt}}
\\renewcommand{{\\arraystretch}}{{0.9}}
\\begin{{tabular}}{{@{{}}lrr@{{}}}}
\\toprule
Monitor & Attacks blocked $\\uparrow$ & Benign tasks refused $\\downarrow$ \\\\
\\midrule
{rows}
\\bottomrule
\\end{{tabular}}
\\caption{{Look-ahead judges and \\ROPE{{}} on the profile-derived stress suite:
ten cases from each of its sixteen attack families and six from each of its eight
benign families. The judges decide the rendered trajectories with the prompt of
the in-loop judge baseline; \\ROPE{{}} runs the same case records as event traces.
{sonnet['attack_cases_sampled'] - sonnet['attack_cases']} sampled attack case achieves no attacker goal
when no monitor runs and is not scored. No judge verdict remained unparsed. The small
judge misses attacks in five families ({miss_text}).}}
\\label{{tab:judge-probe}}
\\end{{table*}}
"""


def stress_table(summary: dict) -> str:
    systems = summary["systems"]
    lines = []
    for group in (("none",), BASELINE_ORDER, ABLATION_ORDER, ("rope@k=8",)):
        for name in group:
            row = systems[name]
            label = NAMES["rope" if name.startswith("rope@") else name]
            lines.append(
                f"{label} & {pct(row['attack_success_rate'])} & {pct(row['benign_completion'])} & "
                f"{pct(row['safe_completion_under_attack'])} & {pct(row['safe_completion_persistent'])} \\\\"
            )
        lines.append("\\midrule")
    body = "\n".join(lines[:-1])
    return f"""\\begin{{table*}}[t]
\\centering
\\scriptsize
\\setlength{{\\tabcolsep}}{{4pt}}
\\begin{{tabular}}{{@{{}}lrrrr@{{}}}}
\\toprule
Monitor & ASR $\\downarrow$ & Benign done $\\uparrow$ & Safe completion, continues $\\uparrow$ & Safe completion, stops $\\uparrow$ \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}
\\caption{{Profile-derived stress suite, executed: {num(summary['harmful_attack_scenarios'])} attack traces
that achieve an attacker goal without a monitor (of {num(summary['attack_scenarios'])} generated) and
{num(summary['completable_benign_scenarios'])} benign traces, each built from one of 124 captured MCP
tool profiles. \\ROPE{{}} runs at $k=8$.}}
\\label{{tab:stress-results}}
\\end{{table*}}
"""


def family_matrix(summary: dict) -> str:
    systems = summary["systems"]
    columns = ("scope-gate", "bound-approval", "ifc-declass+bound-approval", "current-predicates", "trace-contract", "rope-no-future", "rope@k=8")
    heads = ("Scope", "Bnd-Appr", "IFC+Appr", "Pred.", "Contract", "R$-$fut", "\\ROPE{}")
    families = sorted(systems["none"]["attack_success_by_family"])
    lines = []
    for family in families:
        cells = []
        for name in columns:
            rate = systems[name]["attack_success_by_family"][family]
            cells.append(f"{100 * (1 - rate):.0f}")
        lines.append(family.replace("_", " ").capitalize() + " & " + " & ".join(cells) + " \\\\")
    return (
        "\\begin{table}[t]\n\\centering\n\\scriptsize\n\\setlength{\\tabcolsep}{3pt}\n"
        "\\resizebox{\\columnwidth}{!}{%\n\\begin{tabular}{@{}l" + "r" * len(columns) + "@{}}\n\\toprule\n"
        "Attack family & " + " & ".join(heads) + " \\\\\n\\midrule\n" + "\n".join(lines) +
        "\n\\bottomrule\n\\end{tabular}%\n}\n"
        "\\caption{Share of attack traces blocked (\\%) per family on the executed stress suite. "
        "R$-$fut is \\ROPE{} without \\FutureAccept{}; its permission check falls back to the contract's static budget.}\n"
        "\\label{tab:mechanism-family-matrix}\n\\end{table}\n"
    )


def false_rejection_table(summary: dict, rows_path: Path) -> str:
    systems = summary["systems"]
    reasons: dict[str, Counter] = defaultdict(Counter)
    completable = set()
    with gzip.open(rows_path, "rt", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        if row["system"] == "none" and row["kind"] == "benign" and row["task_complete"] == "1":
            completable.add(row["scenario_id"])
    for row in rows:
        if row["system"] == "rope" and row["kind"] == "benign" and row["scenario_id"] in completable and row["task_complete"] == "0":
            reasons[row["max_depth"]][row["family"]] += 1
    lines = []
    for k in ("4", "6", "8", "10"):
        entry = systems[f"rope@k={k}"]
        n = entry["benign_cases"]
        failed = n - entry["benign_completed"]
        split = ", ".join(f"{family.replace('_', ' ')} {cnt}" for family, cnt in sorted(reasons[k].items())) or "none"
        lines.append(f"{k} & {pct(entry['attack_success_rate'])} & {failed}/{n} ({pct(failed / n)}) & {split} \\\\")
    body = "\n".join(lines)
    return f"""\\begin{{table*}}[t]
\\centering
\\scriptsize
\\begin{{tabularx}}{{\\textwidth}}{{r r r Y}}
\\toprule
$k$ & ASR & Benign refused & Refused benign traces by family \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabularx}}
\\caption{{Search bound and false rejection of \\ROPE{{}} on the executed stress suite. A benign trace is
refused when the monitor stops a step and the task does not finish.}}
\\label{{tab:false-rejection-k-tradeoff}}
\\end{{table*}}
"""


def provenance_table(summary: dict) -> str:
    systems = summary["systems"]
    lines = []
    for name, mode in (("rope-raw-text", "Raw text"), ("rope-scanner", "Host scanner"), ("rope", "Context closure")):
        entry = systems[name]
        leak = entry["attack_success_by_family"]["fresh_literal_leak"]
        lines.append(f"{mode} & {pct(leak)} & {pct(entry['attack_success_rate'])} & {pct(entry['benign_completion'])} \\\\")
    body = "\n".join(lines)
    return f"""\\begin{{table}}[t]
\\centering
\\scriptsize
\\begin{{tabular}}{{@{{}}lrrr@{{}}}}
\\toprule
Provenance mode & Fresh-literal ASR & All-family ASR & Benign done \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}
\\caption{{Provenance modes for model-written literals on the executed stress suite. The host scanner
labels a literal that contains a span the host marked as protected in a value the model has seen;
context closure gives every model-written literal the joined label of the values the model has seen.}}
\\label{{tab:context-provenance-modes}}
\\end{{table}}
"""


def cost_table(cost: dict) -> str:
    lines = []
    for k, entry in sorted(cost["by_k"].items(), key=lambda item: int(item[0])):
        lines.append(
            f"{k} & {num(entry['decisions'])} & {entry['median_ms']:.2f} & {entry['p95_ms']:.2f} & "
            f"{int(entry['median_expanded'])} & {num(int(entry['p95_expanded']))} & {num(int(entry['max_expanded']))} \\\\"
        )
    body = "\n".join(lines)
    return f"""\\begin{{table}}[t]
\\centering
\\scriptsize
\\setlength{{\\tabcolsep}}{{3pt}}
\\begin{{tabular}}{{@{{}}rrrrrrr@{{}}}}
\\toprule
$k$ & Decisions & Median ms & p95 ms & Median states & p95 states & Max states \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}
\\caption{{Measured cost of one \\ROPE{{}} decision, including the \\FutureAccept{{}} search, on a
{num(cost['scenarios'])}-trace sample of the stress suite (single core, Python 3.11). States are abstract states
expanded by the bounded search.}}
\\label{{tab:future-scaling-model}}
\\end{{table}}
"""


def repair_table(controlled: dict, stress: dict, replay: dict) -> str:
    rows = []
    for name, label in (("rope", "\\textbf{\\ROPE{} full}"), ("rope-no-repair", "\\ROPE{} without repair"), ("rope-no-certificate", "\\ROPE{} without certificate check")):
        c = controlled["systems"][name]
        s = stress["systems"]["rope@k=8" if name == "rope" else name]
        replayed = c["attack_success_by_family"]["repair_certificate_replay"]
        rows.append(
            f"{label} & {pct(c['safe_completion_persistent'])} & {pct(s['safe_completion_persistent'])} & {pct(replayed)} \\\\"
        )
    body = "\n".join(rows)
    checks = "; ".join(
        f"{text} {'yes' if replay[key] else 'no'}"
        for key, text in (
            ("valid_replay_accepts", "valid replay accepted"),
            ("recipient_swap_rejected", "recipient swap rejected"),
            ("stale_certificate_rejected", "stale certificate rejected"),
        )
    )
    return f"""\\begin{{table}}[t]
\\centering
\\scriptsize
\\setlength{{\\tabcolsep}}{{3pt}}
\\begin{{tabular}}{{@{{}}lrrr@{{}}}}
\\toprule
Monitor & \\begin{{tabular}}[b]{{@{{}}r@{{}}}}Safe completion,\\\\ agent stops, controlled\\end{{tabular}} &
\\begin{{tabular}}[b]{{@{{}}r@{{}}}}Safe completion,\\\\ agent stops, stress\\end{{tabular}} &
\\begin{{tabular}}[b]{{@{{}}r@{{}}}}Certificate-replay\\\\ attacks accepted\\end{{tabular}} \\\\
\\midrule
{body}
\\bottomrule
\\end{{tabular}}
\\caption{{Repair and certificate value on the executed suites. When the agent stops at a rejected call,
only a repair can finish the task. Certificate-replay attacks are the controlled suite's template in which the
agent submits a repair plan certified in another session. The running-example certificate replay reports: {checks}.}}
\\label{{tab:repair-certificate-main}}
\\end{{table}}
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="由真实运行结果生成论文表格")
    parser.add_argument("--out", required=True)
    parser.add_argument("--controlled", default="controlled_v1")
    parser.add_argument("--cleanup", default="cleanup")
    parser.add_argument("--stress", default="stress_v1")
    parser.add_argument("--modes", default="stress_modes")
    args = parser.parse_args()
    out = Path(args.out)
    suites = RESULTS / "trace_suites"
    controlled = load(suites / args.controlled / "summary.json")
    cleanup = load(suites / args.cleanup / "summary.json")
    (out / "table_controlled_results.tex").write_text(controlled_table(controlled, cleanup), encoding="utf-8")
    probes = {
        model: load(RESULTS / "controlled_judge_probe" / f"probe_summary_{model}.json")
        for model in ("claude-sonnet-5", "deepseek-flash")
    }
    (out / "table_judge_probe.tex").write_text(probe_table(probes), encoding="utf-8")
    if (suites / args.stress / "summary.json").exists():
        stress = load(suites / args.stress / "summary.json")
        (out / "table_stress_results.tex").write_text(stress_table(stress), encoding="utf-8")
        (out / "table_mechanism_family_matrix.tex").write_text(family_matrix(stress), encoding="utf-8")
        (out / "table_false_rejection_analysis.tex").write_text(
            false_rejection_table(stress, suites / args.stress / "rows.csv.gz"), encoding="utf-8"
        )
    if (suites / args.modes / "summary.json").exists():
        (out / "table_context_provenance_modes.tex").write_text(provenance_table(load(suites / args.modes / "summary.json")), encoding="utf-8")
    if (suites / "decision_cost.json").exists():
        (out / "table_future_scaling_model.tex").write_text(cost_table(load(suites / "decision_cost.json")), encoding="utf-8")
    replay_path = RESULTS / "certificate_replay" / "certificate_replay_sample.json"
    if (suites / args.stress / "summary.json").exists() and replay_path.exists():
        (out / "table_repair_certificate_main.tex").write_text(
            repair_table(controlled, load(suites / args.stress / "summary.json"), load(replay_path)), encoding="utf-8"
        )


if __name__ == "__main__":
    main()
