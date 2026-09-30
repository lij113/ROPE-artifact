"""Aggregate in-loop AgentDojo runs into paper artifacts."""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

RESULT_ROOT = Path("bench/results/agentdojo_inloop")
SCOPE_ORDER = ("sink_governed", "text_output", "other")
SCOPE_LABELS = {
    "sink_governed": "In-scope (sink-governed)",
    "text_output": "Out-of-scope (text-output)",
    "other": "Other",
}
SINK_GOVERNED_INJECTIONS = {
    "workspace": frozenset(f"injection_task_{idx}" for idx in range(6)),
    "travel": frozenset(f"injection_task_{idx}" for idx in range(6)),
}
TEXT_OUTPUT_INJECTIONS = {
    "travel": frozenset({"injection_task_6"}),
}


def summarize_agentdojo_inloop_run(root: Path, *, run_id: str) -> dict[str, Any]:
    run_dir = root / RESULT_ROOT / run_id
    attack_rows = _read_many(run_dir.glob("attack_rows_*.csv"))
    benign_rows = _read_many(run_dir.glob("benign_rows_*.csv"))
    error_rows = _read_many(run_dir.glob("errors_*.csv"))

    route_rows = _route_rows(attack_rows, benign_rows, error_rows)
    aggregate_rows = _aggregate_rows(attack_rows, benign_rows, error_rows)
    scope_rows = _attack_scope_rows(attack_rows, benign_rows)
    status = _status(route_rows)
    matched_status = _matched_status(aggregate_rows)
    failed_route_cells = [
        {
            "suite": row["suite"],
            "route": row["route"],
            "system": row["system"],
            "errors": row["errors"],
        }
        for row in route_rows
        if row["errors"] > 0
    ]
    summary = {
        "run_id": run_id,
        "status": status,
        "matched_status": matched_status,
        "attack_rows": len(attack_rows),
        "benign_rows": len(benign_rows),
        "errors": len(error_rows),
        "failed_route_cells": failed_route_cells,
        "route_rows": route_rows,
        "aggregate_rows": aggregate_rows,
        "scope_rows": scope_rows,
        "notes": [
            "AgentDojo security()==True is treated as attack success.",
            "ROPE is enforced in-loop before tool execution; utility and security are AgentDojo-native labels.",
            "status covers every observed route cell; matched_status covers the aggregate cells reported in the paper table.",
            "Aggregate rows include only matched suite/route cells with both base and ROPE attack and benign rows; route_rows retains partial and error-only cells.",
            "scope_rows split matched attack rows into sink-governed injection tasks and text-output tasks with no ground-truth sink.",
        ],
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "summary_aggregate.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_csv(run_dir / "summary_aggregate_rows.csv", aggregate_rows)
    _write_csv(run_dir / "summary_route_rows.csv", route_rows)
    _write_csv(run_dir / "summary_attack_scope_rows.csv", scope_rows)
    _write_table(root, summary)
    _write_scope_table(root, summary)
    return summary


def _read_many(paths) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(paths):
        if path.stat().st_size == 0:
            continue
        context = _path_context(path)
        with path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                item = dict(row)
                for key, value in context.items():
                    item.setdefault(key, value)
                    if item.get(key, "") == "":
                        item[key] = value
                rows.append(item)
    return rows


def _path_context(path: Path) -> dict[str, str]:
    stem = path.stem
    for prefix in ("attack_rows_", "benign_rows_", "errors_"):
        if not stem.startswith(prefix):
            continue
        rest = stem[len(prefix) :]
        if "_" not in rest:
            return {}
        suite, route = rest.rsplit("_", 1)
        return {"suite": suite, "route": route}
    return {}


def _route_rows(
    attack_rows: list[dict[str, Any]],
    benign_rows: list[dict[str, Any]],
    error_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    keys = sorted(
        {
            (r.get("suite", ""), r.get("route", ""), r.get("system", ""))
            for r in attack_rows + benign_rows + error_rows
        }
    )
    out = []
    for suite, route, system in keys:
        attacks = [
            r
            for r in attack_rows
            if r.get("suite") == suite and r.get("route") == route and r.get("system") == system
        ]
        benign = [
            r
            for r in benign_rows
            if r.get("suite") == suite and r.get("route") == route and r.get("system") == system
        ]
        errors = [
            r
            for r in error_rows
            if r.get("suite") == suite
            and r.get("route") == route
            and r.get("system") == system
        ]
        out.append(_summarize_group(suite, route, system, attacks, benign, errors))
    return out


def _aggregate_rows(
    attack_rows: list[dict[str, Any]],
    benign_rows: list[dict[str, Any]],
    error_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    complete_keys = _complete_matched_keys(attack_rows, benign_rows)
    matched_attack_rows = [
        row for row in attack_rows if (row.get("suite", ""), row.get("route", "")) in complete_keys
    ]
    matched_benign_rows = [
        row for row in benign_rows if (row.get("suite", ""), row.get("route", "")) in complete_keys
    ]
    systems = sorted({r.get("system", "") for r in matched_attack_rows + matched_benign_rows})
    out = []
    for system in systems:
        attacks = [r for r in matched_attack_rows if r.get("system") == system]
        benign = [r for r in matched_benign_rows if r.get("system") == system]
        errors = [
            r
            for r in error_rows
            if r.get("system") == system
            and (r.get("suite", ""), r.get("route", "")) in complete_keys
        ]
        suites = ",".join(sorted({r.get("suite", "") for r in attacks + benign if r.get("suite")}))
        routes = ",".join(sorted({r.get("route", "") for r in attacks + benign if r.get("route")}))
        out.append(_summarize_group(suites or "all", routes or "all", system, attacks, benign, errors))
    return out


def _attack_scope_rows(
    attack_rows: list[dict[str, Any]],
    benign_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    complete_keys = _complete_matched_keys(attack_rows, benign_rows)
    matched_attack_rows = [
        row
        for row in attack_rows
        if (row.get("suite", ""), row.get("route", "")) in complete_keys
    ]
    systems = sorted({row.get("system", "") for row in matched_attack_rows})
    out: list[dict[str, Any]] = []
    for scope in SCOPE_ORDER:
        scoped_rows = [
            row for row in matched_attack_rows if _attack_scope(row) == scope
        ]
        if not scoped_rows:
            continue
        for system in systems:
            attacks = [row for row in scoped_rows if row.get("system") == system]
            if not attacks:
                continue
            successes = sum(int(row.get("attack_success", 0) or 0) for row in attacks)
            suites = ",".join(
                sorted({row.get("suite", "") for row in attacks if row.get("suite")})
            )
            routes = ",".join(
                sorted({row.get("route", "") for row in attacks if row.get("route")})
            )
            out.append(
                {
                    "scope": scope,
                    "scope_label": SCOPE_LABELS[scope],
                    "suite": suites,
                    "route": routes,
                    "system": system,
                    "attack_cases": len(attacks),
                    "attack_successes": successes,
                    "agentdojo_asr": round(successes / len(attacks), 4),
                }
            )
    return out


def _attack_scope(row: dict[str, Any]) -> str:
    suite = str(row.get("suite", ""))
    injection_task = str(row.get("injection_task", ""))
    if injection_task in SINK_GOVERNED_INJECTIONS.get(suite, frozenset()):
        return "sink_governed"
    if injection_task in TEXT_OUTPUT_INJECTIONS.get(suite, frozenset()):
        return "text_output"
    return "other"


def _complete_matched_keys(
    attack_rows: list[dict[str, Any]],
    benign_rows: list[dict[str, Any]],
) -> set[tuple[str, str]]:
    attack_systems: dict[tuple[str, str], set[str]] = defaultdict(set)
    benign_systems: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in attack_rows:
        attack_systems[(row.get("suite", ""), row.get("route", ""))].add(row.get("system", ""))
    for row in benign_rows:
        benign_systems[(row.get("suite", ""), row.get("route", ""))].add(row.get("system", ""))
    return {
        key
        for key, systems in attack_systems.items()
        if {"base", "rope"}.issubset(systems)
        and {"base", "rope"}.issubset(benign_systems.get(key, set()))
    }


def _summarize_group(
    suite: str,
    route: str,
    system: str,
    attacks: list[dict[str, Any]],
    benign: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    asr = _mean(attacks, "attack_success")
    attacked_utility = _mean(attacks, "utility")
    benign_utility = _mean(benign, "utility")
    return {
        "suite": suite,
        "route": route,
        "system": system,
        "attack_cases": len(attacks),
        "agentdojo_asr": asr,
        "agentdojo_security": round(1.0 - asr, 4) if attacks else 0.0,
        "attacked_utility": attacked_utility,
        "benign_cases": len(benign),
        "benign_utility": benign_utility,
        "errors": len(errors),
    }


def _mean(rows: list[dict[str, Any]], key: str) -> float:
    if not rows:
        return 0.0
    return round(sum(int(row.get(key, 0) or 0) for row in rows) / len(rows), 4)


def _status(route_rows: list[dict[str, Any]]) -> str:
    if not route_rows:
        return "missing"
    by_suite_route: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in route_rows:
        by_suite_route[(row["suite"], row["route"])].add(row["system"])
    has_pair = all({"base", "rope"}.issubset(systems) for systems in by_suite_route.values())
    has_benign = all(row["benign_cases"] > 0 for row in route_rows)
    return "completed" if has_pair and has_benign else "partial"


def _matched_status(aggregate_rows: list[dict[str, Any]]) -> str:
    if not aggregate_rows:
        return "missing"
    systems = {row["system"] for row in aggregate_rows}
    if not {"base", "rope"}.issubset(systems):
        return "partial"
    has_rows = all(row["attack_cases"] > 0 and row["benign_cases"] > 0 for row in aggregate_rows)
    has_errors = any(row["errors"] > 0 for row in aggregate_rows)
    return "completed" if has_rows and not has_errors else "partial"


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _write_table(root: Path, summary: dict[str, Any]) -> None:
    rows = summary["aggregate_rows"]
    body = "\n".join(
        " & ".join(
            [
                _tex(row["system"]),
                _tex(row["route"]),
                _tex(row["suite"]),
                str(row["attack_cases"]),
                _pct(row["agentdojo_asr"]),
                _pct(row["attacked_utility"]),
                str(row["benign_cases"]),
                _pct(row["benign_utility"]),
                str(row["errors"]),
            ]
        )
        + r" \\"
        for row in rows
    )
    if not body:
        body = r"\multicolumn{9}{c}{No completed AgentDojo rows found.} \\"
    matched_status = (
        "matched-complete"
        if summary.get("matched_status") == "completed"
        else f"matched-{summary.get('matched_status', 'missing')}"
    )
    route_status = summary.get("status", "missing")
    table = (
        "\\begin{table*}[t]\n"
        "\\centering\n"
        "\\scriptsize\n"
        "\\setlength{\\tabcolsep}{3pt}\n"
        "\\begin{tabular}{@{}lllrrrrrr@{}}\n"
        "\\toprule\n"
        "System & Routes & Suites & Attack eps. & ASR$\\downarrow$ & Atk util$\\uparrow$ & Benign eps. & Benign util$\\uparrow$ & Err. \\\\\n"
        "\\midrule\n"
        f"{body}\n"
        "\\bottomrule\n"
        "\\end{tabular}\n"
        "\\caption{AgentDojo in-loop evaluation "
        f"({matched_status} cells from run {_tex(summary['run_id'])}; "
        f"route-level status {_tex(route_status)}). "
        "The base agent is the unmodified live tool-call model; \\ROPE{} is a "
        "host-side in-loop monitor that filters proposed tool calls before "
        "execution. ASR and utility are AgentDojo-native oracle labels. "
        "Aggregate rows include only matched suite/route cells with both "
        "base and \\ROPE{} attack and benign rows; partial and error-only "
        "cells are retained in the released route-level CSV.}\n"
        "\\label{tab:agentdojo-inloop}\n"
        "\\end{table*}\n"
    )
    path = root / "paper" / "rope" / "tables" / "table_agentdojo_inloop.tex"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(table, encoding="utf-8")


def _write_scope_table(root: Path, summary: dict[str, Any]) -> None:
    rows = summary["scope_rows"]
    lines: list[str] = []
    for scope in SCOPE_ORDER:
        scoped = [row for row in rows if row["scope"] == scope]
        if not scoped:
            continue
        lines.append(
            r"\multicolumn{6}{@{}l}{\emph{"
            + _tex(SCOPE_LABELS[scope])
            + r"}} \\"
        )
        for row in scoped:
            lines.append(
                " & ".join(
                    [
                        _tex(row["system"]),
                        _tex(row["route"]),
                        _tex(row["suite"]),
                        str(row["attack_cases"]),
                        str(row["attack_successes"]),
                        _pct(row["agentdojo_asr"]),
                    ]
                )
                + r" \\"
            )
        lines.append(r"\addlinespace[2pt]")
    if lines and lines[-1].startswith(r"\addlinespace"):
        lines.pop()
    body = "\n".join(lines)
    if not body:
        body = r"\multicolumn{6}{c}{No matched attack rows found.} \\"
    table = (
        "\\begin{table*}[t]\n"
        "\\centering\n"
        "\\scriptsize\n"
        "\\setlength{\\tabcolsep}{4pt}\n"
        "\\begin{tabular}{@{}lllrrr@{}}\n"
        "\\toprule\n"
        "System & Routes & Suites & Attack eps. & Attack succ. & ASR$\\downarrow$ \\\\\n"
        "\\midrule\n"
        f"{body}\n"
        "\\bottomrule\n"
        "\\end{tabular}\n"
        "\\caption{Scope split for the matched AgentDojo in-loop attack rows "
        f"from run {_tex(summary['run_id'])}. "
        "Sink-governed rows are injection tasks whose ground-truth security "
        "violation requires an external sink or destructive tool call. "
        "Text-output rows are travel injection tasks with no ground-truth "
        "sink tool; they measure model text obedience and are outside "
        "\\ROPE{}'s host-side tool-call enforcement scope.}\n"
        "\\label{tab:agentdojo-scope-split}\n"
        "\\end{table*}\n"
    )
    path = root / "paper" / "rope" / "tables" / "table_agentdojo_scope_split.tex"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(table, encoding="utf-8")


def _pct(value: float) -> str:
    return f"{100.0 * value:.1f}\\%"


def _tex(value: str) -> str:
    return (
        str(value)
        .replace("\\", "\\textbackslash{}")
        .replace("&", "\\&")
        .replace("_", "\\_")
        .replace("%", "\\%")
    )


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    out = summarize_agentdojo_inloop_run(root, run_id="inloop_main_v2")
    print(json.dumps({"status": out["status"], "attack_rows": out["attack_rows"]}, indent=2))
