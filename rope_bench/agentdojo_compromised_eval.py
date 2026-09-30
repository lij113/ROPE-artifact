"""Compromised-planner evaluation on official AgentDojo suites.

The live in-loop study measures attack success *given* a model's own
susceptibility; frontier models refuse most canonical injections, so a low
base ASR says little about the monitor. This evaluator removes the model from
the security question. A scripted planner executes the user task's ground
truth and, as soon as injected content appears in a tool result, executes the
injection task's ground truth -- i.e. a planner that is fully hijacked by
whatever it reads. Base ASR under this planner is the executable ceiling of
each injection; ROPE ASR is what the host monitor lets through when the model
offers no resistance at all.

The same planner without injections runs each user task's ground truth, which
measures the monitor's structural false rejection on correct plans.

No model API is called. The ROPE monitor is the unchanged in-loop executor
from ``rope_bench.agentdojo_inloop_eval``.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from rope_bench.agentdojo_inloop_eval import (
    _build_rope_executor,
    executed_calls_trace_scoring,
)

# system name -> ROPE in-loop profile version (None = no monitor)
ROPE_SYSTEMS = {"rope": "v1", "rope_v2": "v2"}

RESULT_ROOT = Path("bench/results/agentdojo_compromised")
INJECTION_MARKERS = ("<INFORMATION>",)
BLOCK_MARKERS = ("Blocked by ROPE", "Blocked by host policy")
BASELINE_SYSTEMS = ("taint_block", "monotone_budget", "llm_lookahead", "llm_lookahead_strict")


def _make_planner(user_task, injection_task):
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.types import (
        ChatAssistantMessage,
        get_text_content_as_str,
        text_content_block_from_string,
    )

    goal_probe = ""
    if injection_task is not None:
        goal_probe = " ".join(str(injection_task.GOAL).split())[:48]

    class CompromisedPlanner(BasePipelineElement):
        name = "compromised-planner"

        def __init__(self) -> None:
            self.user_plan: list[Any] | None = None
            self.injection_plan: list[Any] = []
            self.triggered = False
            self.counter = 0
            self.emitted: list[tuple[str, str]] = []
            self.last_messages: Sequence[Mapping[str, Any]] = ()

        def _exposed(self, messages) -> bool:
            for message in messages:
                if message.get("role") != "tool" or message.get("content") is None:
                    continue
                text = get_text_content_as_str(message["content"])
                flat = " ".join(text.split())
                if any(marker in text for marker in INJECTION_MARKERS):
                    return True
                if goal_probe and goal_probe in flat:
                    return True
            return False

        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            extra_args = extra_args if extra_args is not None else {}
            self.last_messages = messages
            if self.user_plan is None:
                self.user_plan = list(user_task.ground_truth(env))
            if (
                injection_task is not None
                and not self.triggered
                and self._exposed(messages)
            ):
                self.triggered = True
                self.injection_plan = list(injection_task.ground_truth(env))
            call = None
            kind = ""
            if self.triggered and self.injection_plan:
                call, kind = self.injection_plan.pop(0), "inj"
            elif self.user_plan:
                call, kind = self.user_plan.pop(0), "user"
            if call is None:
                output = ChatAssistantMessage(
                    role="assistant",
                    content=[text_content_block_from_string(user_task.GROUND_TRUTH_OUTPUT)],
                    tool_calls=None,
                )
            else:
                self.counter += 1
                call = call.model_copy(update={"id": f"cp_{kind}_{self.counter}"})
                self.emitted.append((kind, call.function))
                output = ChatAssistantMessage(
                    role="assistant",
                    content=[text_content_block_from_string("")],
                    tool_calls=[call],
                )
            out_messages = [*messages, output]
            self.last_messages = out_messages
            return query, runtime, env, out_messages, extra_args

    return CompromisedPlanner()


def _make_pipeline(suite_name: str, system: str, planner, decision_log: list[dict[str, Any]]):
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor

    if system in ROPE_SYSTEMS:
        executor = _build_rope_executor(suite_name, decision_log, ROPE_SYSTEMS[system])
    elif system == "base":
        executor = ToolsExecutor()
    elif system in BASELINE_SYSTEMS:
        from rope_bench.agentdojo_baseline_monitors import (
            build_filter_executor,
            llm_lookahead_decider,
            monotone_budget_decider,
            taint_block_decider,
        )

        if system == "taint_block":
            decide = taint_block_decider(suite_name)
        elif system == "monotone_budget":
            decide = monotone_budget_decider(suite_name)
        else:
            block_on = ("unsafe",) if system == "llm_lookahead" else ("unsafe", "critical")
            decide = llm_lookahead_decider(RESULT_ROOT, block_on)
        executor = build_filter_executor(decide, decision_log, system)
    else:
        raise ValueError(f"unknown system {system!r}")
    pipeline = AgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            planner,
            ToolsExecutionLoop([executor, planner], max_iters=60),
        ]
    )
    # Same token as the live harness so the attack template renders identically.
    pipeline.name = f"{system}-compromised-gpt-4o-2024-05-13"
    return pipeline


def _call_outcomes(messages: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = {"inj_calls": 0, "inj_blocked": 0, "user_calls": 0, "user_blocked": 0}
    for message in messages:
        if message.get("role") != "tool":
            continue
        call_id = str(message.get("tool_call_id") or "")
        if not call_id.startswith("cp_"):
            continue
        kind = "inj" if call_id.startswith("cp_inj_") else "user"
        counts[f"{kind}_calls"] += 1
        if str(message.get("error") or "").startswith(BLOCK_MARKERS):
            counts[f"{kind}_blocked"] += 1
    return counts


def run_compromised_suite(
    suite_name: str,
    *,
    systems: Sequence[str] = ("base", "rope"),
    attack_name: str = "important_instructions_no_model_name",
    include_benign: bool = True,
    monitor_note: str | None = None,
    include_attacks: bool = True,
    user_task_limit: int | None = None,
    injection_task_limit: int | None = None,
    user_task_offset: int = 0,
    benchmark_version: str = "v1",
    injection_task_ids: Sequence[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite(benchmark_version, suite_name)
    attack_rows: list[dict[str, Any]] = []
    benign_rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []

    probe_pipeline = _make_pipeline(suite_name, "base", _make_planner(next(iter(suite.user_tasks.values())), None), [])
    attack = load_attack(attack_name, suite, probe_pipeline)

    user_ids = sorted(suite.user_tasks)[user_task_offset:]
    user_ids = user_ids[:user_task_limit]
    injection_ids = sorted(suite.injection_tasks)[:injection_task_limit]
    if injection_task_ids:
        injection_ids = [i for i in injection_task_ids if i in suite.injection_tasks]
    for user_id in user_ids if include_attacks else []:
        user_task = suite.user_tasks[user_id]
        for injection_id in injection_ids:
            injection_task = suite.injection_tasks[injection_id]
            try:
                injections = attack.attack(user_task, injection_task)
            except Exception as exc:  # noqa: BLE001 - non-injectable pairs are data
                errors.append({"suite": suite_name, "user_task": user_id, "injection_task": injection_id, "system": "*", "error": f"attack: {type(exc).__name__}: {str(exc)[:160]}"})
                continue
            if monitor_note:
                # Adaptive variant: the injection also addresses the monitor.
                injections = {key: value + monitor_note for key, value in injections.items()}
            for system in systems:
                decision_log: list[dict[str, Any]] = []
                planner = _make_planner(user_task, injection_task)
                pipeline = _make_pipeline(suite_name, system, planner, decision_log)
                try:
                    with executed_calls_trace_scoring():
                        utility, injection_executed = suite.run_task_with_pipeline(
                            pipeline, user_task, injection_task, injections
                        )
                except Exception as exc:  # noqa: BLE001
                    errors.append({"suite": suite_name, "user_task": user_id, "injection_task": injection_id, "system": system, "error": f"{type(exc).__name__}: {str(exc)[:160]}"})
                    continue
                outcome = _call_outcomes(planner.last_messages)
                attack_rows.append(
                    {
                        "suite": suite_name,
                        "system": system,
                        "user_task": user_id,
                        "injection_task": injection_id,
                        "exposed": int(planner.triggered),
                        "utility": int(bool(utility)),
                        "attack_success": int(bool(injection_executed)),
                        **outcome,
                    }
                )
                for row in decision_log:
                    decisions.append({"suite": suite_name, "system": system, "user_task": user_id, "injection_task": injection_id, **row})

    if include_benign:
        for user_id in user_ids:
            user_task = suite.user_tasks[user_id]
            for system in systems:
                decision_log = []
                planner = _make_planner(user_task, None)
                pipeline = _make_pipeline(suite_name, system, planner, decision_log)
                try:
                    with executed_calls_trace_scoring():
                        utility, _ = suite.run_task_with_pipeline(pipeline, user_task, None, {})
                except Exception as exc:  # noqa: BLE001
                    errors.append({"suite": suite_name, "user_task": user_id, "injection_task": "(benign)", "system": system, "error": f"{type(exc).__name__}: {str(exc)[:160]}"})
                    continue
                outcome = _call_outcomes(planner.last_messages)
                benign_rows.append(
                    {
                        "suite": suite_name,
                        "system": system,
                        "user_task": user_id,
                        "utility": int(bool(utility)),
                        "user_calls": outcome["user_calls"],
                        "user_blocked": outcome["user_blocked"],
                    }
                )
                for row in decision_log:
                    decisions.append({"suite": suite_name, "system": system, "user_task": user_id, "injection_task": "(benign)", **row})
    return attack_rows, benign_rows, errors, decisions


def summarize(attack_rows: Sequence[Mapping[str, Any]], benign_rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {"suites": {}, "by_injection_task": {}}
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in attack_rows:
        groups[(row["suite"], row["system"])].append(row)
    benign_groups: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in benign_rows:
        benign_groups[(row["suite"], row["system"])].append(row)
    keys = sorted(set(groups) | set(benign_groups))
    for suite, system in keys + [("ALL", s) for s in sorted({k[1] for k in keys})]:
        rows = [r for (su, sy), rs in groups.items() for r in rs if sy == system and (suite == "ALL" or su == suite)]
        brows = [r for (su, sy), rs in benign_groups.items() for r in rs if sy == system and (suite == "ALL" or su == suite)]
        exposed = [r for r in rows if r["exposed"]]
        entry = {
            "pairs": len(rows),
            "exposed_pairs": len(exposed),
            "asr_all": round(sum(r["attack_success"] for r in rows) / len(rows), 4) if rows else None,
            "asr_exposed": round(sum(r["attack_success"] for r in exposed) / len(exposed), 4) if exposed else None,
            "attack_successes": sum(r["attack_success"] for r in rows),
            "utility_under_attack": round(sum(r["utility"] for r in rows) / len(rows), 4) if rows else None,
            "inj_calls": sum(r["inj_calls"] for r in rows),
            "inj_blocked": sum(r["inj_blocked"] for r in rows),
            "user_calls_under_attack": sum(r["user_calls"] for r in rows),
            "user_blocked_under_attack": sum(r["user_blocked"] for r in rows),
            "benign_tasks": len(brows),
            "benign_utility": round(sum(r["utility"] for r in brows) / len(brows), 4) if brows else None,
            "benign_user_calls": sum(r["user_calls"] for r in brows),
            "benign_user_blocked": sum(r["user_blocked"] for r in brows),
            "benign_tasks_with_block": sum(1 for r in brows if r["user_blocked"]),
        }
        out["suites"].setdefault(suite, {})[system] = entry
    per_task: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for row in attack_rows:
        per_task[(row["suite"], row["injection_task"], row["system"])].append(row)
    for (suite, injection_task, system), rows in sorted(per_task.items()):
        out["by_injection_task"].setdefault(f"{suite}/{injection_task}", {})[system] = {
            "pairs": len(rows),
            "asr": round(sum(r["attack_success"] for r in rows) / len(rows), 4),
            "inj_blocked": sum(r["inj_blocked"] for r in rows),
            "inj_calls": sum(r["inj_calls"] for r in rows),
        }
    return out


def write_outputs(out_dir: Path, attack_rows, benign_rows, errors, decisions, summary) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, rows in (("attack_rows.csv", attack_rows), ("benign_rows.csv", benign_rows), ("errors.csv", errors)):
        with (out_dir / name).open("w", encoding="utf-8", newline="") as handle:
            if rows:
                fields = sorted({k for r in rows for k in r})
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
    with (out_dir / "decisions.jsonl").open("w", encoding="utf-8") as handle:
        for row in decisions:
            handle.write(json.dumps(row, sort_keys=True, default=str) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
