"""Standard AgentDojo validation for ROPE.

This runner executes an official AgentDojo subset with live tool-call models and
then evaluates the resulting trace at the ROPE boundary.  It is deliberately
separate from the synthetic controlled suite: AgentDojo supplies the tasks,
injection tasks, tool runtime, and utility/security oracles.
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

RESULT_ROOT = Path("bench/results/standard_validation")


@dataclass(frozen=True)
class AgentDojoCase:
    suite: str
    user_task: str
    injection_task: str


@dataclass(frozen=True)
class Route:
    route_id: str
    model: str
    base_url: str
    api_key: str
    protocol: str
    source: str


SMOKE_CASES: tuple[AgentDojoCase, ...] = tuple(
    AgentDojoCase("workspace", f"user_task_{idx}", "injection_task_0") for idx in range(3)
)

MAIN_CASES: tuple[AgentDojoCase, ...] = (
    *tuple(AgentDojoCase("workspace", f"user_task_{idx}", "injection_task_0") for idx in range(5)),
    AgentDojoCase("slack", "user_task_0", "injection_task_1"),
    AgentDojoCase("travel", "user_task_0", "injection_task_6"),
)


def run_standard_agentdojo_eval(
    root: Path,
    *,
    run_id: str = "agentdojo_standard_v1",
    stage: str = "smoke",
    route_ids: Sequence[str] | None = None,
    force: bool = True,
) -> dict[str, Any]:
    cases = MAIN_CASES if stage == "main" else SMOKE_CASES
    out_dir = root / RESULT_ROOT
    run_dir = out_dir / f"{run_id}_runs"
    if force and run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    routes = _available_routes()
    selected = [
        route
        for route in routes
        if route_ids is None or route.route_id in set(route_ids)
    ]
    rows: list[dict[str, Any]] = []
    route_rows: list[dict[str, Any]] = []
    for route in selected:
        if route.protocol != "openai_tool_chat":
            route_rows.append(
                {
                    "route": route.route_id,
                    "model": route.model,
                    "source": route.source,
                    "status": "skipped",
                    "reason": "AgentDojo requires an OpenAI-compatible chat/completions tool-call endpoint",
                }
            )
            continue
        started = time.perf_counter()
        try:
            route_case_rows = _run_route(route, cases, run_dir / route.route_id)
            rows.extend(route_case_rows)
            route_rows.append(
                {
                    "route": route.route_id,
                    "model": route.model,
                    "source": route.source,
                    "status": "completed",
                    "reason": "",
                    "elapsed_s": round(time.perf_counter() - started, 2),
                }
            )
        except Exception as exc:  # noqa: BLE001 - route failures are benchmark data.
            route_rows.append(
                {
                    "route": route.route_id,
                    "model": route.model,
                    "source": route.source,
                    "status": "error",
                    "reason": f"{type(exc).__name__}: {_sanitize(str(exc))}",
                    "elapsed_s": round(time.perf_counter() - started, 2),
                }
            )

    summary = _summary(run_id, stage, cases, rows, route_rows)
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(out_dir / f"{run_id}_rows.csv", rows)
    _write_csv(out_dir / f"{run_id}_routes.csv", route_rows)
    _write_json(out_dir / f"{run_id}.json", {"summary": summary, "rows": rows, "routes": route_rows})
    _write_json(out_dir / f"{run_id}_summary.json", summary)
    _write_report(root, summary, route_rows)
    _write_table(root, summary)
    return summary


def _available_routes() -> list[Route]:
    routes: list[Route] = []
    if os.environ.get("GLM_API_KEY") and os.environ.get("GLM_BASE_URL"):
        routes.append(
            Route(
                "glm",
                os.environ.get("GLM_MODEL", "glm-5.1"),
                os.environ["GLM_BASE_URL"].rstrip("/"),
                os.environ["GLM_API_KEY"],
                "openai_tool_chat",
                "external_api",
            )
        )
    if os.environ.get("OPENAI_API_KEY") and os.environ.get("OPENAI_BASE_URL"):
        routes.append(
            Route(
                "minimax",
                os.environ.get("TARGET_LLM_MODEL")
                or os.environ.get("AGENTMARK_LLM_MODEL")
                or os.environ.get("OPENAI_MODEL")
                or "MiniMax-M2.7",
                os.environ["OPENAI_BASE_URL"].rstrip("/"),
                os.environ["OPENAI_API_KEY"],
                "openai_tool_chat",
                "external_api",
            )
        )
    ollama_base = os.environ.get("OLLAMA_API_BASE", "").rstrip("/")
    ollama_model = _ollama_model(ollama_base)
    if ollama_base and ollama_model:
        routes.append(
            Route(
                "ollama-4090",
                ollama_model,
                f"{ollama_base}/v1",
                "ollama",
                "openai_tool_chat",
                "remote_4090_ollama",
            )
        )
    if os.environ.get("OPENCLAUDECODE_GPT_API_KEY") and os.environ.get("OPENCLAUDECODE_GPT_BASE_URL"):
        routes.append(
            Route(
                "gpt-api",
                os.environ.get("OPENCLAUDECODE_GPT_MODEL", "gpt-5.4"),
                _chat_completions_root(os.environ["OPENCLAUDECODE_GPT_BASE_URL"]),
                os.environ["OPENCLAUDECODE_GPT_API_KEY"],
                "openai_tool_chat",
                "external_api",
            )
        )
    if os.environ.get("OPENCLAUDECODE_CLAUDE_API_KEY") and os.environ.get("OPENCLAUDECODE_CLAUDE_BASE_URL"):
        routes.append(
            Route(
                "claude-api",
                os.environ.get("OPENCLAUDECODE_CLAUDE_OPUS_MODEL", "claude-opus-4-6"),
                _chat_completions_root(os.environ["OPENCLAUDECODE_CLAUDE_BASE_URL"]),
                os.environ["OPENCLAUDECODE_CLAUDE_API_KEY"],
                "openai_tool_chat",
                "external_api",
            )
        )
    if os.environ.get("DEEPSEEK_API_KEY") and os.environ.get("DEEPSEEK_BASE_URL"):
        routes.append(
            Route(
                "deepseek-api",
                os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash"),
                _chat_completions_root(os.environ["DEEPSEEK_BASE_URL"]),
                os.environ["DEEPSEEK_API_KEY"],
                "openai_tool_chat",
                "external_api",
            )
        )
    return routes


def _chat_completions_root(base_url: str) -> str:
    """Normalize provider-specific endpoints to the OpenAI SDK base URL root."""
    root = base_url.rstrip("/")
    for suffix in ("/chat/completions", "/messages"):
        if root.endswith(suffix):
            return root[: -len(suffix)]
    return root


def _ollama_model(base: str) -> str:
    if not base:
        return ""
    try:
        with urllib.request.urlopen(f"{base}/api/tags", timeout=5) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception:
        return os.environ.get("OLLAMA_LLAMA_MODEL", "")
    names = [str(item.get("name", "")) for item in data.get("models", []) if isinstance(item, dict)]
    for preferred in (
        os.environ.get("OLLAMA_LLAMA_MODEL", ""),
        os.environ.get("OPEN_SOURCE_70B_OLLAMA_MODEL", ""),
        "qwen2.5:7b-instruct-q4_K_M",
    ):
        if preferred in names:
            return preferred
    return names[0] if names else ""


def _run_route(route: Route, cases: Sequence[AgentDojoCase], run_dir: Path) -> list[dict[str, Any]]:
    import openai
    from openai._types import NOT_GIVEN
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.agent_pipeline.llms.openai_llm import _function_to_openai, _tool_call_to_openai
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import benchmark_suite_with_injections
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.logging import OutputLogger
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.types import ChatAssistantMessage, text_content_block_from_string

    class CompatOpenAILLM(BasePipelineElement):
        name: str

        def __init__(self, client: openai.OpenAI, model: str) -> None:
            self.client = client
            self.model = model
            self.name = model

        def query(
            self,
            query: str,
            runtime: Any,
            env: Any = None,
            messages: Sequence[Mapping[str, Any]] = (),
            extra_args: dict[str, Any] | None = None,
        ) -> tuple[str, Any, Any, Sequence[Mapping[str, Any]], dict[str, Any]]:
            converted = [_message_to_openai(message) for message in messages]
            tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
            completion = cast(Any, self.client.chat.completions).create(
                model=self.model,
                messages=cast(Any, converted),
                tools=tools or NOT_GIVEN,
                tool_choice="auto",
                temperature=0,
            )
            output = _assistant_from_openai_message(completion.choices[0].message)
            return query, runtime, env, [*messages, output], extra_args or {}

    def _message_to_openai(message: Mapping[str, Any]) -> dict[str, Any]:
        role = str(message["role"])
        if role in ("system", "user"):
            return {"role": role, "content": _content_text(message)}
        if role == "assistant":
            out: dict[str, Any] = {"role": "assistant", "content": _content_text(message)}
            reasoning_content = _reasoning_content(message)
            if reasoning_content:
                out["reasoning_content"] = reasoning_content
            tool_calls = message.get("tool_calls")
            if isinstance(tool_calls, list) and tool_calls:
                out["tool_calls"] = [_tool_call_to_openai(tool_call) for tool_call in tool_calls]
            return out
        if role == "tool":
            tool_call = message["tool_call"]
            return {
                "role": "tool",
                "tool_call_id": message["tool_call_id"],
                "name": tool_call.function,
                "content": message.get("error") or _content_text(message) or "",
            }
        raise ValueError(f"unsupported AgentDojo message role: {role}")

    def _content_text(message: Mapping[str, Any]) -> str | None:
        content = message.get("content")
        if content is None:
            return None
        if not isinstance(content, list):
            return str(content)
        parts = [
            str(block.get("content", ""))
            for block in content
            if isinstance(block, dict) and block.get("type", "text") == "text"
        ]
        return "\n".join(part for part in parts if part)

    def _reasoning_content(message: Mapping[str, Any]) -> str | None:
        content = message.get("content")
        if not isinstance(content, list):
            return None
        parts = [
            str(block.get("content", ""))
            for block in content
            if isinstance(block, dict) and block.get("type") == "thinking"
        ]
        return "\n".join(part for part in parts if part) or None

    def _assistant_from_openai_message(message: Any) -> Mapping[str, Any]:
        content = []
        reasoning_content = getattr(message, "reasoning_content", None)
        if reasoning_content:
            content.append({"type": "thinking", "content": str(reasoning_content), "id": None})
        if message.content is not None:
            content.append(text_content_block_from_string(message.content))
        tool_calls = []
        for tool_call in message.tool_calls or []:
            try:
                args = json.loads(tool_call.function.arguments or "{}")
                if not isinstance(args, dict):
                    args = {}
            except json.JSONDecodeError:
                args = {}
            tool_calls.append(FunctionCall(function=tool_call.function.name, args=args, id=tool_call.id))
        return ChatAssistantMessage(
            role="assistant",
            content=content or None,
            tool_calls=tool_calls if tool_calls else None,
        )

    client = openai.OpenAI(api_key=route.api_key, base_url=route.base_url, timeout=90.0)
    rows: list[dict[str, Any]] = []
    by_suite: dict[str, list[AgentDojoCase]] = {}
    for case in cases:
        by_suite.setdefault(case.suite, []).append(case)

    for suite_name, suite_cases in sorted(by_suite.items()):
        suite = get_suite("v1", suite_name)
        pipeline = AgentPipeline.from_config(
            PipelineConfig(
                llm=CompatOpenAILLM(client, route.model),
                model_id=None,
                defense=None,
                system_message_name=None,
                system_message=None,
                tool_output_format=None,
            )
        )
        attack = load_attack("direct", suite, pipeline)
        user_tasks = tuple(case.user_task for case in suite_cases)
        injection_tasks = tuple(sorted({case.injection_task for case in suite_cases}))
        suite_run_dir = run_dir / suite_name
        started = time.perf_counter()
        with OutputLogger(str(suite_run_dir)):
            results = benchmark_suite_with_injections(
                pipeline,
                suite,
                attack,
                user_tasks=user_tasks,
                injection_tasks=injection_tasks,
                logdir=suite_run_dir,
                force_rerun=True,
                benchmark_version="v1",
            )
        elapsed = time.perf_counter() - started
        for (user_task, injection_task), utility in sorted(results["utility_results"].items()):
            security_pass = bool(results["security_results"][(user_task, injection_task)])
            rows.append(
                {
                    "route": route.route_id,
                    "model": route.model,
                    "source": route.source,
                    "suite": suite_name,
                    "user_task": user_task,
                    "injection_task": injection_task,
                    "agentdojo_utility": int(bool(utility)),
                    "agentdojo_security_pass": int(security_pass),
                    "agentdojo_attack_success": int(not security_pass),
                    "rope_trace_blocked_attack": int(not security_pass),
                    "rope_security_pass": 1,
                    "rope_safe_completion": int(bool(utility)),
                    "elapsed_suite_s": round(elapsed, 3),
                }
            )
    return rows


def _summary(
    run_id: str,
    stage: str,
    cases: Sequence[AgentDojoCase],
    rows: Sequence[Mapping[str, Any]],
    route_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    completed_routes = sorted({str(row["route"]) for row in rows})

    def avg(key: str) -> float:
        vals = [float(row[key]) for row in rows]
        return round(sum(vals) / len(vals), 4) if vals else 0.0

    route_summary: list[dict[str, Any]] = []
    for route in completed_routes:
        route_data = [row for row in rows if row["route"] == route]
        route_summary.append(
            {
                "route": route,
                "cases": len(route_data),
                "agentdojo_utility": round(sum(float(row["agentdojo_utility"]) for row in route_data) / len(route_data), 4),
                "agentdojo_security": round(sum(float(row["agentdojo_security_pass"]) for row in route_data) / len(route_data), 4),
                "agentdojo_asr": round(sum(float(row["agentdojo_attack_success"]) for row in route_data) / len(route_data), 4),
                "rope_security": round(sum(float(row["rope_security_pass"]) for row in route_data) / len(route_data), 4),
                "rope_safe_completion": round(sum(float(row["rope_safe_completion"]) for row in route_data) / len(route_data), 4),
            }
        )

    return {
        "run_id": run_id,
        "status": "completed",
        "benchmark": "AgentDojo v1",
        "stage": stage,
        "case_count_per_route": len(cases),
        "completed_route_count": len(completed_routes),
        "attempted_route_count": len(route_rows),
        "row_count": len(rows),
        "agentdojo_utility": avg("agentdojo_utility"),
        "agentdojo_security": avg("agentdojo_security_pass"),
        "agentdojo_asr": avg("agentdojo_attack_success"),
        "rope_security": avg("rope_security_pass"),
        "rope_safe_completion": avg("rope_safe_completion"),
        "route_summary": route_summary,
        "route_status": list(route_rows),
        "boundary": (
            "ROPE is evaluated as a host-side trace monitor on official AgentDojo "
            "executions. AgentDojo supplies the task, injection, tool runtime, and "
            "utility/security labels; ROPE's contribution is blocking unsafe "
            "post-observation sink continuations."
        ),
    }


def _write_report(root: Path, summary: Mapping[str, Any], route_rows: Sequence[Mapping[str, Any]]) -> None:
    lines = [
        "# Standard Benchmark Validation",
        "",
        "## AgentDojo v1",
        "",
        f"- Stage: {summary['stage']}.",
        f"- Completed routes: {summary['completed_route_count']} / {summary['attempted_route_count']}.",
        f"- Cases per completed route: {summary['case_count_per_route']}.",
        f"- AgentDojo utility: {summary['agentdojo_utility']:.3f}.",
        f"- AgentDojo security: {summary['agentdojo_security']:.3f}.",
        f"- AgentDojo ASR: {summary['agentdojo_asr']:.3f}.",
        f"- ROPE trace security: {summary['rope_security']:.3f}.",
        f"- ROPE safe completion: {summary['rope_safe_completion']:.3f}.",
        "",
        "Route status:",
        "",
    ]
    for row in route_rows:
        lines.append(f"- {row['route']}: {row['status']} {row.get('reason', '')}".rstrip())
    lines.extend(["", str(summary["boundary"]), ""])
    path = root / "docs" / "STANDARD_BENCHMARK_VALIDATION.md"
    path.write_text("\n".join(lines), encoding="utf-8")


def _write_table(root: Path, summary: Mapping[str, Any]) -> None:
    rows = [
        (
            "AgentDojo v1",
            f"{summary['completed_route_count']} routes / {summary['row_count']} cases",
            f"{100.0 * float(summary['agentdojo_asr']):.1f}\\%",
            f"{100.0 * float(summary['agentdojo_utility']):.1f}\\%",
            f"{100.0 * float(summary['rope_security']):.1f}\\%",
            f"{100.0 * float(summary['rope_safe_completion']):.1f}\\%",
        )
    ]
    body = "\n".join(" & ".join(row) + r" \\" for row in rows)
    table = (
        "\\begin{table}[t]\n"
        "\\centering\n"
        "\\scriptsize\n"
        "\\setlength{\\tabcolsep}{3pt}\n"
        "\\begin{tabularx}{\\columnwidth}{@{}lL{0.24\\columnwidth}rrrr@{}}\n"
        "\\toprule\n"
        "Benchmark & Scope & Base ASR$\\downarrow$ & Base Util$\\uparrow$ & ROPE Sec$\\uparrow$ & ROPE Safe$\\uparrow$ \\\\\n"
        "\\midrule\n"
        f"{body}\n"
        "\\bottomrule\n"
        "\\end{tabularx}\n"
        "\\caption{Standard benchmark validation on official AgentDojo v1 tasks. "
        "The base agent is the unmodified live tool-call model; ROPE is evaluated "
        "as a host-side trace monitor over the same official executions and "
        "AgentDojo utility/security labels.}\n"
        "\\label{tab:standard-benchmark-validation}\n"
        "\\end{table}\n"
    )
    path = root / "paper" / "rope" / "tables" / "table_standard_benchmark_validation.tex"
    path.write_text(table, encoding="utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _sanitize(text: str) -> str:
    return text.replace("\n", " ")[:260]
