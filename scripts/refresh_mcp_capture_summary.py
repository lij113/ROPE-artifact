#!/usr/bin/env python3
"""Refresh paper-v1 MCP summary/profile/table from captured server traces."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.mcp_capture import _profile_draft, load_server_config  # noqa: E402


def main() -> None:
    config_path = ROOT / "bench" / "mcp_servers" / "paper_v1" / "servers.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    output_root = ROOT / config["output_root"]
    profile_output = ROOT / config["profile_output"]
    results: list[dict[str, object]] = []
    profiles: list[dict[str, object]] = []
    for server in load_server_config(config_path):
        server_dir = output_root / server.server_id
        summary_path = server_dir / "summary.json"
        if summary_path.exists():
            result = json.loads(summary_path.read_text(encoding="utf-8"))
        else:
            result = {
                "server_id": server.server_id,
                "category": server.category,
                "status": "skipped_missing_env" if server.requires_env else "missing_trace",
                "missing_env": list(server.requires_env),
                "tool_count": 0,
                "call_count": 0,
            }
            server_dir.mkdir(parents=True, exist_ok=True)
            summary_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        tools_path = server_dir / "tools_list.json"
        if tools_path.exists():
            tools = json.loads(tools_path.read_text(encoding="utf-8")).get("result", {}).get("tools", [])
            call_records = _existing_call_records(server_dir)
            if tools and call_records and result.get("status") != "captured":
                result = {
                    "server_id": server.server_id,
                    "category": server.category,
                    "status": "captured",
                    "tool_count": len(tools),
                    "call_count": len(call_records),
                    "calls": call_records,
                    "tools_list_path": str(tools_path),
                    "recovered_from_existing_trace": True,
                }
                summary_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
            for tool in tools:
                if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                    profiles.append(_profile_draft(server, tool))
        results.append(result)
    profile_report = {
        "version": "paper_v1_mcp_capture",
        "source": "bench/mcp_servers/paper_v1/servers.json",
        "profiles": profiles,
        "trust_note": "Captured server annotations are profile drafts only; ROPE treats them as server hints until host-reviewed.",
    }
    profile_output.parent.mkdir(parents=True, exist_ok=True)
    profile_output.write_text(json.dumps(profile_report, indent=2, sort_keys=True) + "\n")
    summary = {
        "run_id": "paper_v1_mcp_capture",
        "config": "bench/mcp_servers/paper_v1/servers.json",
        "servers": results,
        "captured_servers": sum(1 for row in results if row["status"] == "captured"),
        "skipped_servers": sum(1 for row in results if str(row["status"]).startswith("skipped")),
        "failed_servers": sum(1 for row in results if row["status"] == "failed"),
        "profile_output": config["profile_output"],
    }
    (output_root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    _write_capture_table(results)
    sinks = Counter(profile["sink"] for profile in profiles)
    print(
        json.dumps(
            {
                "captured_servers": summary["captured_servers"],
                "skipped_servers": summary["skipped_servers"],
                "profiles": len(profiles),
                "sinks": dict(sorted(sinks.items())),
            },
            sort_keys=True,
        )
    )


def _write_capture_table(results: list[dict[str, object]]) -> None:
    table = ROOT / "paper" / "rope" / "tables" / "table_paper_v1_mcp_capture.tex"
    labels = {
        "filesystem": "Filesystem",
        "memory": "Memory",
        "git": "Git",
        "fetch": "Fetch",
        "sqlite": "SQLite",
        "github": "GitHub",
        "slack": "Slack",
        "notion": "Notion",
        "google_drive": "Google Drive",
        "playwright_browser": "Playwright",
        "discord": "Discord",
    }
    lines = [
        "\\begin{table}[t]",
        "\\centering",
        "\\small",
        "\\begin{tabular}{lrrl}",
        "\\toprule",
        "MCP server & Tools & Calls & Status \\\\",
        "\\midrule",
    ]
    for row in results:
        server_id = str(row["server_id"])
        status = str(row["status"]).replace("_", "\\_")
        lines.append(
            f"{labels.get(server_id, server_id)} & {row.get('tool_count', 0)} & {row.get('call_count', 0)} & {status} \\\\"
        )
    lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular}",
            "\\caption{Real MCP stdio server capture for the deployment study. "
            "Google Drive includes a personal-OAuth write probe; Playwright covers browser "
            "public-web behavior. Captured profiles are treated as server hints until host review.}",
            "\\label{tab:paper-v1-mcp-capture}",
            "\\end{table}",
            "",
        ]
    )
    table.write_text("\n".join(lines), encoding="utf-8")


def _existing_call_records(server_dir: Path) -> list[dict[str, object]]:
    calls_dir = server_dir / "calls"
    if not calls_dir.exists():
        return []
    records = []
    for path in sorted(calls_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        request = data.get("request", {})
        response = data.get("response", {})
        result = response.get("result", {})
        records.append(
            {
                "name": request.get("name", path.stem),
                "ok": "error" not in response,
                "has_error": bool(result.get("isError", False) or "error" in response),
            }
        )
    return records


if __name__ == "__main__":
    main()
