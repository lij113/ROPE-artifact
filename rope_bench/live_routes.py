"""Optional live route probes for external APIs and the 4090 Ollama host.

These probes are deliberately separate from the deterministic trace suites so
paid APIs or remote GPU availability cannot affect reproducible metrics.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXTERNAL_ROUTES = (
    {
        "route_id": "gpt",
        "base_env": "OPENCLAUDECODE_GPT_BASE_URL",
        "key_env": "OPENCLAUDECODE_GPT_API_KEY",
        "model_env": "OPENCLAUDECODE_GPT_MODEL",
        "default_model": "gpt-5.4",
    },
    {
        "route_id": "claude",
        "base_env": "OPENCLAUDECODE_CLAUDE_BASE_URL",
        "key_env": "OPENCLAUDECODE_CLAUDE_API_KEY",
        "model_env": "OPENCLAUDECODE_CLAUDE_OPUS_MODEL",
        "default_model": "claude-opus-4-6",
    },
    {
        "route_id": "deepseek",
        "base_env": "DEEPSEEK_BASE_URL",
        "key_env": "DEEPSEEK_API_KEY",
        "model_env": "DEEPSEEK_MODEL",
        "default_model": "deepseek-v4-flash",
    },
    {
        "route_id": "glm",
        "base_env": "GLM_BASE_URL",
        "key_env": "GLM_API_KEY",
        "model_env": "GLM_MODEL",
        "default_model": "glm-5.1",
    },
)

OLLAMA_PORTS = (11435, 11436, 11437, 11438, 11439, 11440)


def collect_live_route_health(*, probe_external: bool = False) -> dict[str, Any]:
    report = {
        "run_id": "live_route_probe",
        "date": "2026-05-25",
        "external_probe_enabled": probe_external,
        "external_routes": [
            _probe_external_route(route) if probe_external else _describe_external_route(route)
            for route in EXTERNAL_ROUTES
        ],
        "local_ollama": [_probe_ollama_port(port) for port in OLLAMA_PORTS],
        "remote_4090": _probe_remote_4090(),
    }
    return report


def write_live_route_report(root: Path, *, probe_external: bool = False) -> dict[str, Any]:
    result = collect_live_route_health(probe_external=probe_external)
    out = root / "bench" / "results" / "live_routes" / "live_routes.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _describe_external_route(route: dict[str, str]) -> dict[str, Any]:
    base = os.environ.get(route["base_env"], "")
    key_present = bool(os.environ.get(route["key_env"]))
    return {
        "route_id": route["route_id"],
        "url": _resolved_url(base) if base else "",
        "model": os.environ.get(route["model_env"], route["default_model"]),
        "key_env": route["key_env"],
        "key_present": key_present,
        "status": "configured" if base and key_present else "missing_config",
    }


def _probe_external_route(route: dict[str, str]) -> dict[str, Any]:
    base = os.environ.get(route["base_env"], "")
    key = os.environ.get(route["key_env"], "")
    url = _resolved_url(base) if base else ""
    model = os.environ.get(route["model_env"], route["default_model"])
    result = _describe_external_route(route)
    if not url or not key:
        return result
    payload, headers = _payload_for(url, key, model)
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            raw = response.read().decode("utf-8", errors="replace")
            json.loads(raw)
            result.update(
                {
                    "status": "ok",
                    "http_status": response.status,
                    "latency_ms": round((time.perf_counter() - start) * 1000, 1),
                }
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        result.update(
            {
                "status": "http_error",
                "http_status": exc.code,
                "latency_ms": round((time.perf_counter() - start) * 1000, 1),
                "error": _sanitize_error(body),
            }
        )
    except Exception as exc:  # noqa: BLE001 - health reports should not crash.
        result.update(
            {
                "status": "error",
                "latency_ms": round((time.perf_counter() - start) * 1000, 1),
                "error": f"{type(exc).__name__}: {_sanitize_error(str(exc))}",
            }
        )
    return result


def _probe_ollama_port(port: int) -> dict[str, Any]:
    url = f"http://127.0.0.1:{port}/api/tags"
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=8) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
            return {
                "port": port,
                "status": "ok",
                "latency_ms": round((time.perf_counter() - start) * 1000, 1),
                "models": [item.get("name") for item in data.get("models", [])][:8],
            }
    except Exception as exc:  # noqa: BLE001
        return {
            "port": port,
            "status": "error",
            "latency_ms": round((time.perf_counter() - start) * 1000, 1),
            "error": _sanitize_error(str(exc)),
        }


def _probe_remote_4090() -> dict[str, Any]:
    host = os.environ.get("OLLAMA_REMOTE_SSH_HOST", "my-server-10001")
    command = (
        "echo HOST=$(hostname); "
        "if command -v nvidia-smi >/dev/null; then "
        "nvidia-smi --query-gpu=index,name,memory.total,memory.used,utilization.gpu "
        "--format=csv,noheader; else echo NO_NVIDIA_SMI; fi; "
        "if command -v ollama >/dev/null; then ollama list 2>&1 | head -20; "
        "else echo NO_OLLAMA; fi"
    )
    try:
        completed = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, command],
            check=False,
            text=True,
            capture_output=True,
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        return {"host": host, "status": "error", "error": _sanitize_error(str(exc))}
    stdout = completed.stdout.strip().splitlines()
    gpu_lines = [line for line in stdout if "NVIDIA" in line]
    ollama_up = any(line.startswith("NAME") for line in stdout)
    return {
        "host": host,
        "status": "ok" if completed.returncode == 0 else "error",
        "ssh_returncode": completed.returncode,
        "gpu_count": len(gpu_lines),
        "gpu_lines": gpu_lines,
        "ollama_available": ollama_up,
        "stderr": _sanitize_error(completed.stderr.strip()),
    }


def _resolved_url(base: str) -> str:
    stripped = base.rstrip("/")
    if stripped.endswith("/messages") or stripped.endswith("/chat/completions"):
        return stripped
    return f"{stripped}/chat/completions"


def _payload_for(url: str, key: str, model: str) -> tuple[dict[str, Any], dict[str, str]]:
    if url.endswith("/messages"):
        return (
            {
                "model": model,
                "max_tokens": 4,
                "system": "Reply OK only.",
                "messages": [{"role": "user", "content": "ping"}],
                "temperature": 0,
            },
            {
                "Authorization": f"Bearer {key}",
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
        )
    return (
        {
            "model": model,
            "messages": [{"role": "user", "content": "Reply OK only."}],
            "temperature": 0,
            "max_tokens": 4,
        },
        {"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )


def _sanitize_error(text: str) -> str:
    cleaned = text.replace("\n", " ")[:320]
    for marker in ("sk-", "ghp_"):
        index = cleaned.find(marker)
        if index >= 0:
            end = index + len(marker)
            while end < len(cleaned) and not cleaned[end].isspace():
                end += 1
            cleaned = cleaned[:index] + f"{marker}<redacted>" + cleaned[end:]
    return cleaned
