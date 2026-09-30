#!/usr/bin/env python3
"""Minimal Discord MCP adapter for disposable channel capture."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


API_ROOT = "https://discord.com/api/v10"


def _tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "discord_get_channel",
            "description": "Read Discord channel metadata.",
            "annotations": {"readOnlyHint": True},
            "inputSchema": {
                "type": "object",
                "properties": {"channel_id": {"type": "string"}},
                "required": ["channel_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "discord_list_messages",
            "description": "Read recent Discord channel messages.",
            "annotations": {"readOnlyHint": True},
            "inputSchema": {
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string"},
                    "limit": {"type": "integer", "default": 5},
                },
                "required": ["channel_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "discord_post_message",
            "description": "Post a small message to a Discord channel.",
            "annotations": {"readOnlyHint": False},
            "inputSchema": {
                "type": "object",
                "properties": {
                    "channel_id": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["channel_id", "content"],
                "additionalProperties": False,
            },
        },
    ]


def _headers() -> dict[str, str]:
    token = os.environ["DISCORD_BOT_TOKEN"]
    return {
        "Authorization": f"Bot {token}",
        "Content-Type": "application/json",
        "User-Agent": "ROPE-MCP-Capture/0.1",
    }


def _request(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{API_ROOT}{path}",
        data=data,
        headers=_headers(),
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(raw)
        except json.JSONDecodeError:
            detail = {"message": raw[:240]}
        return {
            "status": "discord_api_error",
            "http_status": exc.code,
            "message": str(detail.get("message", "discord_api_error"))[:240],
        }


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    channel_id = arguments["channel_id"]
    if name == "discord_get_channel":
        result = _request(f"/channels/{channel_id}")
    elif name == "discord_list_messages":
        limit = int(arguments.get("limit", 5))
        query = urllib.parse.urlencode({"limit": max(1, min(limit, 20))})
        result = _request(f"/channels/{channel_id}/messages?{query}")
    elif name == "discord_post_message":
        result = _request(
            f"/channels/{channel_id}/messages",
            method="POST",
            payload={"content": arguments["content"]},
        )
    else:
        raise ValueError(f"unknown tool: {name}")
    return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}]}


def _respond(
    request_id: Any,
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> None:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        message["error"] = error
    else:
        message["result"] = result or {}
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> None:
    for raw in sys.stdin:
        if not raw.strip():
            continue
        request = json.loads(raw)
        request_id = request.get("id")
        method = request.get("method")
        try:
            if method == "initialize":
                _respond(
                    request_id,
                    {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {
                            "name": "rope-discord-capture-adapter",
                            "version": "0.1",
                        },
                    },
                )
            elif method == "notifications/initialized":
                continue
            elif method == "tools/list":
                _respond(request_id, {"tools": _tools()})
            elif method == "tools/call":
                params = request.get("params", {})
                _respond(request_id, _call_tool(params["name"], params.get("arguments", {})))
            else:
                _respond(request_id, error={"code": -32601, "message": f"unknown method: {method}"})
        except Exception as exc:  # noqa: BLE001
            _respond(request_id, error={"code": -32000, "message": f"{type(exc).__name__}: {exc}"})


if __name__ == "__main__":
    main()
