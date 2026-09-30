#!/usr/bin/env python3
"""Minimal Google Drive MCP server for paper-v1 capture.

The official Google Drive MCP package uses OAuth desktop credentials. ROPE's
paper-v1 capture also needs a small, deterministic write probe, so this adapter
exposes a minimal stdio MCP surface over the Google Drive API. It supports both
service-account JSON and personal Gmail OAuth token JSON.
"""

from __future__ import annotations

import io
import json
import os
import sys
import urllib.parse
from typing import Any

import httplib2
from google.oauth2.credentials import Credentials as OAuthCredentials
from google.oauth2 import service_account
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload


SCOPES = ["https://www.googleapis.com/auth/drive"]


def _proxy_info() -> Any:
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    if not proxy:
        return None
    parsed = urllib.parse.urlparse(proxy)
    if not parsed.hostname or not parsed.port:
        return None
    proxy_type = (
        httplib2.socks.PROXY_TYPE_HTTP
        if parsed.scheme.startswith("http")
        else httplib2.socks.PROXY_TYPE_SOCKS5
    )
    return httplib2.ProxyInfo(proxy_type, parsed.hostname, parsed.port)


def _drive_service() -> Any:
    credentials = _credentials()
    http = AuthorizedHttp(
        credentials,
        http=httplib2.Http(proxy_info=_proxy_info(), timeout=30),
    )
    return build("drive", "v3", http=http, cache_discovery=False)


def _credentials() -> Any:
    mode = os.environ.get("GOOGLE_DRIVE_AUTH_MODE", "auto").strip().lower()
    oauth_token_path = os.environ.get("GOOGLE_OAUTH_TOKEN")
    service_account_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")

    if mode in {"auto", "oauth"} and oauth_token_path:
        return OAuthCredentials.from_authorized_user_file(oauth_token_path, SCOPES)
    if mode == "oauth":
        raise RuntimeError("GOOGLE_OAUTH_TOKEN is required when GOOGLE_DRIVE_AUTH_MODE=oauth")

    if mode in {"auto", "service_account", "service-account"} and service_account_path:
        return service_account.Credentials.from_service_account_file(
            service_account_path,
            scopes=SCOPES,
        )
    if mode in {"service_account", "service-account"}:
        raise RuntimeError(
            "GOOGLE_APPLICATION_CREDENTIALS is required when "
            "GOOGLE_DRIVE_AUTH_MODE=service_account"
        )

    raise RuntimeError("set GOOGLE_OAUTH_TOKEN or GOOGLE_APPLICATION_CREDENTIALS")


def _tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "gdrive_get_folder_metadata",
            "description": "Read metadata and Drive capabilities for a Google Drive folder.",
            "annotations": {"readOnlyHint": True},
            "inputSchema": {
                "type": "object",
                "properties": {"folder_id": {"type": "string"}},
                "required": ["folder_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "gdrive_list_files",
            "description": "List files directly under a Google Drive folder.",
            "annotations": {"readOnlyHint": True},
            "inputSchema": {
                "type": "object",
                "properties": {
                    "folder_id": {"type": "string"},
                    "page_size": {"type": "integer", "default": 10},
                },
                "required": ["folder_id"],
                "additionalProperties": False,
            },
        },
        {
            "name": "gdrive_write_text_file",
            "description": "Create a small text file under a Google Drive folder.",
            "annotations": {"readOnlyHint": False},
            "inputSchema": {
                "type": "object",
                "properties": {
                    "folder_id": {"type": "string"},
                    "name": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["folder_id", "name", "content"],
                "additionalProperties": False,
            },
        },
    ]


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    service = _drive_service()
    if name == "gdrive_get_folder_metadata":
        folder_id = arguments["folder_id"]
        result = (
            service.files()
            .get(
                fileId=folder_id,
                fields="id,name,mimeType,capabilities,shared,driveId",
                supportsAllDrives=True,
            )
            .execute()
        )
        return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}]}

    if name == "gdrive_list_files":
        folder_id = arguments["folder_id"]
        page_size = int(arguments.get("page_size", 10))
        result = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents and trashed=false",
                fields="files(id,name,mimeType,size,modifiedTime)",
                pageSize=page_size,
                supportsAllDrives=True,
                includeItemsFromAllDrives=True,
            )
            .execute()
        )
        return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}]}

    if name == "gdrive_write_text_file":
        folder_id = arguments["folder_id"]
        body = {
            "name": arguments["name"],
            "parents": [folder_id],
            "mimeType": "text/plain",
        }
        media = MediaIoBaseUpload(
            io.BytesIO(arguments["content"].encode("utf-8")),
            mimetype="text/plain",
        )
        try:
            created = (
                service.files()
                .create(
                    body=body,
                    media_body=media,
                    fields="id,name,mimeType",
                    supportsAllDrives=True,
                )
                .execute()
            )
            result = {"status": "created", "file": created}
        except HttpError as exc:
            reason = "google_api_error"
            try:
                details = json.loads(exc.content.decode("utf-8"))
                errors = details.get("error", {}).get("errors", [])
                if errors and errors[0].get("reason"):
                    reason = str(errors[0]["reason"])
            except Exception:  # noqa: BLE001 - sanitize any unexpected error shape.
                pass
            result = {
                "status": "blocked_by_google_api",
                "reason": reason,
                "http_status": exc.resp.status,
            }
        return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}]}

    raise ValueError(f"unknown tool: {name}")


def _respond(request_id: Any, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> None:
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
                            "name": "rope-gdrive-capture-adapter",
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
        except Exception as exc:  # noqa: BLE001 - MCP response should carry sanitized errors.
            _respond(
                request_id,
                error={"code": -32000, "message": f"{type(exc).__name__}: {exc}"},
            )


if __name__ == "__main__":
    main()
