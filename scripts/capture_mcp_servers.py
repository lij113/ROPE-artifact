#!/usr/bin/env python3
"""Capture tool metadata and sample calls from configured MCP stdio servers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.mcp_capture import capture_servers  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default="bench/mcp_servers/paper_v1/servers.json",
        help="Path to MCP server capture config, relative to repo root by default.",
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = ROOT / config_path

    summary = capture_servers(ROOT, config_path)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
