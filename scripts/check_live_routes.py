#!/usr/bin/env python3
"""Probe optional external API and 4090 routes without printing secrets."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.live_routes import write_live_route_report  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--probe-external",
        action="store_true",
        help="send one tiny request per configured external API route",
    )
    args = parser.parse_args()
    report = write_live_route_report(ROOT, probe_external=args.probe_external)
    ok_external = sum(
        1 for route in report["external_routes"] if route.get("status") == "ok"
    )
    ok_ollama = sum(1 for route in report["local_ollama"] if route.get("status") == "ok")
    remote = report["remote_4090"]
    print(
        "wrote live route report: "
        f"external_ok={ok_external}/{len(report['external_routes'])}, "
        f"local_ollama_ok={ok_ollama}/{len(report['local_ollama'])}, "
        f"remote_gpu_count={remote.get('gpu_count', 0)}, "
        f"remote_ollama={remote.get('ollama_available')}"
    )


if __name__ == "__main__":
    main()
