#!/usr/bin/env python3
"""Run the Phase 3 repair demo and write report/table artifacts."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.phase3_demo import write_phase3_outputs  # noqa: E402


def main() -> None:
    result = write_phase3_outputs(ROOT)
    print(f"wrote phase3 demo: {result['run_id']}")


if __name__ == "__main__":
    main()
