#!/usr/bin/env python3
"""Review captured paper-v1 MCP profiles into host-side classifications."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.profile_review import review_captured_profiles  # noqa: E402


def main() -> None:
    result = review_captured_profiles(ROOT)
    print(
        json.dumps(
            {
                "profile_count": result["profile_count"],
                "review_status_counts": result["review_status_counts"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
