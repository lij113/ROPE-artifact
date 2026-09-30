#!/usr/bin/env python3
"""Run the ROPE unittest suite."""

from __future__ import annotations

import subprocess
import sys


def main() -> None:
    raise SystemExit(
        subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
            check=False,
        ).returncode
    )


if __name__ == "__main__":
    main()
