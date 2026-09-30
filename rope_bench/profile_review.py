"""Host-review captured MCP tool profile drafts."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


LOCAL_OR_CONTROLLED = {
    "filesystem",
    "memory",
    "git",
    "sqlite",
    "google_drive",
    "playwright_browser",
    "discord",
}


def review_captured_profiles(root: Path) -> dict[str, Any]:
    source = root / "bench" / "profiles" / "paper_v1" / "captured_tool_profiles.json"
    if not source.exists():
        raise FileNotFoundError(source)
    data = json.loads(source.read_text(encoding="utf-8"))
    reviewed = [_review_profile(profile) for profile in data.get("profiles", [])]
    status_counts = Counter(item["review_status"] for item in reviewed)
    sink_counts = Counter(item["sink"] for item in reviewed)
    result = {
        "run_id": "paper_v1_host_profile_review",
        "date": "2026-05-26",
        "source": str(source.relative_to(root)),
        "profiles": reviewed,
        "profile_count": len(reviewed),
        "review_status_counts": dict(sorted(status_counts.items())),
        "sink_counts": dict(sorted(sink_counts.items())),
        "trust_note": (
            "Host review validates sink/side-effect classification for paper-v1 "
            "deployment evidence. It does not allow captured server metadata to "
            "discharge ROPE obligations."
        ),
    }
    out = root / "bench" / "profiles" / "paper_v1" / "host_reviewed_profiles.json"
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _review_profile(profile: dict[str, Any]) -> dict[str, Any]:
    server_id = profile.get("server_id", "")
    review_status = "host_reviewed_local_or_controlled" if server_id in LOCAL_OR_CONTROLLED else "host_reviewed_external"
    return {
        **profile,
        "review_status": review_status,
        "trusted_for_sink_classification": True,
        "trusted_for_obligation_discharge": False,
        "host_review_note": (
            "Reviewed for ROPE sink and side-effect vocabulary; not a sanitizer "
            "or obligation-discharge authority."
        ),
    }
