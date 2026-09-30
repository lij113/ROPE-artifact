"""Fixture loading helpers for Phase 1 tests and future benchmark runners."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rope_core.model import SinkClass, TaskContract, TaskPhase


def load_fixture(path: str | Path) -> dict[str, Any]:
    fixture_path = Path(path)
    with fixture_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Fixture must be a JSON object: {fixture_path}")
    return data


def contract_from_workflow_fixture(workflow: dict[str, Any]) -> TaskContract:
    contract = workflow["contract"]
    return TaskContract(
        contract_id=contract["contract_id"],
        initial_phase=TaskPhase(contract["initial_phase"]),
        accepting_phases=frozenset(TaskPhase(phase) for phase in contract["accepting_phases"]),
        phase_order=tuple(TaskPhase(phase) for phase in contract["phase_order"]),
        sink_policy={
            TaskPhase(phase): {
                SinkClass(sink): policy
                for sink, policy in sink_policy.items()
            }
            for phase, sink_policy in contract["sink_policy"].items()
        },
    )
