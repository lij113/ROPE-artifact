"""Two-layer task contract helpers for ROPE."""

from __future__ import annotations

from rope_core.model import (
    SideEffect,
    SinkClass,
    StructuredAction,
    TaskContract,
    TaskPhase,
)


def sink_policy(contract: TaskContract, phase: TaskPhase, sink: SinkClass) -> str:
    return contract.sink_policy.get(phase, {}).get(sink, "deny")


def local_valid(
    contract: TaskContract,
    phase: TaskPhase,
    action: StructuredAction,
    *,
    obligations_satisfied: bool = False,
) -> bool:
    policy = sink_policy(contract, phase, action.sink)
    if policy == "allow":
        return True
    if policy == "deny":
        return False
    if policy == "conditional":
        return obligations_satisfied
    raise ValueError(f"Unknown sink policy {policy!r} for {phase}/{action.sink}")


def next_phase(contract: TaskContract, phase: TaskPhase, action: StructuredAction) -> TaskPhase:
    """Advance through the finite phase automaton with conservative heuristics."""

    if phase not in contract.phase_order:
        raise ValueError(f"Phase {phase} is not in contract {contract.contract_id}")

    if action.side_effect in {SideEffect.SEND, SideEffect.STEPUP}:
        return phase
    if action.action in {"read_email", "read_notes"}:
        return _at_least(contract, phase, TaskPhase.TRANSFORM)
    if action.action in {"summarize_email", "redact_pii", "derive_search_terms"}:
        return _at_least(contract, phase, TaskPhase.PREPARE_OUTPUT)
    if action.action in {"create_draft", "create_local_draft", "display_draft"}:
        return _at_least(contract, phase, TaskPhase.USER_REVIEW)
    return phase


def _at_least(contract: TaskContract, phase: TaskPhase, minimum: TaskPhase) -> TaskPhase:
    current_idx = contract.phase_order.index(phase)
    minimum_idx = contract.phase_order.index(minimum)
    return contract.phase_order[max(current_idx, minimum_idx)]

