"""Small mechanism ablations for Phase 2 tests.

These are not production baselines. They exist to make the Phase 2 ablation
story executable on toy traces.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import replace

from rope_core.contracts import local_valid, next_phase
from rope_core.model import (
    AdmissibilityDecision,
    DecisionKind,
    Event,
    EventKind,
    Obligation,
    RuntimeState,
    TaskContract,
    ValueLabel,
)
from rope_core.semantics import obligation_safe


def admit_no_future(
    contract: TaskContract,
    state: RuntimeState,
    event: Event,
    *,
    input_labels: Sequence[ValueLabel] = (),
    discharged: Iterable[Obligation] = (),
    permission_budget: frozenset[str] | None = None,
) -> AdmissibilityDecision:
    """Ablation that ignores permission necessity and future continuation."""

    discharged = tuple(discharged)
    if event.kind == EventKind.STEPUP:
        # 没有后续搜索时，提权只能对照合约的静态权限预算
        if permission_budget is not None and str(event.payload.get("permission", "")) not in permission_budget:
            return AdmissibilityDecision(kind=DecisionKind.BLOCK, reason="permission_outside_budget")
        return AdmissibilityDecision(kind=DecisionKind.ALLOW, reason="no_future_ablation")
    if event.action is None:
        return AdmissibilityDecision(kind=DecisionKind.ALLOW, reason="no_future_ablation")
    sink_safe = all(obligation_safe(label, event.action.sink, discharged) for label in input_labels)
    if not local_valid(contract, state.task_phase, event.action, obligations_satisfied=sink_safe):
        return AdmissibilityDecision(kind=DecisionKind.BLOCK, reason="local_policy_block")
    return AdmissibilityDecision(kind=DecisionKind.ALLOW, reason="no_future_ablation")


def admit_no_obligation(
    contract: TaskContract,
    state: RuntimeState,
    event: Event,
) -> AdmissibilityDecision:
    """Ablation that treats all sink obligations as satisfied."""

    if event.action is None:
        return AdmissibilityDecision(kind=DecisionKind.ALLOW, reason="no_obligation_ablation")
    if not local_valid(contract, state.task_phase, event.action, obligations_satisfied=True):
        return AdmissibilityDecision(kind=DecisionKind.BLOCK, reason="local_policy_block")
    replace(state, task_phase=next_phase(contract, state.task_phase, event.action))
    return AdmissibilityDecision(kind=DecisionKind.ALLOW, reason="no_obligation_ablation")

