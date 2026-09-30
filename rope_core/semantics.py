"""Executable Phase 2 toy semantics for ROPE."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace

from rope_core.contracts import local_valid, next_phase
from rope_core.future import AbstractState, SearchContext, bounded_search, phase_space
from rope_core.model import (
    AdmissibilityDecision,
    DecisionKind,
    Event,
    EventKind,
    Obligation,
    RuntimeState,
    SinkClass,
    StructuredAction,
    TaskContract,
    ToolEffect,
    TrustLevel,
    ValueLabel,
)
from rope_core.obligations import conjunction, is_satisfied, remove_discharged

TRUSTED_DISCHARGE_LEVELS = {
    TrustLevel.AUDITED,
    TrustLevel.ORG_POLICY,
    TrustLevel.SIGNED_THIRD_PARTY,
}


def propagate_label(
    inputs: Sequence[ValueLabel],
    *,
    added_obligations: Mapping[SinkClass, Obligation] | None = None,
    sensitivity: str | None = None,
    purpose: Iterable[str] | None = None,
) -> ValueLabel:
    added_obligations = added_obligations or {}
    sinks = set(added_obligations)
    for label in inputs:
        sinks.update(label.obligations)

    obligations = {
        sink: conjunction(
            *(label.obligations.get(sink, Obligation.top()) for label in inputs),
            added_obligations.get(sink, Obligation.top()),
        )
        for sink in sinks
    }
    source_ids = frozenset().union(*(label.source_ids for label in inputs)) if inputs else frozenset()
    purposes = frozenset(purpose or ()).union(*(label.purposes for label in inputs))
    return ValueLabel(
        source_ids=source_ids,
        sensitivity=sensitivity or _max_sensitivity(inputs),
        purposes=purposes,
        obligations=obligations,
    )


def discharge_label(label: ValueLabel, effect: ToolEffect) -> ValueLabel:
    if effect.trust not in TRUSTED_DISCHARGE_LEVELS:
        return label
    return ValueLabel(
        source_ids=label.source_ids,
        sensitivity=label.sensitivity,
        purposes=label.purposes,
        obligations={
            sink: remove_discharged(obligation, effect.discharges)
            for sink, obligation in label.obligations.items()
        },
    )


def obligation_safe(
    label: ValueLabel,
    sink: SinkClass,
    discharged: Iterable[Obligation] = (),
) -> bool:
    obligation = label.obligations.get(sink, Obligation.top())
    return obligation.is_top() or is_satisfied(obligation, discharged)


def necessary_perms(
    contract: TaskContract,
    state: RuntimeState,
    event: Event,
    *,
    permission_plan: Mapping[str, set[str]] | None = None,
    search: SearchContext | None = None,
    max_depth: int = 4,
) -> bool:
    if event.kind != EventKind.STEPUP:
        return True
    permission = str(event.payload.get("permission", ""))
    if not permission:
        return False
    # 见证式提权：从当前抽象状态出发，存在一条用到该权限的有界合法后续
    if search is not None:
        granted = replace(
            search.pre_state,
            permissions=search.pre_state.permissions | {permission},
        )
        report = bounded_search(
            search.space,
            granted,
            max_depth,
            must_use_permission=permission,
        )
        if report["accepted"]:
            return True
    # 声明式提前授权：权限必须写在可信合约的权限计划里，且请求绑定用途、资源、nonce 和有效期
    if permission_plan:
        allowed = permission_plan.get(contract.contract_id, set())
        if permission in allowed and _early_permission_binding_valid(event):
            return True
    return False


def future_accept(
    contract: TaskContract,
    state: RuntimeState,
    *,
    max_depth: int = 4,
) -> bool:
    return bool(future_search_report(contract, state, max_depth=max_depth)["accepted"])


def future_search_report(
    contract: TaskContract,
    state: RuntimeState,
    *,
    max_depth: int = 4,
    search: SearchContext | None = None,
) -> dict[str, object]:
    """Return bounded continuation-search evidence for auditing decisions."""

    if search is not None:
        return bounded_search(search.space, search.post_state, max_depth)
    if state.task_phase not in contract.phase_order:
        return {
            "accepted": False,
            "bound": max_depth,
            "frontier_size": 0,
            "expanded": 0,
            "witness": [],
            "actions": [],
            "failed_goals": sorted(phase.value for phase in contract.accepting_phases),
            "pruned_by": ["phase_not_in_contract"],
        }
    # 合约没有动作模型时，搜索空间只含阶段推进
    return bounded_search(
        phase_space(contract),
        AbstractState(phase=state.task_phase),
        max_depth,
    )


def admit(
    contract: TaskContract,
    state: RuntimeState,
    event: Event,
    *,
    input_labels: Sequence[ValueLabel] = (),
    discharged: Iterable[Obligation] = (),
    max_depth: int = 4,
    permission_plan: Mapping[str, set[str]] | None = None,
    search: SearchContext | None = None,
) -> AdmissibilityDecision:
    discharged = tuple(discharged)
    if event.kind == EventKind.STEPUP and not necessary_perms(
        contract,
        state,
        event,
        permission_plan=permission_plan,
        search=search,
        max_depth=max_depth,
    ):
        return AdmissibilityDecision(
            kind=DecisionKind.BLOCK,
            reason="permission_not_necessary_for_legal_continuation",
        )

    if event.action is None:
        post_state = state
    else:
        sink_safe = all(obligation_safe(label, event.action.sink, discharged) for label in input_labels)
        if not local_valid(contract, state.task_phase, event.action, obligations_satisfied=sink_safe):
            return AdmissibilityDecision(
                kind=DecisionKind.BLOCK,
                reason=f"sink_policy_rejects_{event.action.sink.value}_in_{state.task_phase.value}",
                required_obligations=_required_obligations(input_labels, event.action.sink),
            )
        if not sink_safe:
            return AdmissibilityDecision(
                kind=DecisionKind.BLOCK,
                reason=f"undischarged_obligations_for_{event.action.sink.value}",
                required_obligations=_required_obligations(input_labels, event.action.sink),
            )
        post_state = replace(
            state,
            task_phase=next_phase(contract, state.task_phase, event.action),
        )

    report = future_search_report(contract, post_state, max_depth=max_depth, search=search)
    if not report["accepted"]:
        return AdmissibilityDecision(
            kind=DecisionKind.BLOCK,
            reason="no_legal_continuation_after_event",
            evidence={"future_search": report},
        )

    return AdmissibilityDecision(
        kind=DecisionKind.ALLOW,
        reason="admitted",
        evidence={"future_search": report},
    )


def parse_action(data: Mapping[str, str]) -> StructuredAction:
    return StructuredAction(
        action=data["action"],
        resource=data["resource"],
        sink=SinkClass(data["sink"]),
        side_effect=_parse_side_effect(data["side_effect"]),
        purpose=data["purpose"],
    )


def _parse_side_effect(value: str):
    from rope_core.model import SideEffect

    return SideEffect(value)


def _max_sensitivity(inputs: Sequence[ValueLabel]) -> str:
    if any(label.sensitivity == "private" for label in inputs):
        return "private"
    if any(label.sensitivity == "internal" for label in inputs):
        return "internal"
    return "public"


def _required_obligations(
    labels: Sequence[ValueLabel],
    sink: SinkClass,
) -> tuple[Obligation, ...]:
    atoms: list[Obligation] = []
    for label in labels:
        atoms.extend(label.obligations.get(sink, Obligation.top()).atoms())
    return tuple(atoms)


def _early_permission_binding_valid(event: Event) -> bool:
    """Return whether an early step-up is explicitly bounded to this task.

    Immediate step-up is justified by a bounded legal continuation that uses
    the permission. Early or batched consent needs more structure: the
    runtime must know which resource, purpose, nonce, and expiry the grant is
    bound to, and send-like permissions must also bind a recipient. Broad
    wildcard/admin grants are not accepted as early permissions.
    """

    payload = event.payload
    required = ("purpose", "resource", "approval_nonce", "expiry")
    if any(not str(payload.get(key, "")).strip() for key in required):
        return False
    permission = str(payload.get("permission", ""))
    if any(token in permission for token in ("*", "any_recipient", "all", "admin")):
        return False
    if "send" in permission and not str(payload.get("recipient", "")).strip():
        return False
    return True
