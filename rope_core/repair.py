"""Bounded repair and certificate replay for Phase 3."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any

from rope_core.model import (
    Event,
    EventKind,
    Obligation,
    Repair,
    RepairCertificate,
    SideEffect,
    SinkClass,
    StructuredAction,
    TaskPhase,
    ValueLabel,
)
from rope_core.obligations import approve, redact, remove_discharged, summarize

PHASE3_REPAIR_SEARCH_SPACE = (
    "redact",
    "summarize",
    "downscope_args",
    "switch_to_local_draft",
    "ask_confirm",
)

HOST_POLICY_MINIMUM_REPAIR_SEARCH_SPACE = frozenset(
    {
        "redact",
        "summarize",
        "switch_to_local_draft",
        "ask_confirm",
    }
)

PHASE3_REPAIR_CANDIDATE_COSTS = {
    "block": 100.0,
    "ask_confirm_only": "inadmissible",
    "redact_only": "inadmissible",
    "summarize_only": "inadmissible",
    "redact+summarize+local_draft+approval": 3.75,
}


@dataclass(frozen=True)
class RepairOutcome:
    repairs: tuple[Repair, ...]
    old_trace: tuple[Event, ...]
    new_trace: tuple[Event, ...]
    repaired_label: ValueLabel
    certificate: RepairCertificate


@dataclass(frozen=True)
class CertificateReplayContext:
    policy_hash: str
    effect_profile_hash: str
    approval_nonce: str
    approval_expiry: str
    current_time: str
    task_id: str = "task-1"
    session_id: str = "session-1"
    sanitizer_manifest_hash: str = "sanitizer_manifest:v1"
    tool_availability_hash: str = "tools:v1"
    permission_epoch: str = "permissions:v1"
    external_state_hash: str = "external_state:v1"


def apply_repair_action(
    event: Event,
    label: ValueLabel,
    repair: Repair,
) -> tuple[Event, ValueLabel, tuple[Event, ...]]:
    """Apply one bounded repair action.

    The return shape is `(event, label, emitted_events)`, where emitted events
    are additional trace events such as approval prompts.
    """

    if repair.name == "redact":
        return event, _discharge(label, redact(repair.parameters.get("class", "PII"))), ()
    if repair.name == "summarize":
        return (
            event,
            _discharge(label, summarize(repair.parameters.get("granularity", "short"))),
            (),
        )
    if repair.name == "downscope_args":
        recipient = repair.parameters.get("recipient", "approved_recipient")
        payload = dict(event.payload)
        payload["recipient"] = recipient
        payload["input_values"] = ("v_redacted_summary",)
        return replace(event, payload=payload), label, ()
    if repair.name == "switch_to_local_draft":
        payload = dict(event.payload)
        payload["tool"] = "create_local_draft"
        payload["input_values"] = ("v_redacted_summary",)
        payload.pop("recipient", None)
        action = StructuredAction(
            action="create_draft",
            resource="local_draft",
            sink=SinkClass.LOCAL_FILE,
            side_effect=SideEffect.WRITE,
            purpose="customer_reply_draft",
        )
        return replace(event, event_id=f"{event.event_id}.draft", payload=payload, action=action), label, ()
    if repair.name == "ask_confirm":
        recipient = repair.parameters.get("recipient", "approved_recipient")
        approval_event = Event(
            event_id=f"{event.event_id}.approval",
            kind=EventKind.APPROVE,
            payload={
                "data_class": "email_body",
                "sink": SinkClass.EXTERNAL_EMAIL.value,
                "purpose": "customer_reply",
                "recipient": recipient,
                "nonce": repair.parameters.get("nonce", "phase3-demo-nonce"),
                "expiry": repair.parameters.get("expiry", "2026-05-25T23:59:59Z"),
            },
        )
        return event, label, (approval_event,)
    raise ValueError(f"Unknown repair action: {repair.name}")


def repair_raw_external_send(
    event: Event,
    label: ValueLabel,
    *,
    approved_recipient: str = "approved_recipient",
) -> RepairOutcome:
    """Repair the running-example raw external send into a redacted local draft."""

    old_trace = (event,)
    repairs = (
        Repair(name="redact", cost=1.0, parameters={"class": "PII"}),
        Repair(name="summarize", cost=1.0, parameters={"granularity": "short"}),
        Repair(name="downscope_args", cost=0.25, parameters={"recipient": approved_recipient}),
        Repair(name="switch_to_local_draft", cost=0.5),
        Repair(
            name="ask_confirm",
            cost=1.0,
            parameters={"recipient": approved_recipient, "nonce": "phase3-demo-nonce"},
        ),
    )

    current_event = event
    current_label = label
    emitted: list[Event] = []
    for repair in repairs:
        current_event, current_label, extra_events = apply_repair_action(
            current_event,
            current_label,
            repair,
        )
        emitted.extend(extra_events)

    new_trace = tuple(emitted + [current_event])
    discharged = (
        "redact:PII",
        "summarize:short",
        "approve:email_body:external_email:customer_reply:approved_recipient",
    )
    invariants = (
        "local_draft_sink",
        "draft_uses_redacted_summary",
        "no_raw_body_external_sink",
        "recipient=approved_recipient",
        "pii_redacted",
        "short_summary",
        "bound_approval",
    )
    certificate = RepairCertificate(
        old_trace_hash=trace_hash(old_trace),
        new_trace_hash=trace_hash(new_trace),
        discharged_obligations=discharged,
        contract_path=(TaskPhase.PREPARE_OUTPUT, TaskPhase.USER_REVIEW),
        invariants=invariants,
        search_space=PHASE3_REPAIR_SEARCH_SPACE,
        cost_bound=sum(repair.cost for repair in repairs),
    )
    return RepairOutcome(
        repairs=repairs,
        old_trace=old_trace,
        new_trace=new_trace,
        repaired_label=current_label,
        certificate=certificate,
    )


def verify_repair_certificate(
    certificate: RepairCertificate,
    old_trace: Sequence[Event],
    new_trace: Sequence[Event],
) -> bool:
    if certificate.old_trace_hash != trace_hash(old_trace):
        return False
    if certificate.new_trace_hash != trace_hash(new_trace):
        return False
    if certificate.cost_bound < 0:
        return False
    if not search_space_satisfies_host_policy(certificate.search_space):
        return False

    invariants = set(certificate.invariants)
    discharged = set(certificate.discharged_obligations)
    if "pii_redacted" in invariants and "redact:PII" not in discharged:
        return False
    if "short_summary" in invariants and "summarize:short" not in discharged:
        return False
    if (
        "bound_approval" in invariants
        and "approve:email_body:external_email:customer_reply:approved_recipient"
        not in discharged
    ):
        return False
    if "local_draft_sink" in invariants and not _has_local_draft(new_trace):
        return False
    if "draft_uses_redacted_summary" in invariants and not _draft_uses_redacted_summary(new_trace):
        return False
    if "no_raw_body_external_sink" in invariants and _has_raw_external_sink(new_trace):
        return False
    if "recipient=approved_recipient" in invariants and not _approval_recipient_matches(
        new_trace,
        "approved_recipient",
    ):
        return False
    return True


def search_space_satisfies_host_policy(search_space: Sequence[str]) -> bool:
    """Validate the host minimum template for repair certificate search spaces.

    Minimality is meaningful only if the declared candidate set includes the
    standard moves that can preserve task utility while removing unsafe release
    paths. A certificate that declares a trivially small search space is
    rejected before replay, even if its hashes and invariants otherwise match.
    """

    declared = set(search_space)
    allowed = set(PHASE3_REPAIR_SEARCH_SPACE)
    return (
        declared.issubset(allowed)
        and HOST_POLICY_MINIMUM_REPAIR_SEARCH_SPACE.issubset(declared)
    )


def verify_repair_certificate_bundle(
    certificate: RepairCertificate,
    old_trace: Sequence[Event],
    new_trace: Sequence[Event],
    *,
    expected_context: CertificateReplayContext,
    observed_context: CertificateReplayContext,
) -> bool:
    """Replay a certificate under explicit policy/profile/approval context."""

    if expected_context.policy_hash != observed_context.policy_hash:
        return False
    if expected_context.effect_profile_hash != observed_context.effect_profile_hash:
        return False
    if expected_context.task_id != observed_context.task_id:
        return False
    if expected_context.session_id != observed_context.session_id:
        return False
    if expected_context.sanitizer_manifest_hash != observed_context.sanitizer_manifest_hash:
        return False
    if expected_context.tool_availability_hash != observed_context.tool_availability_hash:
        return False
    if expected_context.permission_epoch != observed_context.permission_epoch:
        return False
    if expected_context.external_state_hash != observed_context.external_state_hash:
        return False
    if expected_context.approval_nonce != observed_context.approval_nonce:
        return False
    if expected_context.approval_expiry != observed_context.approval_expiry:
        return False
    if observed_context.current_time > observed_context.approval_expiry:
        return False
    if not _approval_nonce_matches(new_trace, observed_context.approval_nonce):
        return False
    if not _approval_expiry_matches(new_trace, observed_context.approval_expiry):
        return False
    return verify_repair_certificate(certificate, old_trace, new_trace)


def witness_cache_valid(
    expected_context: CertificateReplayContext,
    observed_context: CertificateReplayContext,
) -> bool:
    """Return whether a cached continuation witness may be reused.

    A witness is not a standing authorization.  It is reusable only while the
    replay context that can affect task legality remains unchanged.
    """

    return (
        expected_context.policy_hash == observed_context.policy_hash
        and expected_context.effect_profile_hash == observed_context.effect_profile_hash
        and expected_context.task_id == observed_context.task_id
        and expected_context.session_id == observed_context.session_id
        and expected_context.sanitizer_manifest_hash
        == observed_context.sanitizer_manifest_hash
        and expected_context.tool_availability_hash == observed_context.tool_availability_hash
        and expected_context.permission_epoch == observed_context.permission_epoch
        and expected_context.external_state_hash == observed_context.external_state_hash
        and expected_context.approval_nonce == observed_context.approval_nonce
        and expected_context.approval_expiry == observed_context.approval_expiry
        and observed_context.current_time <= observed_context.approval_expiry
    )


def trace_hash(trace: Sequence[Event]) -> str:
    payload = json.dumps([_to_jsonable(event) for event in trace], sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def certificate_to_dict(certificate: RepairCertificate) -> dict[str, Any]:
    return _to_jsonable(certificate)


def repair_candidate_costs() -> dict[str, float | str]:
    return dict(PHASE3_REPAIR_CANDIDATE_COSTS)


def _discharge(label: ValueLabel, obligation: Obligation) -> ValueLabel:
    return ValueLabel(
        source_ids=label.source_ids,
        sensitivity=label.sensitivity,
        purposes=label.purposes,
        obligations={
            sink: remove_discharged(existing, (obligation,))
            for sink, existing in label.obligations.items()
        },
    )


def _has_local_draft(trace: Sequence[Event]) -> bool:
    return any(
        event.action is not None
        and event.action.action == "create_draft"
        and event.action.sink is SinkClass.LOCAL_FILE
        for event in trace
    )


def _draft_uses_redacted_summary(trace: Sequence[Event]) -> bool:
    for event in trace:
        if event.action is None or event.action.action != "create_draft":
            continue
        input_values = tuple(event.payload.get("input_values", ()))
        return "v_redacted_summary" in input_values and not any(
            value.startswith("v_raw") for value in input_values
        )
    return False


def _has_raw_external_sink(trace: Sequence[Event]) -> bool:
    for event in trace:
        if event.action is None or event.action.sink is not SinkClass.EXTERNAL_EMAIL:
            continue
        input_values = tuple(event.payload.get("input_values", ()))
        if any(value.startswith("v_raw") for value in input_values):
            return True
    return False


def _approval_recipient_matches(trace: Sequence[Event], expected: str) -> bool:
    approvals = [event for event in trace if event.kind is EventKind.APPROVE]
    if not approvals:
        return False
    return all(event.payload.get("recipient") == expected for event in approvals)


def _approval_nonce_matches(trace: Sequence[Event], expected: str) -> bool:
    approvals = [event for event in trace if event.kind is EventKind.APPROVE]
    if not approvals:
        return False
    return all(event.payload.get("nonce") == expected for event in approvals)


def _approval_expiry_matches(trace: Sequence[Event], expected: str) -> bool:
    approvals = [event for event in trace if event.kind is EventKind.APPROVE]
    if not approvals:
        return False
    return all(event.payload.get("expiry") == expected for event in approvals)


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(_to_jsonable(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return _to_jsonable(asdict(value))
    return value
