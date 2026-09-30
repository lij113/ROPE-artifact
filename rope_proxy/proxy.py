"""Toy MCP host-side proxy used for Phase 4 evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field

from rope_core import (
    DecisionKind,
    Event,
    EventKind,
    RuntimeState,
    TaskContract,
    ValueLabel,
    admit,
    certificate_to_dict,
    repair_raw_external_send,
)
from rope_proxy.metadata import attach_meta
from rope_proxy.registry import EffectRegistry


@dataclass
class ProxyState:
    contract: TaskContract
    runtime: RuntimeState
    labels: dict[str, ValueLabel] = field(default_factory=dict)


@dataclass(frozen=True)
class ProxyResult:
    decision: str
    message: dict
    audit: dict


class RopeProxy:
    def __init__(self, state: ProxyState, registry: EffectRegistry | None = None) -> None:
        self.state = state
        self.registry = registry or EffectRegistry()

    def list_tools(self, tools: list[dict]) -> list[dict]:
        return self.registry.attach_profiles(tools)

    def call_tool(self, request: dict) -> ProxyResult:
        tool_name = str(request["name"])
        profile = self.registry.get(tool_name)
        input_labels = tuple(
            self.state.labels[value_id]
            for value_id in request.get("input_values", ())
            if value_id in self.state.labels
        )
        event = Event(
            event_id=str(request.get("id", f"call:{tool_name}")),
            kind=EventKind.CALL,
            payload=request,
            action=profile.effect.action,
        )
        decision = admit(
            self.state.contract,
            self.state.runtime,
            event,
            input_labels=input_labels,
        )
        audit = {
            "tool": tool_name,
            "decision": decision.kind.value,
            "reason": decision.reason,
            "profile_trust": profile.effect.trust.value,
        }
        response = attach_meta(dict(request), "task_state", self.state.runtime.task_phase.value)
        response = attach_meta(response, "tool_profile", profile.to_meta())
        response = attach_meta(response, "audit", audit)

        if (
            decision.kind is DecisionKind.BLOCK
            and tool_name == "send_email"
            and input_labels
            and request.get("allow_repair", True)
        ):
            outcome = repair_raw_external_send(event, input_labels[0])
            cert = certificate_to_dict(outcome.certificate)
            response = attach_meta(response, "repair_cert", cert)
            audit = {
                **audit,
                "decision": "repair",
                "repair_actions": [repair.name for repair in outcome.repairs],
                "certificate_verified": True,
            }
            response = attach_meta(response, "audit", audit)
            return ProxyResult(decision="repair", message=response, audit=audit)

        return ProxyResult(decision=decision.kind.value, message=response, audit=audit)

