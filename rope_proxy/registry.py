"""Host-side tool effect profile registry for the toy MCP proxy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from rope_core import (
    Obligation,
    SideEffect,
    SinkClass,
    StructuredAction,
    ToolEffect,
    TrustLevel,
    audit,
    parse_action,
    redact,
    summarize,
)


@dataclass(frozen=True)
class ToolProfile:
    tool_name: str
    effect: ToolEffect
    source: str

    def to_meta(self) -> dict[str, object]:
        return {
            "tool": self.tool_name,
            "action": {
                "action": self.effect.action.action,
                "resource": self.effect.action.resource,
                "sink": self.effect.action.sink.value,
                "side_effect": self.effect.action.side_effect.value,
                "purpose": self.effect.action.purpose,
            },
            "trust": self.effect.trust.value,
            "source": self.source,
            "cost": self.effect.cost,
            "discharges": [obligation.pretty() for obligation in self.effect.discharges],
        }


class EffectRegistry:
    def __init__(self, profiles: Mapping[str, ToolProfile] | None = None) -> None:
        self._profiles = dict(profiles or default_profiles())

    def get(self, tool_name: str) -> ToolProfile:
        return self._profiles.get(tool_name, pessimistic_profile(tool_name))

    def attach_profiles(self, tools: list[dict]) -> list[dict]:
        profiled = []
        for tool in tools:
            tool_name = str(tool["name"])
            profile = self.get(tool_name)
            updated = dict(tool)
            meta = dict(updated.get("_meta", {}))
            meta["rope/toolProfile"] = profile.to_meta()
            meta["rope/profileTrust"] = profile.effect.trust.value
            updated["_meta"] = meta
            profiled.append(updated)
        return profiled


def default_profiles() -> dict[str, ToolProfile]:
    return {
        "read_email": _profile(
            "read_email",
            "host_policy",
            "read_email",
            "internal_mailbox",
            SinkClass.INTERNAL_SERVICE,
            SideEffect.READ,
            "summarize_customer_email",
            TrustLevel.ORG_POLICY,
        ),
        "summarize_email": _profile(
            "summarize_email",
            "audited",
            "summarize_email",
            "host_summarizer",
            SinkClass.LOCAL_FILE,
            SideEffect.TRANSFORM,
            "summarize_customer_email",
            TrustLevel.AUDITED,
            discharges=(summarize("short"),),
        ),
        "redact_pii": _profile(
            "redact_pii",
            "audited",
            "redact_pii",
            "host_redactor",
            SinkClass.LOCAL_FILE,
            SideEffect.TRANSFORM,
            "sanitize_email",
            TrustLevel.AUDITED,
            discharges=(redact("PII"),),
        ),
        "create_local_draft": _profile(
            "create_local_draft",
            "host_policy",
            "create_draft",
            "local_draft",
            SinkClass.LOCAL_FILE,
            SideEffect.WRITE,
            "customer_reply_draft",
            TrustLevel.ORG_POLICY,
        ),
        "show_to_user": _profile(
            "show_to_user",
            "host_policy",
            "display_draft",
            "host_ui",
            SinkClass.LOCAL_DISPLAY,
            SideEffect.NONE,
            "user_review",
            TrustLevel.ORG_POLICY,
        ),
        "send_email": _profile(
            "send_email",
            "host_policy",
            "send_email",
            "external_email",
            SinkClass.EXTERNAL_EMAIL,
            SideEffect.SEND,
            "customer_reply",
            TrustLevel.ORG_POLICY,
        ),
        "web_search": _profile(
            "web_search",
            "host_policy",
            "web_search",
            "public_search",
            SinkClass.PUBLIC_WEB,
            SideEffect.SEND,
            "web_query",
            TrustLevel.ORG_POLICY,
        ),
        "request_permission": _profile(
            "request_permission",
            "host_policy",
            "stepup",
            "permission_manager",
            SinkClass.INTERNAL_SERVICE,
            SideEffect.STEPUP,
            "permission_stepup",
            TrustLevel.ORG_POLICY,
            discharges=(audit("stepup_reason"),),
        ),
    }


def pessimistic_profile(tool_name: str) -> ToolProfile:
    return _profile(
        tool_name,
        "pessimistic_default",
        tool_name,
        "unknown",
        SinkClass.PUBLIC_WEB,
        SideEffect.SEND,
        "unknown",
        TrustLevel.DEFAULT,
        cost=100.0,
    )


def _profile(
    tool_name: str,
    source: str,
    action: str,
    resource: str,
    sink: SinkClass,
    side_effect: SideEffect,
    purpose: str,
    trust: TrustLevel,
    *,
    discharges: tuple[Obligation, ...] = (),
    cost: float = 1.0,
) -> ToolProfile:
    return ToolProfile(
        tool_name=tool_name,
        source=source,
        effect=ToolEffect(
            tool_name=tool_name,
            action=StructuredAction(
                action=action,
                resource=resource,
                sink=sink,
                side_effect=side_effect,
                purpose=purpose,
            ),
            trust=trust,
            discharges=discharges,
            cost=cost,
        ),
    )

