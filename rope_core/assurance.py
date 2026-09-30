"""Assurance layer for profiles, side effects, and sanitizers.

This module keeps trust decisions host-side and evidence-based.  It does not
try to prove that arbitrary tools or LLM-written policies are correct.  Instead
it narrows the TCB by requiring versioned profiles, brokered high-risk side
effects, drift downgrades, and independently checked sanitizer evidence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Mapping, Sequence

from rope_core.model import Obligation, SideEffect, SinkClass, TrustLevel


class AssuranceTier(str, Enum):
    SERVER_HINT = "server_hint"
    OBSERVED = "observed"
    HOST_REVIEWED = "host_reviewed"
    CONSTRAINED = "constrained"
    VERIFIED = "verified"
    UNTRUSTED = "untrusted"


class AssuranceDecisionKind(str, Enum):
    ACCEPT = "accept"
    DOWNGRADE = "downgrade"
    REJECT = "reject"


DISCHARGE_TIERS = {AssuranceTier.CONSTRAINED, AssuranceTier.VERIFIED}
BROKERED_TIERS = {AssuranceTier.CONSTRAINED, AssuranceTier.VERIFIED}
HIGH_RISK_SINKS = {
    SinkClass.EXTERNAL_EMAIL,
    SinkClass.PUBLIC_WEB,
    SinkClass.PAYMENT,
    SinkClass.DESTRUCTIVE_WRITE,
}
HIGH_RISK_SIDE_EFFECTS = {SideEffect.SEND, SideEffect.WRITE, SideEffect.STEPUP}
PII_PATTERNS = (
    re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
)


@dataclass(frozen=True)
class GlobalSafetyEnvelope:
    envelope_id: str = "rope-assurance-envelope-v1"
    policy_hash: str = "policy:v1"
    forbidden_private_sinks: frozenset[SinkClass] = frozenset({SinkClass.PUBLIC_WEB})
    high_risk_sinks: frozenset[SinkClass] = frozenset(HIGH_RISK_SINKS)
    high_risk_side_effects: frozenset[SideEffect] = frozenset(HIGH_RISK_SIDE_EFFECTS)
    required_approval_fields: frozenset[str] = frozenset(
        {"task_id", "value_id", "sink", "purpose", "recipient", "nonce", "expiry"}
    )


@dataclass(frozen=True)
class ProfileAssurance:
    tool_name: str
    tier: AssuranceTier
    trust: TrustLevel
    schema_hash: str
    server_identity: str
    policy_hash: str
    allowed_sinks: frozenset[SinkClass]
    allowed_side_effects: frozenset[SideEffect]
    discharge_obligations: tuple[Obligation, ...] = ()
    broker_required: bool = False
    regression_cases: tuple[str, ...] = ()
    evidence: Mapping[str, str] = field(default_factory=dict)

    @property
    def can_discharge(self) -> bool:
        return self.tier in DISCHARGE_TIERS and bool(self.discharge_obligations)


@dataclass(frozen=True)
class AssuranceDecision:
    kind: AssuranceDecisionKind
    reason: str
    profile: ProfileAssurance | None = None
    risks: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolObservation:
    tool_name: str
    schema_hash: str
    server_identity: str
    observed_sink: SinkClass
    observed_side_effect: SideEffect
    description_hash: str = ""


@dataclass(frozen=True)
class ApprovalBinding:
    task_id: str
    value_id: str
    sink: SinkClass
    purpose: str
    recipient: str
    nonce: str
    expiry: str
    policy_hash: str


@dataclass(frozen=True)
class BrokerRequest:
    tool_name: str
    sink: SinkClass
    side_effect: SideEffect
    task_id: str
    value_id: str
    purpose: str
    recipient: str
    nonce: str
    policy_hash: str
    trace_hash: str


@dataclass(frozen=True)
class RepairCertificateView:
    trace_hash: str
    policy_hash: str
    approval: ApprovalBinding
    invariants: frozenset[str] = frozenset()
    profile_hash: str = ""


@dataclass(frozen=True)
class BrokerDecision:
    allowed: bool
    reason: str
    executed_by_broker: bool = False


@dataclass(frozen=True)
class SanitizerEvidence:
    sanitizer_id: str
    tier: AssuranceTier
    input_hash: str
    output_hash: str
    obligation: Obligation
    policy_hash: str
    verifier_id: str
    verifier_passed: bool
    removed_spans: tuple[str, ...] = ()
    max_words: int | None = None
    residual_risk: str = "unknown"


@dataclass(frozen=True)
class SanitizerDecision:
    accepted: bool
    discharge_tier: str
    reason: str
    residual_risk: str = "unknown"


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_profile_assurance(
    profile: ProfileAssurance,
    envelope: GlobalSafetyEnvelope = GlobalSafetyEnvelope(),
) -> AssuranceDecision:
    """Validate a host profile before it can influence enforcement."""

    risks: list[str] = []
    if profile.policy_hash != envelope.policy_hash:
        return AssuranceDecision(
            AssuranceDecisionKind.REJECT,
            "policy_hash_mismatch",
            risks=("profile_bound_to_different_policy",),
        )
    if profile.tier in {AssuranceTier.SERVER_HINT, AssuranceTier.OBSERVED, AssuranceTier.UNTRUSTED}:
        if profile.discharge_obligations:
            return AssuranceDecision(
                AssuranceDecisionKind.DOWNGRADE,
                "untrusted_profile_cannot_discharge",
                profile=replace(profile, discharge_obligations=(), tier=AssuranceTier.OBSERVED),
                risks=("server_hint_discharge_claim",),
            )
        return AssuranceDecision(AssuranceDecisionKind.ACCEPT, "non_authoritative_profile", profile)

    high_risk = bool(profile.allowed_sinks & envelope.high_risk_sinks) or bool(
        profile.allowed_side_effects & envelope.high_risk_side_effects
    )
    if high_risk and not profile.broker_required:
        risks.append("high_risk_effect_without_broker")
    if profile.allowed_sinks & envelope.forbidden_private_sinks and profile.can_discharge:
        risks.append("profile_can_discharge_for_forbidden_private_sink")
    if profile.can_discharge and profile.tier not in DISCHARGE_TIERS:
        risks.append("tier_not_authorized_for_discharge")
    if profile.tier is AssuranceTier.VERIFIED and not profile.regression_cases:
        risks.append("verified_profile_without_regression_cases")

    if risks:
        downgraded = replace(
            profile,
            tier=AssuranceTier.HOST_REVIEWED,
            discharge_obligations=(),
            broker_required=profile.broker_required or high_risk,
        )
        return AssuranceDecision(
            AssuranceDecisionKind.DOWNGRADE,
            "profile_requires_more_assurance",
            profile=downgraded,
            risks=tuple(risks),
        )
    return AssuranceDecision(AssuranceDecisionKind.ACCEPT, "profile_assured", profile)


def apply_profile_drift(
    profile: ProfileAssurance,
    observation: ToolObservation,
) -> AssuranceDecision:
    """Downgrade profiles on schema, identity, or effect drift.

    Drift can only reduce authority. It never promotes a profile.
    """

    risks: list[str] = []
    if observation.tool_name != profile.tool_name:
        risks.append("tool_name_mismatch")
    if observation.schema_hash != profile.schema_hash:
        risks.append("schema_hash_drift")
    if observation.server_identity != profile.server_identity:
        risks.append("server_identity_drift")
    if observation.observed_sink not in profile.allowed_sinks:
        risks.append("observed_sink_outside_profile")
    if observation.observed_side_effect not in profile.allowed_side_effects:
        risks.append("observed_side_effect_outside_profile")
    if not risks:
        return AssuranceDecision(AssuranceDecisionKind.ACCEPT, "no_drift", profile)

    downgraded = replace(
        profile,
        tier=AssuranceTier.UNTRUSTED,
        trust=TrustLevel.UNTRUSTED,
        discharge_obligations=(),
        broker_required=True,
        evidence={**dict(profile.evidence), "drift": ",".join(risks)},
    )
    return AssuranceDecision(
        AssuranceDecisionKind.DOWNGRADE,
        "profile_drift_detected",
        profile=downgraded,
        risks=tuple(risks),
    )


def broker_side_effect(
    request: BrokerRequest,
    certificate: RepairCertificateView,
    profile: ProfileAssurance,
    envelope: GlobalSafetyEnvelope = GlobalSafetyEnvelope(),
) -> BrokerDecision:
    """Check whether a high-risk side effect may be executed by the broker."""

    if profile.tier not in BROKERED_TIERS:
        return BrokerDecision(False, "profile_not_broker_authorized")
    if request.sink not in profile.allowed_sinks:
        return BrokerDecision(False, "sink_outside_profile")
    if request.side_effect not in profile.allowed_side_effects:
        return BrokerDecision(False, "side_effect_outside_profile")
    if request.policy_hash != envelope.policy_hash or certificate.policy_hash != envelope.policy_hash:
        return BrokerDecision(False, "policy_hash_mismatch")
    if request.trace_hash != certificate.trace_hash:
        return BrokerDecision(False, "trace_hash_mismatch")
    approval = certificate.approval
    if approval.policy_hash != request.policy_hash:
        return BrokerDecision(False, "approval_policy_mismatch")
    checks = {
        "task_id": approval.task_id == request.task_id,
        "value_id": approval.value_id == request.value_id,
        "sink": approval.sink == request.sink,
        "purpose": approval.purpose == request.purpose,
        "recipient": approval.recipient == request.recipient,
        "nonce": approval.nonce == request.nonce,
    }
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        return BrokerDecision(False, "approval_binding_mismatch:" + ",".join(failed))
    if request.sink in envelope.high_risk_sinks and "bound_approval" not in certificate.invariants:
        return BrokerDecision(False, "missing_bound_approval_invariant")
    return BrokerDecision(True, "broker_authorized", executed_by_broker=True)


def verify_sanitizer_evidence(
    evidence: SanitizerEvidence,
    *,
    input_text: str,
    output_text: str,
    envelope: GlobalSafetyEnvelope = GlobalSafetyEnvelope(),
) -> SanitizerDecision:
    """Independently verify sanitizer evidence before discharge."""

    if evidence.tier not in DISCHARGE_TIERS:
        return SanitizerDecision(False, "none", "sanitizer_not_trusted", "high")
    if evidence.policy_hash != envelope.policy_hash:
        return SanitizerDecision(False, "none", "policy_hash_mismatch", "high")
    if evidence.input_hash != stable_hash(input_text):
        return SanitizerDecision(False, "none", "input_hash_mismatch", "high")
    if evidence.output_hash != stable_hash(output_text):
        return SanitizerDecision(False, "none", "output_hash_mismatch", "high")
    if not evidence.verifier_passed:
        return SanitizerDecision(False, "none", "verifier_failed", "high")

    atom = evidence.obligation
    if atom.name == "redact" and atom.args.get("class") == "PII":
        for span in evidence.removed_spans:
            if span and span in output_text:
                return SanitizerDecision(False, "none", "removed_span_still_present", "high")
        if _contains_pii(output_text):
            return SanitizerDecision(False, "none", "pii_pattern_in_output", "high")
        return SanitizerDecision(True, "verified_discharge", "redact_verified", evidence.residual_risk)

    if atom.name == "summarize":
        max_words = evidence.max_words or _summary_bound(atom)
        if max_words and len(output_text.split()) > max_words:
            return SanitizerDecision(False, "none", "summary_too_long", "medium")
        if len(output_text) >= len(input_text):
            return SanitizerDecision(False, "none", "summary_not_shorter", "medium")
        return SanitizerDecision(True, "verified_discharge", "summary_shape_verified", evidence.residual_risk)

    if atom.name == "approve" or atom.name == "bind":
        return SanitizerDecision(False, "none", "approval_is_not_sanitizer_discharge", "high")

    return SanitizerDecision(False, "heuristic_only", "semantic_obligation_requires_human_or_policy", "medium")


def residual_attack_surface() -> tuple[dict[str, str], ...]:
    """Document new attack surfaces introduced by the assurance layer."""

    return (
        {
            "surface": "capability_broker_compromise",
            "risk": "broker holds high-risk side-effect tokens",
            "control": "minimal broker API, no LLM, cert/nonce/policy checks, token custody isolated",
        },
        {
            "surface": "verifier_unsoundness",
            "risk": "trusted verifier accepts a leaky sanitizer output",
            "control": "deterministic verifiers first, model sanitizers cannot self-certify, human fallback for semantic obligations",
        },
        {
            "surface": "drift_induced_dos",
            "risk": "attacker triggers schema/effect drift to force fail-closed behavior",
            "control": "drift only downgrades, alert deduplication, observation mode and local-only fallback",
        },
        {
            "surface": "profile_promotion_bug",
            "risk": "server hint is accidentally promoted to trusted profile",
            "control": "tier transitions are host-only; server metadata cannot set discharge or broker authority",
        },
        {
            "surface": "approval_replay",
            "risk": "old approval is reused for a new recipient, task, or value",
            "control": "single-use nonce, expiry, task/value/sink/purpose/recipient/policy binding",
        },
    )


def _contains_pii(text: str) -> bool:
    return any(pattern.search(text) for pattern in PII_PATTERNS)


def _summary_bound(obligation: Obligation) -> int | None:
    value = obligation.args.get("k") or obligation.args.get("level")
    if value in {"short", "brief"}:
        return 80
    if value and value.isdigit():
        return int(value)
    return None
