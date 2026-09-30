"""Verified task-contract compiler for common ROPE workflow templates.

The compiler is intentionally not a natural-language policy oracle. A model or
heuristic may propose task-specific slots, but the trusted part is a deterministic
pipeline:

1. choose a workflow template;
2. merge the draft with a non-overridable global safety envelope;
3. verify schema, source/sink obligations, approval binding, and permissions;
4. run a small counterexample suite over the draft;
5. refine fail-open drafts into local-only or approval-gated contracts.

This makes contract generation a conservative synthesis step rather than a
trusted semantic source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from rope_core.model import SinkClass, TaskContract, TaskPhase


GLOBAL_ENVELOPE_ID = "rope-global-envelope-v1"
PHASE_ORDER = (
    TaskPhase.COLLECT_SOURCES,
    TaskPhase.TRANSFORM,
    TaskPhase.PREPARE_OUTPUT,
    TaskPhase.USER_REVIEW,
    TaskPhase.COMMIT_OR_SEND,
)
PRIVATE_SOURCE_CLASSES = frozenset(
    {
        "internal_email",
        "drive_doc",
        "slack_thread",
        "notion_page",
        "crm_record",
        "ticket",
        "local_file",
        "calendar_event",
    }
)
EXTERNAL_SINKS = frozenset({"external_email", "same_org_message", "public_web"})
HIGH_RISK_SINKS = frozenset({"external_email", "public_web", "destructive_write", "payment"})
REQUIRED_EXTERNAL_TRANSFORMS = frozenset(
    {"redact(PII)", "summarize(short)", "approve(bound_recipient)"}
)


@dataclass(frozen=True)
class ContractFinding:
    code: str
    severity: str
    message: str


@dataclass(frozen=True)
class ContractCompileResult:
    contract: TaskContract
    template: str
    confidence: float
    approval_nodes: tuple[str, ...]
    deny_by_default: bool
    verified: bool = True
    envelope_id: str = GLOBAL_ENVELOPE_ID
    draft: Mapping[str, Any] = field(default_factory=dict)
    findings: tuple[ContractFinding, ...] = ()
    refinement_steps: tuple[str, ...] = ()
    counterexamples_before: tuple[str, ...] = ()
    counterexamples_after: tuple[str, ...] = ()
    fallback_used: bool = False


def compile_task_contract(
    user_request: str,
    *,
    draft: Mapping[str, Any] | None = None,
) -> ContractCompileResult:
    """Compile a user request into a finite ROPE task contract.

    ``draft`` can be supplied by an LLM. It is treated as untrusted input and can
    only narrow the global safety envelope. If verifier or counterexample checks
    still find fail-open risk after refinement, the result falls back to a local
    review-only contract.
    """

    proposed = _normalize_draft(draft or propose_contract_draft(user_request))
    before = tuple(_counterexample_failures(proposed))
    findings = tuple(verify_contract_draft(proposed))
    refined, refinement_steps = refine_contract_draft(proposed, findings, before)
    after = tuple(_counterexample_failures(refined))
    fallback_used = bool(after or _has_fail_open(verify_contract_draft(refined)))
    final_draft = _fallback_review_draft(user_request) if fallback_used else refined
    final_findings = tuple(verify_contract_draft(final_draft))
    final_after = tuple(_counterexample_failures(final_draft))

    template = str(final_draft["template"])
    contract = build_contract_from_slots(final_draft)
    approval_nodes = tuple(sorted(_approval_nodes(final_draft)))
    confidence = _confidence(user_request, final_draft, fallback_used)
    return ContractCompileResult(
        contract=contract,
        template=template,
        confidence=confidence,
        approval_nodes=approval_nodes,
        deny_by_default=True,
        verified=not final_after and not _has_fail_open(final_findings),
        draft=final_draft,
        findings=final_findings,
        refinement_steps=tuple(refinement_steps),
        counterexamples_before=before,
        counterexamples_after=final_after,
        fallback_used=fallback_used,
    )


def propose_contract_draft(user_request: str) -> dict[str, Any]:
    """Heuristic proposer used when no LLM draft is supplied."""

    text = user_request.lower()
    if _looks_like_email_draft(text):
        return _base_draft(
            user_request,
            template="email_draft",
            task_type="summarize_and_draft",
            source_classes=("internal_email",),
            output_artifact="local_draft",
            allowed_final_sinks=("external_email",),
            evidence=("email", "draft", "review"),
        )
    if any(token in text for token in ("github", "issue", "pull request", "代码", "仓库")):
        return _base_draft(
            user_request,
            template="code_review",
            task_type="code_review",
            source_classes=("github_issue", "local_file"),
            output_artifact="local_draft",
            allowed_final_sinks=("same_org_message",),
            evidence=("github", "review"),
        )
    if any(token in text for token in ("slack", "notion", "drive", "calendar", "crm")):
        surface = _first_surface(text)
        return _base_draft(
            user_request,
            template="internal_summary",
            task_type="summarize_and_draft",
            source_classes=(surface,),
            output_artifact="local_draft",
            allowed_final_sinks=("same_org_message",),
            evidence=(surface, "summary"),
        )
    if any(token in text for token in ("search public", "public docs", "公开", "web")):
        return _base_draft(
            user_request,
            template="public_research",
            task_type="public_research",
            source_classes=("public_web",),
            output_artifact="local_report",
            allowed_final_sinks=("local_file",),
            evidence=("public", "web"),
        )
    return _fallback_review_draft(user_request)


def verify_contract_draft(draft: Mapping[str, Any]) -> list[ContractFinding]:
    findings: list[ContractFinding] = []
    required = {
        "template",
        "task_type",
        "source_classes",
        "output_artifact",
        "allowed_final_sinks",
        "forbidden_sinks",
        "required_transformations",
        "permission_budget",
        "approval_tuple",
    }
    missing = sorted(required - set(draft))
    if missing:
        findings.append(
            ContractFinding("schema_missing_fields", "fail_closed", ",".join(missing))
        )
        return findings

    sources = set(_strings(draft.get("source_classes")))
    allowed = set(_strings(draft.get("allowed_final_sinks")))
    forbidden = set(_strings(draft.get("forbidden_sinks")))
    transforms = set(_strings(draft.get("required_transformations")))
    permissions = set(_strings(draft.get("permission_budget")))
    approval = _approval_mapping(draft.get("approval_tuple"))
    private = bool(sources & PRIVATE_SOURCE_CLASSES)

    if allowed & forbidden:
        findings.append(
            ContractFinding(
                "sink_allowed_and_forbidden",
                "fail_open",
                "a sink cannot be both allowed and forbidden",
            )
        )
    if private and "public_web" in allowed:
        findings.append(
            ContractFinding(
                "private_public_web",
                "fail_open",
                "private sources cannot be sent to public web by task contract",
            )
        )
    if private and (allowed & EXTERNAL_SINKS) and not REQUIRED_EXTERNAL_TRANSFORMS <= transforms:
        findings.append(
            ContractFinding(
                "missing_external_obligations",
                "fail_open",
                "private external flow requires redact, summarize, and bound approval",
            )
        )
    if allowed & HIGH_RISK_SINKS and not _approval_bound(approval):
        findings.append(
            ContractFinding(
                "missing_bound_approval",
                "fail_open",
                "high-risk sinks require data/sink/purpose/recipient/expiry binding",
            )
        )
    if any("send" in permission or "admin" in permission for permission in permissions):
        if "approve(bound_recipient)" not in transforms:
            findings.append(
                ContractFinding(
                    "unbound_send_permission",
                    "fail_open",
                    "send/admin permissions require a bound approval obligation",
                )
            )
    if "destructive_write" in allowed and not {
        "stepup(permission)",
        "approve(operation)",
    } <= transforms:
        findings.append(
            ContractFinding(
                "destructive_without_stepup",
                "fail_open",
                "destructive writes require step-up and operation approval",
            )
        )
    if not allowed:
        findings.append(
            ContractFinding("no_final_sink", "fail_closed", "contract has no final output sink")
        )
    return findings


def refine_contract_draft(
    draft: Mapping[str, Any],
    findings: tuple[ContractFinding, ...],
    counterexamples: tuple[str, ...],
) -> tuple[dict[str, Any], list[str]]:
    refined = _normalize_draft(draft)
    steps: list[str] = []
    if "raw_exfiltration" in counterexamples or _has_code(findings, "missing_external_obligations"):
        transforms = set(_strings(refined.get("required_transformations")))
        transforms.update(REQUIRED_EXTERNAL_TRANSFORMS)
        refined["required_transformations"] = sorted(transforms)
        steps.append("add_external_obligations")
    if "public_web_laundering" in counterexamples or _has_code(findings, "private_public_web"):
        allowed = set(_strings(refined.get("allowed_final_sinks")))
        allowed.discard("public_web")
        refined["allowed_final_sinks"] = sorted(allowed or {"local_file"})
        refined["forbidden_sinks"] = sorted(set(_strings(refined.get("forbidden_sinks"))) | {"public_web"})
        steps.append("remove_private_public_web")
    if "stale_approval" in counterexamples or _has_code(findings, "missing_bound_approval"):
        refined["approval_tuple"] = _default_approval_tuple(refined)
        transforms = set(_strings(refined.get("required_transformations")))
        transforms.add("approve(bound_recipient)")
        refined["required_transformations"] = sorted(transforms)
        steps.append("bind_approval_tuple")
    if "over_stepup" in counterexamples or _has_code(findings, "unbound_send_permission"):
        permissions = {
            permission
            for permission in _strings(refined.get("permission_budget"))
            if "admin" not in permission and permission != "mail.send"
        }
        permissions.add("send_after_approval")
        refined["permission_budget"] = sorted(permissions)
        steps.append("downscope_permission_budget")
    if "destructive_without_stepup" in counterexamples or _has_code(findings, "destructive_without_stepup"):
        transforms = set(_strings(refined.get("required_transformations")))
        transforms.update({"stepup(permission)", "approve(operation)"})
        refined["required_transformations"] = sorted(transforms)
        steps.append("gate_destructive_write")
    if "untrusted_sanitizer" in counterexamples:
        refined["trusted_discharge_only"] = True
        steps.append("require_trusted_discharge")
    if "recipient_swap" in counterexamples:
        refined["approval_tuple"] = _default_approval_tuple(refined)
        steps.append("repair_recipient_binding")
    return refined, steps


def build_contract_from_slots(slots: Mapping[str, Any]) -> TaskContract:
    allowed = set(_strings(slots.get("allowed_final_sinks")))
    forbidden = set(_strings(slots.get("forbidden_sinks")))
    local_allowed = {
        SinkClass.LOCAL_DISPLAY: "allow",
        SinkClass.LOCAL_FILE: "allow",
        SinkClass.INTERNAL_SERVICE: "allow",
        SinkClass.SAME_ORG_MESSAGE: "deny",
        SinkClass.EXTERNAL_EMAIL: "deny",
        SinkClass.PUBLIC_WEB: "deny",
        SinkClass.CODE_EXECUTION: "deny",
        SinkClass.PAYMENT: "deny",
        SinkClass.DESTRUCTIVE_WRITE: "deny",
    }
    review_policy = dict(local_allowed)
    commit_policy = dict(local_allowed)
    for sink_name in allowed:
        if sink_name in forbidden:
            continue
        sink = _sink_from_name(sink_name)
        if sink in {SinkClass.LOCAL_DISPLAY, SinkClass.LOCAL_FILE, SinkClass.INTERNAL_SERVICE}:
            review_policy[sink] = "allow"
            commit_policy[sink] = "allow"
        else:
            review_policy[sink] = "conditional"
            commit_policy[sink] = "conditional"
    return TaskContract(
        contract_id=f"compiled_{slots['template']}_contract",
        initial_phase=TaskPhase.COLLECT_SOURCES,
        accepting_phases=frozenset({TaskPhase.USER_REVIEW, TaskPhase.COMMIT_OR_SEND}),
        phase_order=PHASE_ORDER,
        sink_policy={
            TaskPhase.COLLECT_SOURCES: local_allowed,
            TaskPhase.TRANSFORM: local_allowed,
            TaskPhase.PREPARE_OUTPUT: local_allowed,
            TaskPhase.USER_REVIEW: review_policy,
            TaskPhase.COMMIT_OR_SEND: commit_policy,
        },
    )


def build_email_draft_contract() -> TaskContract:
    return build_contract_from_slots(propose_contract_draft("summarize email and create draft for review"))


def _base_draft(
    user_request: str,
    *,
    template: str,
    task_type: str,
    source_classes: tuple[str, ...],
    output_artifact: str,
    allowed_final_sinks: tuple[str, ...],
    evidence: tuple[str, ...],
) -> dict[str, Any]:
    private = bool(set(source_classes) & PRIVATE_SOURCE_CLASSES)
    external = bool(set(allowed_final_sinks) & EXTERNAL_SINKS)
    transforms: set[str] = set()
    if private and external:
        transforms.update(REQUIRED_EXTERNAL_TRANSFORMS)
    return {
        "user_request_hash": str(abs(hash(user_request)) % 1_000_000),
        "template": template,
        "task_type": task_type,
        "source_classes": list(source_classes),
        "output_artifact": output_artifact,
        "allowed_final_sinks": list(allowed_final_sinks),
        "forbidden_sinks": sorted(HIGH_RISK_SINKS - set(allowed_final_sinks)),
        "required_transformations": sorted(transforms),
        "permission_budget": ["read", "draft"] + (["send_after_approval"] if external else []),
        "approval_tuple": _default_approval_tuple({"allowed_final_sinks": allowed_final_sinks}) if external else {},
        "evidence": list(evidence),
        "trusted_discharge_only": True,
    }


def _fallback_review_draft(user_request: str) -> dict[str, Any]:
    return {
        "user_request_hash": str(abs(hash(user_request)) % 1_000_000),
        "template": "fallback_review_only",
        "task_type": "review_only",
        "source_classes": ["unknown"],
        "output_artifact": "local_draft",
        "allowed_final_sinks": ["local_file"],
        "forbidden_sinks": sorted(HIGH_RISK_SINKS),
        "required_transformations": [],
        "permission_budget": ["read", "draft"],
        "approval_tuple": {},
        "evidence": [],
        "trusted_discharge_only": True,
    }


def _normalize_draft(draft: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(draft)
    normalized.setdefault("template", "fallback_review_only")
    normalized.setdefault("task_type", "review_only")
    normalized.setdefault("source_classes", ["unknown"])
    normalized.setdefault("output_artifact", "local_draft")
    normalized.setdefault("allowed_final_sinks", ["local_file"])
    normalized.setdefault("forbidden_sinks", [])
    normalized.setdefault("required_transformations", [])
    normalized.setdefault("permission_budget", ["read", "draft"])
    normalized.setdefault("approval_tuple", {})
    normalized.setdefault("evidence", [])
    normalized.setdefault("trusted_discharge_only", True)
    for key in (
        "source_classes",
        "allowed_final_sinks",
        "forbidden_sinks",
        "required_transformations",
        "permission_budget",
        "evidence",
    ):
        normalized[key] = sorted(set(_strings(normalized.get(key))))
    return normalized


def _counterexample_failures(draft: Mapping[str, Any]) -> list[str]:
    sources = set(_strings(draft.get("source_classes")))
    allowed = set(_strings(draft.get("allowed_final_sinks")))
    transforms = set(_strings(draft.get("required_transformations")))
    permissions = set(_strings(draft.get("permission_budget")))
    approval = _approval_mapping(draft.get("approval_tuple"))
    private = bool(sources & PRIVATE_SOURCE_CLASSES)
    failures: list[str] = []
    if private and allowed & EXTERNAL_SINKS and not REQUIRED_EXTERNAL_TRANSFORMS <= transforms:
        failures.append("raw_exfiltration")
    if private and "public_web" in allowed:
        failures.append("public_web_laundering")
    if allowed & HIGH_RISK_SINKS and not _approval_bound(approval):
        failures.append("stale_approval")
        failures.append("recipient_swap")
    if any(permission in {"mail.send", "admin", "email.send"} for permission in permissions):
        failures.append("over_stepup")
    if allowed & EXTERNAL_SINKS and not draft.get("trusted_discharge_only", False):
        failures.append("untrusted_sanitizer")
    if "destructive_write" in allowed and not {"stepup(permission)", "approve(operation)"} <= transforms:
        failures.append("destructive_without_stepup")
    return sorted(set(failures))


def _approval_nodes(draft: Mapping[str, Any]) -> set[str]:
    allowed = set(_strings(draft.get("allowed_final_sinks")))
    nodes: set[str] = set()
    if "external_email" in allowed:
        nodes.add("external_email_send")
    if "same_org_message" in allowed:
        nodes.add("same_org_message")
    if "destructive_write" in allowed:
        nodes.add("destructive_write")
    if draft["template"] == "fallback_review_only":
        nodes.update({"all_external_sinks", "all_writes", "all_stepups"})
    return nodes


def _default_approval_tuple(draft: Mapping[str, Any]) -> dict[str, str]:
    allowed = sorted(_strings(draft.get("allowed_final_sinks")))
    return {
        "data_class": "private_user_data",
        "sink": ",".join(allowed) if allowed else "local_file",
        "purpose": "current_task",
        "recipient": "bound_at_runtime",
        "expiry": "task_window",
    }


def _approval_bound(approval: Mapping[str, Any]) -> bool:
    required = {"data_class", "sink", "purpose", "recipient", "expiry"}
    return required <= set(approval) and all(str(approval[key]) for key in required)


def _approval_mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _sink_from_name(name: str) -> SinkClass:
    try:
        return SinkClass(name)
    except ValueError:
        return SinkClass.LOCAL_FILE


def _strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Mapping):
        return tuple(str(key) for key in value)
    try:
        return tuple(str(item) for item in value)
    except TypeError:
        return (str(value),)


def _has_fail_open(findings: tuple[ContractFinding, ...] | list[ContractFinding]) -> bool:
    return any(finding.severity == "fail_open" for finding in findings)


def _has_code(findings: tuple[ContractFinding, ...], code: str) -> bool:
    return any(finding.code == code for finding in findings)


def _confidence(user_request: str, draft: Mapping[str, Any], fallback_used: bool) -> float:
    if fallback_used or draft["template"] == "fallback_review_only":
        return 0.35
    evidence = len(_strings(draft.get("evidence")))
    request_bonus = 0.1 if len(user_request.split()) >= 4 or len(user_request) >= 12 else 0.0
    return min(0.92, 0.72 + 0.03 * evidence + request_bonus)


def _looks_like_email_draft(text: str) -> bool:
    has_email = any(token in text for token in ("email", "mail", "邮件", "客户邮件"))
    has_draft = any(token in text for token in ("draft", "草稿", "起草", "回复"))
    has_review = any(token in text for token in ("confirm", "review", "确认", "给我看"))
    return has_email and has_draft and has_review


def _first_surface(text: str) -> str:
    if "slack" in text:
        return "slack_thread"
    if "notion" in text:
        return "notion_page"
    if "drive" in text:
        return "drive_doc"
    if "calendar" in text:
        return "calendar_event"
    if "crm" in text:
        return "crm_record"
    return "internal_email"
