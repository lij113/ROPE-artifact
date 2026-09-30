import unittest
from dataclasses import replace

from rope_core import (
    AssuranceTier,
    ProvenanceMode,
    SideEffect,
    SinkClass,
    TaskContract,
    TaskGoal,
    TaskPhase,
    ToolObservation,
    TrustLevel,
    approve,
    atom_key,
    conjunction,
    redact,
    summarize,
)
from rope_core.runtime import (
    Approval,
    ContractSpec,
    HostProfile,
    HostRuntime,
    RuntimeConfig,
    transform_output_id,
)

PHASES = (
    TaskPhase.COLLECT_SOURCES,
    TaskPhase.TRANSFORM,
    TaskPhase.PREPARE_OUTPUT,
    TaskPhase.USER_REVIEW,
    TaskPhase.COMMIT_OR_SEND,
)
CLIENT = "client@example.com"
NOW = "2026-09-28T12:00:00Z"


def _contract(*, archive_allowed: bool = False) -> TaskContract:
    policy = {}
    for phase in PHASES:
        late = phase in (TaskPhase.USER_REVIEW, TaskPhase.COMMIT_OR_SEND)
        policy[phase] = {
            SinkClass.LOCAL_DISPLAY: "allow",
            SinkClass.LOCAL_FILE: "allow",
            SinkClass.INTERNAL_SERVICE: "allow",
            SinkClass.EXTERNAL_EMAIL: "conditional" if late else "deny",
            SinkClass.PUBLIC_WEB: "deny",
            SinkClass.DESTRUCTIVE_WRITE: "allow" if archive_allowed else "deny",
        }
    return TaskContract(
        contract_id="reply_contract",
        initial_phase=TaskPhase.COLLECT_SOURCES,
        accepting_phases=frozenset({TaskPhase.USER_REVIEW, TaskPhase.COMMIT_OR_SEND}),
        phase_order=PHASES,
        sink_policy=policy,
    )


def _profiles() -> dict[str, HostProfile]:
    reviewed = dict(trust=TrustLevel.ORG_POLICY, tier=AssuranceTier.HOST_REVIEWED)
    audited = dict(trust=TrustLevel.AUDITED, tier=AssuranceTier.VERIFIED)
    return {
        "read_email": HostProfile(
            "read_email", "read_email", SinkClass.INTERNAL_SERVICE, SideEffect.READ, "read",
            resource_arg="thread", advances_to=TaskPhase.TRANSFORM, **reviewed,
        ),
        "summarize_email": HostProfile(
            "summarize_email", "summarize_email", SinkClass.LOCAL_FILE, SideEffect.TRANSFORM, "transform",
            discharges=(summarize("short"),), advances_to=TaskPhase.PREPARE_OUTPUT, **audited,
        ),
        "redact_pii": HostProfile(
            "redact_pii", "redact_pii", SinkClass.LOCAL_FILE, SideEffect.TRANSFORM, "transform",
            discharges=(redact("PII"),), advances_to=TaskPhase.PREPARE_OUTPUT, **audited,
        ),
        "create_local_draft": HostProfile(
            "create_local_draft", "create_draft", SinkClass.LOCAL_FILE, SideEffect.WRITE, "draft",
            advances_to=TaskPhase.USER_REVIEW, **reviewed,
        ),
        "send_email": HostProfile(
            "send_email", "send_email", SinkClass.EXTERNAL_EMAIL, SideEffect.SEND, "customer_reply",
            permission="email.send", binding_arg="to", trust=TrustLevel.ORG_POLICY,
            tier=AssuranceTier.CONSTRAINED, schema_hash="schema:v1", server_identity="mail.example",
        ),
        "archive_thread": HostProfile(
            "archive_thread", "archive", SinkClass.DESTRUCTIVE_WRITE, SideEffect.WRITE, "cleanup",
            resource_arg="thread", **reviewed,
        ),
    }


def _spec(*, archive_goal: bool = False) -> ContractSpec:
    goals = [
        TaskGoal(
            goal_id="reply",
            sink=SinkClass.EXTERNAL_EMAIL,
            purpose="customer_reply",
            recipient=CLIENT,
            sources=frozenset({"thread-1"}),
            transforms=frozenset({atom_key(summarize("short")), atom_key(redact("PII"))}),
        )
    ]
    if archive_goal:
        goals.append(TaskGoal(goal_id="archive", sink=SinkClass.DESTRUCTIVE_WRITE, removes="thread-1"))
    return ContractSpec(
        contract=_contract(archive_allowed=archive_goal),
        task_id="task-1",
        obligation_policy={
            "customer_email": {
                SinkClass.EXTERNAL_EMAIL: conjunction(
                    redact("PII"),
                    summarize("short"),
                    approve("customer_email", "external_email", "customer_reply", CLIENT),
                )
            }
        },
        goals=tuple(goals),
        sources={"thread-1": "customer_email"},
        tools=tuple(_profiles()),
        permission_budget=frozenset({"email.send"}),
    )


RAW_TEXT = "Alice (alice@example.com, 415-555-1212) asks for a refund of order 7731."
SUMMARY_TEXT = "The customer asks for a refund of a recent order."


def _read(rt: HostRuntime) -> str:
    assert rt.check_call("read_email", {"thread": "thread-1"}).allowed
    rt.commit_call(
        "read_email",
        {"thread": "thread-1"},
        [{"value_id": "v_raw", "data_class": "customer_email", "resource": "thread-1", "text": RAW_TEXT}],
    )
    return "v_raw"


def _transform(rt: HostRuntime, tool: str, value_id: str, text: str) -> str:
    args = {"input": {"$value": value_id}}
    decision = rt.check_call(tool, args)
    assert decision.allowed, decision.reason
    out = transform_output_id(value_id, tool)
    rt.commit_call(tool, args, [{"value_id": out, "text": text}])
    return out


def _approval(value_id: str, *, recipient: str = CLIENT, task_id: str = "task-1", expiry: str = NOW, nonce: str = "n-1") -> Approval:
    return Approval(
        value_id=value_id,
        data_class="customer_email",
        sink=SinkClass.EXTERNAL_EMAIL,
        purpose="customer_reply",
        recipient=recipient,
        task_id=task_id,
        nonce=nonce,
        expiry=expiry,
        policy_hash="policy:v1",
    )


def _prepared(config: RuntimeConfig = RuntimeConfig()) -> tuple[HostRuntime, str]:
    rt = HostRuntime(_spec(), _profiles(), config)
    raw = _read(rt)
    summary = _transform(rt, "summarize_email", raw, SUMMARY_TEXT)
    verified = _transform(rt, "redact_pii", summary, SUMMARY_TEXT)
    draft_args = {"content": {"$value": verified}}
    assert rt.check_call("create_local_draft", draft_args).allowed
    rt.commit_call("create_local_draft", draft_args)
    return rt, verified


class RuntimeSemanticsTests(unittest.TestCase):
    def test_compound_payload_with_raw_attachment_is_rejected(self):
        rt, verified = _prepared()
        rt.observe_approval(_approval(verified))
        self.assertTrue(rt.check_stepup("email.send").allowed)
        rt.commit_stepup("email.send")
        attack = {"to": CLIENT, "body": {"$value": verified}, "attach": {"$value": "v_raw"}}
        decision = rt.check_call("send_email", attack)
        self.assertFalse(decision.allowed)
        self.assertIn("external_email", decision.reason)

        benign = {"to": CLIENT, "body": {"$value": verified}}
        self.assertTrue(rt.check_call("send_email", benign).allowed)
        rt.commit_call("send_email", benign)
        self.assertTrue(rt.task_complete())

    def test_wrong_recipient_stale_and_reused_approvals_do_not_discharge(self):
        for approval in (
            _approval("placeholder", recipient="other@example.com"),
            _approval("placeholder", expiry="2026-09-01T00:00:00Z"),
            _approval("placeholder", task_id="task-9"),
        ):
            rt, verified = _prepared()
            rt.observe_approval(replace(approval, value_id=verified))
            rt.commit_stepup("email.send")
            decision = rt.check_call("send_email", {"to": CLIENT, "body": {"$value": verified}})
            self.assertFalse(decision.allowed, approval)

    def test_send_to_unbound_recipient_is_outside_contract(self):
        rt, verified = _prepared()
        rt.observe_approval(_approval(verified))
        rt.commit_stepup("email.send")
        decision = rt.check_call("send_email", {"to": "ops@relay.example", "body": {"$value": verified}})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "effect_outside_contract")

    def test_archiving_the_only_source_before_reading_strands_the_task(self):
        rt = HostRuntime(_spec(archive_goal=True), _profiles())
        early = rt.check_call("archive_thread", {"thread": "thread-1"})
        self.assertFalse(early.allowed)
        self.assertEqual(early.reason, "no_legal_continuation_after_event")

        stepwise = HostRuntime(_spec(archive_goal=True), _profiles(), RuntimeConfig(use_future=False))
        self.assertTrue(stepwise.check_call("archive_thread", {"thread": "thread-1"}).allowed)

        raw = _read(rt)
        self.assertTrue(rt.check_call("archive_thread", {"thread": "thread-1"}).allowed)
        self.assertEqual(raw, "v_raw")

    def test_stepup_needs_a_legal_continuation_that_uses_it(self):
        rt, _verified = _prepared()
        self.assertTrue(rt.check_stepup("email.send").allowed)
        self.assertFalse(rt.check_stepup("email.send.any_recipient").allowed)
        self.assertFalse(rt.check_stepup("drive.admin").allowed)

    def test_profile_drift_downgrades_the_send_tool(self):
        rt, verified = _prepared()
        rt.observe_approval(_approval(verified))
        rt.commit_stepup("email.send")
        rt.observe_metadata(
            "send_email",
            ToolObservation(
                tool_name="send_email",
                schema_hash="schema:v2",
                server_identity="mail.example",
                observed_sink=SinkClass.EXTERNAL_EMAIL,
                observed_side_effect=SideEffect.SEND,
            ),
        )
        self.assertFalse(rt.check_call("send_email", {"to": CLIENT, "body": {"$value": verified}}).allowed)

    def test_fresh_literal_inherits_context_label_only_in_context_modes(self):
        leak = {"to": CLIENT, "body": "order 7731 alice@example.com"}
        closed, verified = _prepared(RuntimeConfig(provenance_mode=ProvenanceMode.CONTEXT_CLOSED))
        closed.observe_approval(_approval(verified))
        closed.commit_stepup("email.send")
        self.assertFalse(closed.check_call("send_email", leak).allowed)

        raw, verified = _prepared(RuntimeConfig(provenance_mode=ProvenanceMode.RAW_TEXT))
        raw.observe_approval(_approval(verified))
        raw.commit_stepup("email.send")
        self.assertTrue(raw.check_call("send_email", leak).allowed)

    def test_repair_plan_is_certified_and_replayed(self):
        rt, verified = _prepared()
        rt.commit_stepup("email.send")
        attack = {"to": CLIENT, "body": {"$value": "v_raw"}}
        self.assertFalse(rt.check_call("send_email", attack).allowed)
        plan = rt.plan_repair("send_email", attack)
        self.assertIsNotNone(plan)
        self.assertTrue(rt.verify_plan(plan))

        other = HostRuntime(replace(_spec(), task_id="task-2"), _profiles())
        other.values = dict(rt.values)
        other.phase = rt.phase
        other.permissions = set(rt.permissions)
        self.assertFalse(other.verify_plan(plan))


if __name__ == "__main__":
    unittest.main()
