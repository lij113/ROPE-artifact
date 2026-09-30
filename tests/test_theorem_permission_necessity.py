import unittest
from pathlib import Path

from rope_bench import contract_from_workflow_fixture, load_fixture
from rope_core import (
    AbstractAction,
    AbstractState,
    AbstractValue,
    Event,
    EventKind,
    RuntimeState,
    SearchContext,
    SearchSpace,
    SideEffect,
    SinkClass,
    TaskGoal,
    TaskPhase,
    admit,
    approve,
    atom_key,
)


ROOT = Path(__file__).resolve().parents[1]


def _contract():
    return contract_from_workflow_fixture(
        load_fixture(ROOT / "fixtures" / "email_draft" / "workflow.json")
    )


def _reply_search(contract, granted: str = "") -> SearchContext:
    goal = TaskGoal(
        goal_id="reply",
        sink=SinkClass.EXTERNAL_EMAIL,
        purpose="customer_reply",
        recipient="approved_recipient",
    )
    approval = approve("email_body", "external_email", "customer_reply", "approved_recipient")
    space = SearchSpace(
        phase_order=contract.phase_order,
        accepting=contract.accepting_phases,
        sink_policy=contract.sink_policy,
        goals=(goal,),
        actions=(
            AbstractAction(name="user_approval", takes_value=True, approves=goal),
            AbstractAction(
                name="send_email",
                sink=SinkClass.EXTERNAL_EMAIL,
                side_effect=SideEffect.SEND,
                takes_value=True,
                delivers=True,
                recipient="approved_recipient",
                purpose="customer_reply",
                permission="email.send.approved_recipient",
            ),
        ),
    )
    summary = AbstractValue(
        value_class="email_body",
        sources=frozenset({"mailbox"}),
        residual=frozenset({(SinkClass.EXTERNAL_EMAIL, atom_key(approval))}),
    )
    state = AbstractState(phase=TaskPhase.USER_REVIEW, values=frozenset({summary}))
    # 提权事件的模拟后状态带上所请求的权限
    post = AbstractState(
        phase=state.phase,
        values=state.values,
        permissions=frozenset({granted}) if granted else frozenset(),
    )
    return SearchContext(space=space, pre_state=state, post_state=post)


class PermissionNecessityTests(unittest.TestCase):
    def test_unnecessary_stepup_is_rejected(self):
        event = Event(
            event_id="permission.unnecessary",
            kind=EventKind.STEPUP,
            payload={"permission": "email.send.any_recipient"},
        )
        decision = admit(
            _contract(),
            RuntimeState(TaskPhase.PREPARE_OUTPUT, "permission-test"),
            event,
        )

        self.assertEqual(decision.kind.value, "block")
        self.assertEqual(decision.reason, "permission_not_necessary_for_legal_continuation")

    def test_needed_stepup_is_allowed_with_future_witness(self):
        contract = _contract()
        search = _reply_search(contract, granted="email.send.approved_recipient")
        event = Event(
            event_id="permission.needed",
            kind=EventKind.STEPUP,
            payload={"permission": "email.send.approved_recipient"},
        )
        decision = admit(
            contract,
            RuntimeState(TaskPhase.USER_REVIEW, "permission-test"),
            event,
            search=search,
        )

        self.assertEqual(decision.kind.value, "allow")
        self.assertTrue(decision.evidence["future_search"]["accepted"])

    def test_broader_stepup_is_not_used_by_any_witness(self):
        contract = _contract()
        event = Event(
            event_id="permission.broad",
            kind=EventKind.STEPUP,
            payload={"permission": "email.send.any_recipient"},
        )
        decision = admit(
            contract,
            RuntimeState(TaskPhase.USER_REVIEW, "permission-test"),
            event,
            search=_reply_search(contract),
        )

        self.assertEqual(decision.kind.value, "block")
        self.assertEqual(decision.reason, "permission_not_necessary_for_legal_continuation")

    def test_request_payload_cannot_declare_its_own_need(self):
        event = Event(
            event_id="permission.self_declared",
            kind=EventKind.STEPUP,
            payload={
                "permission": "email.send.approved_recipient",
                "needed_permissions": ("email.send.approved_recipient",),
                "declared_future_permissions": ("email.send.approved_recipient",),
                "purpose": "customer_reply",
                "resource": "thread-123",
                "recipient": "client@example.com",
                "approval_nonce": "nonce-1",
                "expiry": "task_window",
            },
        )
        decision = admit(
            _contract(),
            RuntimeState(TaskPhase.USER_REVIEW, "permission-test"),
            event,
        )

        self.assertEqual(decision.kind.value, "block")

    def test_declared_early_stepup_requires_bound_consent(self):
        event = Event(
            event_id="permission.early",
            kind=EventKind.STEPUP,
            payload={
                "permission": "email.send.approved_recipient",
                "declared_future_permissions": ("email.send.approved_recipient",),
                "purpose": "customer_reply",
                "resource": "thread-123",
                "recipient": "client@example.com",
                "approval_nonce": "nonce-1",
                "expiry": "task_window",
            },
        )
        contract = _contract()
        decision = admit(
            contract,
            RuntimeState(TaskPhase.PREPARE_OUTPUT, "permission-test"),
            event,
            permission_plan={
                contract.contract_id: {"email.send.approved_recipient"}
            },
        )

        self.assertEqual(decision.kind.value, "allow")
        self.assertTrue(decision.evidence["future_search"]["accepted"])

    def test_declared_early_stepup_without_binding_is_rejected(self):
        event = Event(
            event_id="permission.early.unbound",
            kind=EventKind.STEPUP,
            payload={
                "permission": "email.send.approved_recipient",
                "declared_future_permissions": ("email.send.approved_recipient",),
            },
        )
        contract = _contract()
        decision = admit(
            contract,
            RuntimeState(TaskPhase.PREPARE_OUTPUT, "permission-test"),
            event,
            permission_plan={
                contract.contract_id: {"email.send.approved_recipient"}
            },
        )

        self.assertEqual(decision.kind.value, "block")
        self.assertEqual(decision.reason, "permission_not_necessary_for_legal_continuation")

    def test_batched_broad_send_permission_is_not_valid_early_consent(self):
        event = Event(
            event_id="permission.early.broad",
            kind=EventKind.STEPUP,
            payload={
                "permission": "email.send.any_recipient",
                "declared_future_permissions": ("email.send.any_recipient",),
                "purpose": "customer_reply",
                "resource": "thread-123",
                "recipient": "client@example.com",
                "approval_nonce": "nonce-1",
                "expiry": "task_window",
            },
        )
        contract = _contract()
        decision = admit(
            contract,
            RuntimeState(TaskPhase.PREPARE_OUTPUT, "permission-test"),
            event,
            permission_plan={contract.contract_id: {"email.send.any_recipient"}},
        )

        self.assertEqual(decision.kind.value, "block")
        self.assertEqual(decision.reason, "permission_not_necessary_for_legal_continuation")


if __name__ == "__main__":
    unittest.main()
