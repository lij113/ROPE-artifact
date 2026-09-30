import unittest
from pathlib import Path

from rope_bench import contract_from_workflow_fixture, load_fixture
from rope_core import (
    DecisionKind,
    Event,
    EventKind,
    Obligation,
    RuntimeState,
    SinkClass,
    TaskPhase,
    ToolEffect,
    TrustLevel,
    ValueLabel,
    admit,
    discharge_label,
    future_accept,
    parse_action,
    parse_conjunction,
    propagate_label,
    redact,
    summarize,
)
from rope_core.ablations import admit_no_future, admit_no_obligation
from rope_core.contracts import local_valid


ROOT = Path(__file__).resolve().parents[1]
EMAIL_FIXTURES = ROOT / "fixtures" / "email_draft"
TOY_TRACES = ROOT / "fixtures" / "phase2_toy_traces.json"


def _contract():
    return contract_from_workflow_fixture(load_fixture(EMAIL_FIXTURES / "workflow.json"))


def _state(phase: str) -> RuntimeState:
    return RuntimeState(task_phase=TaskPhase(phase), provenance_graph_id="phase2")


def _raw_private_email_label() -> ValueLabel:
    obligations = parse_conjunction(
        [
            "redact:PII",
            "summarize:short",
            "approve:email_body:external_email:customer_reply:approved_recipient",
        ]
    )
    public_obligations = parse_conjunction(
        [
            "redact:PII",
            "summarize:search_terms",
        ]
    )
    return ValueLabel(
        source_ids=frozenset({"internal_mailbox"}),
        sensitivity="private",
        purposes=frozenset({"customer_reply"}),
        obligations={
            SinkClass.EXTERNAL_EMAIL: obligations,
            SinkClass.PUBLIC_WEB: public_obligations,
        },
    )


def _redacted_summary_label() -> ValueLabel:
    return ValueLabel(
        source_ids=frozenset({"internal_mailbox"}),
        sensitivity="private",
        purposes=frozenset({"customer_reply"}),
        obligations={
            SinkClass.LOCAL_FILE: Obligation.top(),
            SinkClass.LOCAL_DISPLAY: Obligation.top(),
        },
    )


def _event_from_fixture(event_data: dict) -> Event:
    action = parse_action(event_data["action"]) if "action" in event_data else None
    return Event(
        event_id=event_data["event_id"],
        kind=EventKind(event_data["kind"]),
        payload=event_data,
        action=action,
    )


class Phase2SemanticsTests(unittest.TestCase):
    def test_two_layer_contract_policy_matches_email_draft(self) -> None:
        contract = _contract()
        create_draft = parse_action(
            {
                "action": "create_draft",
                "resource": "local_draft",
                "sink": "local_file",
                "side_effect": "write",
                "purpose": "customer_reply_draft",
            }
        )
        send_email = parse_action(
            {
                "action": "send_email",
                "resource": "external_email",
                "sink": "external_email",
                "side_effect": "send",
                "purpose": "customer_reply",
            }
        )

        self.assertTrue(local_valid(contract, TaskPhase.PREPARE_OUTPUT, create_draft))
        self.assertFalse(local_valid(contract, TaskPhase.PREPARE_OUTPUT, send_email))
        self.assertTrue(
            local_valid(
                contract,
                TaskPhase.USER_REVIEW,
                send_email,
                obligations_satisfied=True,
            )
        )

    def test_label_propagation_and_trusted_discharge(self) -> None:
        raw = _raw_private_email_label()
        derived = propagate_label(
            [raw],
            added_obligations={SinkClass.DESTRUCTIVE_WRITE: parse_conjunction(["audit:external_send"])},
        )
        trusted_effect = ToolEffect(
            tool_name="redact_pii",
            action=parse_action(
                {
                    "action": "redact_pii",
                    "resource": "host_sanitizer",
                    "sink": "local_file",
                    "side_effect": "transform",
                    "purpose": "sanitize_email",
                }
            ),
            trust=TrustLevel.AUDITED,
            discharges=(redact("PII"), summarize("short")),
        )
        untrusted_effect = ToolEffect(
            tool_name="untrusted_server_redactor",
            action=trusted_effect.action,
            trust=TrustLevel.SERVER_HINT,
            discharges=(redact("PII"), summarize("short")),
        )

        self.assertIn(SinkClass.EXTERNAL_EMAIL, derived.obligations)
        self.assertIn(SinkClass.DESTRUCTIVE_WRITE, derived.obligations)
        self.assertFalse(
            discharge_label(raw, untrusted_effect)
            .obligations[SinkClass.EXTERNAL_EMAIL]
            .is_top()
        )
        trusted_label = discharge_label(raw, trusted_effect)
        remaining = trusted_label.obligations[SinkClass.EXTERNAL_EMAIL]
        self.assertEqual(len(remaining.atoms()), 1)
        self.assertEqual(remaining.atoms()[0].name, "approve")

    def test_bounded_future_continuation(self) -> None:
        contract = _contract()

        self.assertTrue(future_accept(contract, _state("PrepareOutput"), max_depth=2))
        self.assertFalse(future_accept(contract, _state("PrepareOutput"), max_depth=0))

    def test_toy_traces_have_expected_full_rope_decisions(self) -> None:
        contract = _contract()
        toy = load_fixture(TOY_TRACES)
        labels = {
            "raw_private_email": _raw_private_email_label(),
            "redacted_summary": _redacted_summary_label(),
        }

        for trace in toy["traces"]:
            event = _event_from_fixture(trace["event"])
            input_label = labels.get(trace.get("input_label"))
            decision = admit(
                contract,
                _state(trace["initial_phase"]),
                event,
                input_labels=() if input_label is None else (input_label,),
            )
            self.assertEqual(decision.kind.value, trace["expected_decision"], trace["trace_id"])

    def test_ablations_expose_expected_failures(self) -> None:
        contract = _contract()
        raw = _raw_private_email_label()

        stepup_event = Event(
            event_id="ablate-stepup",
            kind=EventKind.STEPUP,
            payload={"permission": "email.send.any_recipient"},
        )
        full_stepup = admit(contract, _state("PrepareOutput"), stepup_event)
        no_future = admit_no_future(contract, _state("PrepareOutput"), stepup_event)

        self.assertIs(full_stepup.kind, DecisionKind.BLOCK)
        self.assertIs(no_future.kind, DecisionKind.ALLOW)

        send_event = Event(
            event_id="ablate-send",
            kind=EventKind.CALL,
            action=parse_action(
                {
                    "action": "send_email",
                    "resource": "external_email",
                    "sink": "external_email",
                    "side_effect": "send",
                    "purpose": "customer_reply",
                }
            ),
        )
        full_send = admit(contract, _state("UserReview"), send_event, input_labels=(raw,))
        no_obligation = admit_no_obligation(contract, _state("UserReview"), send_event)

        self.assertIs(full_send.kind, DecisionKind.BLOCK)
        self.assertIs(no_obligation.kind, DecisionKind.ALLOW)


if __name__ == "__main__":
    unittest.main()

