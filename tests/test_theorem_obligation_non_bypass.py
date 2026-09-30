import unittest
from pathlib import Path

from rope_bench import contract_from_workflow_fixture, load_fixture
from rope_bench.phase3_demo import raw_private_email_label
from rope_core import Event, EventKind, RuntimeState, TaskPhase, admit, approve, parse_action, redact, summarize


ROOT = Path(__file__).resolve().parents[1]


def _contract():
    return contract_from_workflow_fixture(
        load_fixture(ROOT / "fixtures" / "email_draft" / "workflow.json")
    )


def _send_event():
    return Event(
        event_id="obligation.send",
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


class ObligationNonBypassTests(unittest.TestCase):
    def test_raw_private_value_cannot_reach_external_sink_before_discharge(self):
        decision = admit(
            _contract(),
            RuntimeState(TaskPhase.USER_REVIEW, "obligation-test"),
            _send_event(),
            input_labels=(raw_private_email_label(),),
        )

        self.assertEqual(decision.kind.value, "block")
        self.assertTrue(decision.required_obligations)
        self.assertIn("external_email", decision.reason)

    def test_external_sink_allowed_after_matching_discharge(self):
        decision = admit(
            _contract(),
            RuntimeState(TaskPhase.USER_REVIEW, "obligation-test"),
            _send_event(),
            input_labels=(raw_private_email_label(),),
            discharged=(
                redact("PII"),
                summarize("short"),
                approve(
                    "email_body",
                    "external_email",
                    "customer_reply",
                    "approved_recipient",
                ),
            ),
        )

        self.assertEqual(decision.kind.value, "allow")


if __name__ == "__main__":
    unittest.main()
