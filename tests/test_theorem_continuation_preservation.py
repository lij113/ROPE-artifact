import unittest
from pathlib import Path

from rope_bench import contract_from_workflow_fixture, load_fixture
from rope_core import Event, EventKind, RuntimeState, TaskPhase, admit, future_search_report, parse_action


ROOT = Path(__file__).resolve().parents[1]


def _contract():
    return contract_from_workflow_fixture(
        load_fixture(ROOT / "fixtures" / "email_draft" / "workflow.json")
    )


class ContinuationPreservationTests(unittest.TestCase):
    def test_accepted_event_carries_future_witness(self):
        event = Event(
            event_id="continuation.local_draft",
            kind=EventKind.CALL,
            action=parse_action(
                {
                    "action": "create_draft",
                    "resource": "local_draft",
                    "sink": "local_file",
                    "side_effect": "write",
                    "purpose": "customer_reply_draft",
                }
            ),
        )
        decision = admit(
            _contract(),
            RuntimeState(TaskPhase.PREPARE_OUTPUT, "continuation-test"),
            event,
        )

        self.assertEqual(decision.kind.value, "allow")
        self.assertTrue(decision.evidence["future_search"]["accepted"])
        self.assertIn("UserReview", decision.evidence["future_search"]["witness"])

    def test_bounded_failure_reports_pruning_reason(self):
        report = future_search_report(
            _contract(),
            RuntimeState(TaskPhase.PREPARE_OUTPUT, "continuation-test"),
            max_depth=0,
        )

        self.assertFalse(report["accepted"])
        self.assertEqual(report["bound"], 0)
        self.assertIn("bound", report["pruned_by"])
        self.assertIn("UserReview", report["failed_goals"])


if __name__ == "__main__":
    unittest.main()
