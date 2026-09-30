import unittest
from pathlib import Path

from rope_bench import load_fixture


FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "email_draft"


class EmailFixtureTests(unittest.TestCase):
    def test_email_draft_workflow_fixture_loads(self) -> None:
        workflow = load_fixture(FIXTURE_DIR / "workflow.json")

        self.assertEqual(workflow["fixture_id"], "email_draft_workflow_v1")
        self.assertIn("CollectSources", workflow["contract"]["phase_order"])
        self.assertEqual(
            workflow["contract"]["sink_policy"]["PrepareOutput"]["external_email"],
            "deny",
        )
        self.assertIn("read_email", workflow["trusted_tools"])

    def test_benign_trace_reaches_local_draft_without_external_sink(self) -> None:
        trace = load_fixture(FIXTURE_DIR / "benign_trace.json")

        self.assertIs(trace["contains_external_sink"], False)
        tools = [event.get("tool") for event in trace["events"]]
        sinks = [
            event.get("action", {}).get("sink")
            for event in trace["events"]
            if "action" in event
        ]

        self.assertIn("create_local_draft", tools)
        self.assertIn("show_to_user", tools)
        self.assertNotIn("external_email", sinks)

    def test_malicious_trace_contains_raw_send_and_stepup_attempt(self) -> None:
        trace = load_fixture(FIXTURE_DIR / "malicious_email_injection_trace.json")

        event_kinds = [event["kind"] for event in trace["events"]]
        recipients = [event.get("recipient") for event in trace["events"]]
        expected_obligations = trace["expected_required_obligations_before_send"]

        self.assertIn("stepup", event_kinds)
        self.assertIn("attacker@example.com", recipients)
        self.assertIn("redact:PII", expected_obligations)
        self.assertIn("summarize:short", expected_obligations)
        self.assertTrue(
            any(
                event.get("action", {}).get("sink") == "external_email"
                for event in trace["events"]
            )
        )


if __name__ == "__main__":
    unittest.main()
