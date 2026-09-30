import unittest

from rope_core import (
    AdmissibilityDecision,
    DecisionKind,
    Event,
    EventKind,
    Obligation,
    RepairCertificate,
    RuntimeState,
    SideEffect,
    SinkClass,
    StructuredAction,
    TaskPhase,
    ValueLabel,
)


class CoreStubTests(unittest.TestCase):
    def test_core_type_names_match_phase1_plan(self) -> None:
        action = StructuredAction(
            action="create_draft",
            resource="local_draft",
            sink=SinkClass.LOCAL_FILE,
            side_effect=SideEffect.WRITE,
            purpose="customer_reply_draft",
        )
        event = Event(event_id="e1", kind=EventKind.CALL, action=action)
        decision = AdmissibilityDecision(kind=DecisionKind.ALLOW, reason="stub")

        self.assertEqual(event.action, action)
        self.assertIs(decision.kind, DecisionKind.ALLOW)

    def test_label_and_certificate_stubs_are_constructible(self) -> None:
        obligation = Obligation.conjunction(
            Obligation.atom("redact", klass="PII"),
            Obligation.atom("summarize", granularity="short"),
        )
        label = ValueLabel(
            source_ids=frozenset({"internal_mailbox"}),
            sensitivity="private",
            purposes=frozenset({"customer_reply"}),
            obligations={SinkClass.EXTERNAL_EMAIL: obligation},
        )
        state = RuntimeState(
            task_phase=TaskPhase.PREPARE_OUTPUT,
            provenance_graph_id="graph-email-demo",
            labels={"v1": label},
        )
        cert = RepairCertificate(
            old_trace_hash="old",
            new_trace_hash="new",
            discharged_obligations=("redact:PII",),
            contract_path=(TaskPhase.COLLECT_SOURCES, TaskPhase.PREPARE_OUTPUT),
            invariants=("no_raw_body_external_sink",),
            search_space=("redact", "switch_to_local_draft"),
            cost_bound=2.0,
        )

        self.assertEqual(
            state.labels["v1"].obligations[SinkClass.EXTERNAL_EMAIL].name,
            "and",
        )
        self.assertEqual(cert.invariants, ("no_raw_body_external_sink",))


if __name__ == "__main__":
    unittest.main()
