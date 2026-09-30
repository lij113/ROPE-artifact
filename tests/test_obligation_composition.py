import unittest

from rope_core.model import StructuredAction, ToolEffect, TrustLevel, SideEffect, SinkClass, ValueLabel
from rope_core.obligations import approve, audit, conjunction, localize, redact, remove_discharged, summarize
from rope_core.semantics import discharge_label, obligation_safe, propagate_label


def _transform_effect(name: str, *discharges):
    return ToolEffect(
        tool_name=name,
        action=StructuredAction(
            action=name,
            resource="host_sanitizer",
            sink=SinkClass.LOCAL_FILE,
            side_effect=SideEffect.TRANSFORM,
            purpose="sanitize",
        ),
        trust=TrustLevel.AUDITED,
        discharges=tuple(discharges),
    )


def _email_label() -> ValueLabel:
    return ValueLabel(
        source_ids=frozenset({"email:1"}),
        sensitivity="private",
        purposes=frozenset({"customer_reply"}),
        obligations={
            SinkClass.EXTERNAL_EMAIL: conjunction(
                redact("PII"),
                summarize("short"),
                approve("email_body", "external_email", "customer_reply", "customer@example.com"),
            ),
            SinkClass.PUBLIC_WEB: conjunction(redact("PII"), localize("host")),
        },
    )


def _crm_label() -> ValueLabel:
    return ValueLabel(
        source_ids=frozenset({"crm:7"}),
        sensitivity="private",
        purposes=frozenset({"customer_reply"}),
        obligations={
            SinkClass.EXTERNAL_EMAIL: audit("crm_disclosure"),
            SinkClass.PUBLIC_WEB: approve(
                "crm_record", "public_web", "support_lookup", "none"
            ),
        },
    )


def _atom_names(label: ValueLabel, sink: SinkClass) -> set[str]:
    return {atom.name for atom in label.obligations[sink].atoms()}


class ObligationCompositionTests(unittest.TestCase):
    def test_multi_source_merge_uses_sink_specific_join(self):
        merged = propagate_label((_email_label(), _crm_label()))

        self.assertEqual(merged.source_ids, frozenset({"email:1", "crm:7"}))
        self.assertEqual(
            _atom_names(merged, SinkClass.EXTERNAL_EMAIL),
            {"redact", "summarize", "approve", "audit"},
        )
        self.assertEqual(
            _atom_names(merged, SinkClass.PUBLIC_WEB),
            {"redact", "localize", "approve"},
        )

    def test_partial_sanitizer_discharge_leaves_remaining_atoms(self):
        label = _email_label()
        summarized = discharge_label(label, _transform_effect("summarize_short", summarize("short")))
        self.assertEqual(
            _atom_names(summarized, SinkClass.EXTERNAL_EMAIL),
            {"redact", "approve"},
        )

        redacted_summary = discharge_label(
            summarized,
            _transform_effect("redact_pii", redact("PII")),
        )
        self.assertEqual(
            _atom_names(redacted_summary, SinkClass.EXTERNAL_EMAIL),
            {"approve"},
        )

    def test_summarize_and_redact_order_is_trace_sequential(self):
        label = _email_label()

        summarize_then_redact = discharge_label(
            discharge_label(label, _transform_effect("summarize_short", summarize("short"))),
            _transform_effect("redact_pii", redact("PII")),
        )
        redact_then_summarize = discharge_label(
            discharge_label(label, _transform_effect("redact_pii", redact("PII"))),
            _transform_effect("summarize_short", summarize("short")),
        )

        self.assertEqual(
            _atom_names(summarize_then_redact, SinkClass.EXTERNAL_EMAIL),
            {"approve"},
        )
        self.assertEqual(
            _atom_names(redact_then_summarize, SinkClass.EXTERNAL_EMAIL),
            {"approve"},
        )

    def test_approval_discharge_requires_exact_binding(self):
        label = _email_label()
        base_discharges = (redact("PII"), summarize("short"))
        wrong_approval = approve(
            "email_body", "external_email", "customer_reply", "attacker@example.com"
        )
        right_approval = approve(
            "email_body", "external_email", "customer_reply", "customer@example.com"
        )

        self.assertFalse(
            obligation_safe(
                label,
                SinkClass.EXTERNAL_EMAIL,
                discharged=(*base_discharges, wrong_approval),
            )
        )
        self.assertTrue(
            obligation_safe(
                label,
                SinkClass.EXTERNAL_EMAIL,
                discharged=(*base_discharges, right_approval),
            )
        )

    def test_sink_specific_approval_does_not_discharge_other_sink(self):
        label = _crm_label()
        external_approval = approve(
            "crm_record", "external_email", "support_lookup", "none"
        )
        remaining_public = remove_discharged(
            label.obligations[SinkClass.PUBLIC_WEB],
            (external_approval,),
        )

        self.assertFalse(remaining_public.is_top())
        self.assertEqual(_atom_names(label, SinkClass.PUBLIC_WEB), {"approve"})


if __name__ == "__main__":
    unittest.main()
