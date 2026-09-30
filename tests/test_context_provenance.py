import unittest

from rope_core.context_provenance import (
    clear_context,
    empty_context,
    label_model_generated_argument,
    observe_model_input,
)
from rope_core.model import ProvenanceMode, SinkClass, ValueLabel
from rope_core.obligations import approve, conjunction, redact, summarize, top
from rope_core.semantics import obligation_safe


def _private_email_label() -> ValueLabel:
    return ValueLabel(
        source_ids=frozenset({"email:raw:17"}),
        sensitivity="private",
        purposes=frozenset({"customer_reply"}),
        obligations={
            SinkClass.EXTERNAL_EMAIL: conjunction(
                redact("PII"),
                summarize("short"),
                approve(
                    data_class="email_body",
                    sink="external_email",
                    purpose="customer_reply",
                    recipient="customer@example.com",
                ),
            ),
            SinkClass.PUBLIC_WEB: conjunction(redact("PII"), summarize("aggregate")),
        },
    )


class ContextProvenanceTests(unittest.TestCase):
    def test_raw_text_fresh_literal_remains_untracked(self):
        context = empty_context(mode=ProvenanceMode.RAW_TEXT)
        context = observe_model_input(
            context,
            value_id="email:raw:17",
            label=_private_email_label(),
        )

        fresh_arg = label_model_generated_argument(context)

        self.assertEqual(fresh_arg.source_ids, frozenset())
        self.assertTrue(obligation_safe(fresh_arg, SinkClass.EXTERNAL_EMAIL))

    def test_context_closed_fresh_literal_inherits_visible_obligations(self):
        context = empty_context(mode=ProvenanceMode.CONTEXT_CLOSED)
        context = observe_model_input(
            context,
            value_id="email:raw:17",
            label=_private_email_label(),
        )

        fresh_arg = label_model_generated_argument(context)

        self.assertIn("email:raw:17", fresh_arg.source_ids)
        self.assertFalse(obligation_safe(fresh_arg, SinkClass.EXTERNAL_EMAIL))
        self.assertFalse(obligation_safe(fresh_arg, SinkClass.PUBLIC_WEB))

    def test_context_epoch_reset_restores_precision_after_trusted_summary(self):
        context = empty_context(mode=ProvenanceMode.CONTEXT_EPOCH)
        context = observe_model_input(
            context,
            value_id="email:raw:17",
            label=_private_email_label(),
        )
        blocked_arg = label_model_generated_argument(context)
        self.assertFalse(obligation_safe(blocked_arg, SinkClass.EXTERNAL_EMAIL))

        redacted_summary = ValueLabel(
            source_ids=frozenset({"email:summary:redacted:17"}),
            sensitivity="internal",
            purposes=frozenset({"customer_reply"}),
            obligations={SinkClass.EXTERNAL_EMAIL: top()},
        )
        clean_context = clear_context(
            context,
            new_epoch_id="epoch-1",
            retained_labels=(redacted_summary,),
        )
        fresh_arg = label_model_generated_argument(clean_context)

        self.assertEqual(clean_context.epoch_id, "epoch-1")
        self.assertNotIn("email:raw:17", fresh_arg.source_ids)
        self.assertIn("email:summary:redacted:17", fresh_arg.source_ids)
        self.assertTrue(obligation_safe(fresh_arg, SinkClass.EXTERNAL_EMAIL))

    def test_context_closed_joins_multiple_visible_values(self):
        context = empty_context(mode=ProvenanceMode.CONTEXT_CLOSED)
        context = observe_model_input(
            context,
            value_id="email:raw:17",
            label=_private_email_label(),
        )
        public_label = ValueLabel(
            source_ids=frozenset({"docs:public:1"}),
            sensitivity="public",
            purposes=frozenset({"customer_reply"}),
            obligations={SinkClass.PUBLIC_WEB: top()},
        )
        context = observe_model_input(
            context,
            value_id="docs:public:1",
            label=public_label,
        )

        fresh_arg = label_model_generated_argument(context)

        self.assertEqual(
            fresh_arg.source_ids,
            frozenset({"email:raw:17", "docs:public:1"}),
        )
        self.assertFalse(obligation_safe(fresh_arg, SinkClass.EXTERNAL_EMAIL))


if __name__ == "__main__":
    unittest.main()
