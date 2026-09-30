import unittest

from rope_core import (
    Obligation,
    approve,
    conjunction,
    format_obligation,
    is_satisfied,
    parse_conjunction,
    parse_obligation,
    redact,
    remove_discharged,
    summarize,
    top,
)


class ObligationAlgebraTests(unittest.TestCase):
    def test_parse_and_pretty_print_supported_atoms(self) -> None:
        obligations = [
            "top",
            "redact:PII",
            "summarize:short",
            "approve:email_body:external_email:customer_reply:alice@example.com",
            "localize:host",
            "stepup:email.send",
            "bind:nonce123:email.send",
            "audit:external_send",
        ]

        pretty = [format_obligation(parse_obligation(item)) for item in obligations]

        self.assertEqual(pretty[0], "top")
        self.assertIn("redact", pretty[1])
        self.assertIn("summarize", pretty[2])
        self.assertIn("approve", pretty[3])

    def test_conjunction_flattens_top_and_supports_matching(self) -> None:
        obligation = conjunction(top(), redact("PII"), summarize("short"))
        same_redact = parse_obligation("redact:PII")

        self.assertEqual(len(obligation.atoms()), 2)
        self.assertTrue(redact("PII").matches(same_redact))
        self.assertFalse(summarize("short").matches(same_redact))

    def test_satisfaction_and_removal(self) -> None:
        obligation = parse_conjunction(
            [
                "redact:PII",
                "summarize:short",
                "approve:email_body:external_email:customer_reply:alice@example.com",
            ]
        )
        discharged = (
            redact("PII"),
            summarize("short"),
            approve(
                "email_body",
                "external_email",
                "customer_reply",
                "alice@example.com",
            ),
        )

        self.assertTrue(is_satisfied(obligation, discharged))
        self.assertEqual(remove_discharged(obligation, discharged), Obligation.top())


if __name__ == "__main__":
    unittest.main()

