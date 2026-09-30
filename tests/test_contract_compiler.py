import unittest

from rope_core.contract_compiler import compile_task_contract, verify_contract_draft
from rope_core.contracts import sink_policy
from rope_core.model import SinkClass, TaskPhase


class ContractCompilerTests(unittest.TestCase):
    def test_email_draft_request_compiles_to_deny_by_default_contract(self):
        result = compile_task_contract("总结客户邮件，并起草回复给我确认")

        self.assertEqual(result.template, "email_draft")
        self.assertTrue(result.deny_by_default)
        self.assertIn("external_email_send", result.approval_nodes)
        self.assertGreater(result.confidence, 0.8)
        self.assertTrue(result.verified)
        self.assertEqual(result.counterexamples_after, ())
        self.assertEqual(
            sink_policy(result.contract, TaskPhase.PREPARE_OUTPUT, SinkClass.EXTERNAL_EMAIL),
            "deny",
        )
        self.assertEqual(
            sink_policy(result.contract, TaskPhase.USER_REVIEW, SinkClass.EXTERNAL_EMAIL),
            "conditional",
        )

    def test_unknown_request_becomes_fallback_review_contract(self):
        result = compile_task_contract("do something with many tools")

        self.assertEqual(result.template, "fallback_review_only")
        self.assertTrue(result.deny_by_default)
        self.assertIn("all_external_sinks", result.approval_nodes)
        self.assertLess(result.confidence, 0.5)
        self.assertTrue(result.verified)

    def test_llm_draft_cannot_waive_global_private_external_obligations(self):
        malicious_draft = {
            "template": "email_draft",
            "task_type": "summarize_and_send",
            "source_classes": ["internal_email"],
            "output_artifact": "email",
            "allowed_final_sinks": ["external_email"],
            "forbidden_sinks": [],
            "required_transformations": [],
            "permission_budget": ["mail.send"],
            "approval_tuple": {},
            "trusted_discharge_only": False,
            "evidence": ["email"],
        }

        result = compile_task_contract(
            "summarize customer mail and draft a reply",
            draft=malicious_draft,
        )

        self.assertIn("raw_exfiltration", result.counterexamples_before)
        self.assertIn("over_stepup", result.counterexamples_before)
        self.assertIn("add_external_obligations", result.refinement_steps)
        self.assertIn("downscope_permission_budget", result.refinement_steps)
        self.assertTrue(result.verified)
        self.assertEqual(result.counterexamples_after, ())
        self.assertIn("approve(bound_recipient)", result.draft["required_transformations"])
        self.assertIn("send_after_approval", result.draft["permission_budget"])
        self.assertNotIn("mail.send", result.draft["permission_budget"])

    def test_private_public_web_draft_is_refined_away(self):
        draft = {
            "template": "data_export",
            "task_type": "export",
            "source_classes": ["drive_doc"],
            "output_artifact": "web_query",
            "allowed_final_sinks": ["public_web"],
            "forbidden_sinks": [],
            "required_transformations": [],
            "permission_budget": ["read", "draft"],
            "approval_tuple": {},
            "trusted_discharge_only": True,
            "evidence": ["drive"],
        }

        result = compile_task_contract("summarize private drive files", draft=draft)

        self.assertIn("public_web_laundering", result.counterexamples_before)
        self.assertIn("remove_private_public_web", result.refinement_steps)
        self.assertNotIn("public_web", result.draft["allowed_final_sinks"])
        self.assertEqual(result.counterexamples_after, ())
        self.assertEqual(
            sink_policy(result.contract, TaskPhase.USER_REVIEW, SinkClass.PUBLIC_WEB),
            "deny",
        )

    def test_verifier_reports_fail_open_before_refinement(self):
        findings = verify_contract_draft(
            {
                "template": "bad",
                "task_type": "bad",
                "source_classes": ["internal_email"],
                "output_artifact": "email",
                "allowed_final_sinks": ["external_email"],
                "forbidden_sinks": [],
                "required_transformations": [],
                "permission_budget": ["mail.send"],
                "approval_tuple": {},
            }
        )

        self.assertTrue(any(finding.severity == "fail_open" for finding in findings))

    def test_non_mapping_approval_tuple_is_treated_as_unbound(self):
        result = compile_task_contract(
            "summarize private email and draft a reply",
            draft={
                "template": "email_draft",
                "task_type": "summarize_and_send",
                "source_classes": ["internal_email"],
                "output_artifact": "email",
                "allowed_final_sinks": ["external_email"],
                "forbidden_sinks": [],
                "required_transformations": ["redact(PII)", "summarize(short)"],
                "permission_budget": ["read"],
                "approval_tuple": ["recipient-bound approval"],
            },
        )

        self.assertTrue(result.verified)
        self.assertEqual(result.counterexamples_after, ())
        self.assertIn("bind_approval_tuple", result.refinement_steps)

    def test_underspecified_send_relevant_details_falls_back_to_review_only(self):
        result = compile_task_contract("send the client the relevant details")

        self.assertEqual(result.template, "fallback_review_only")
        self.assertTrue(result.verified)
        self.assertTrue(result.fallback_used is False)
        self.assertIn("all_external_sinks", result.approval_nodes)
        self.assertEqual(result.draft["allowed_final_sinks"], ["local_file"])


if __name__ == "__main__":
    unittest.main()
