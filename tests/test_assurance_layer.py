import unittest

from rope_core.assurance import (
    AssuranceDecisionKind,
    AssuranceTier,
    ApprovalBinding,
    BrokerRequest,
    GlobalSafetyEnvelope,
    ProfileAssurance,
    RepairCertificateView,
    SanitizerEvidence,
    ToolObservation,
    apply_profile_drift,
    broker_side_effect,
    residual_attack_surface,
    stable_hash,
    validate_profile_assurance,
    verify_sanitizer_evidence,
)
from rope_core.model import Obligation, SideEffect, SinkClass, TrustLevel


class AssuranceLayerTests(unittest.TestCase):
    def _profile(self, **overrides):
        base = {
            "tool_name": "send_email",
            "tier": AssuranceTier.VERIFIED,
            "trust": TrustLevel.AUDITED,
            "schema_hash": "schema:v1",
            "server_identity": "mail.example",
            "policy_hash": "policy:v1",
            "allowed_sinks": frozenset({SinkClass.EXTERNAL_EMAIL}),
            "allowed_side_effects": frozenset({SideEffect.SEND}),
            "discharge_obligations": (),
            "broker_required": True,
            "regression_cases": ("send_bound_approval",),
        }
        base.update(overrides)
        return ProfileAssurance(**base)

    def test_server_hint_cannot_discharge_obligations(self):
        profile = self._profile(
            tier=AssuranceTier.SERVER_HINT,
            trust=TrustLevel.SERVER_HINT,
            discharge_obligations=(Obligation.atom("redact", **{"class": "PII"}),),
            broker_required=False,
            regression_cases=(),
        )
        decision = validate_profile_assurance(profile)
        self.assertEqual(decision.kind, AssuranceDecisionKind.DOWNGRADE)
        self.assertIn("server_hint_discharge_claim", decision.risks)
        self.assertEqual(decision.profile.discharge_obligations, ())

    def test_high_risk_profile_without_broker_is_downgraded(self):
        profile = self._profile(broker_required=False)
        decision = validate_profile_assurance(profile)
        self.assertEqual(decision.kind, AssuranceDecisionKind.DOWNGRADE)
        self.assertIn("high_risk_effect_without_broker", decision.risks)
        self.assertTrue(decision.profile.broker_required)

    def test_profile_drift_only_reduces_authority(self):
        profile = self._profile()
        observation = ToolObservation(
            tool_name="send_email",
            schema_hash="schema:v2",
            server_identity="mail.example",
            observed_sink=SinkClass.PUBLIC_WEB,
            observed_side_effect=SideEffect.SEND,
        )
        decision = apply_profile_drift(profile, observation)
        self.assertEqual(decision.kind, AssuranceDecisionKind.DOWNGRADE)
        self.assertEqual(decision.profile.tier, AssuranceTier.UNTRUSTED)
        self.assertEqual(decision.profile.trust, TrustLevel.UNTRUSTED)
        self.assertEqual(decision.profile.discharge_obligations, ())
        self.assertIn("schema_hash_drift", decision.risks)
        self.assertIn("observed_sink_outside_profile", decision.risks)

    def test_capability_broker_requires_bound_certificate(self):
        profile = self._profile()
        request = BrokerRequest(
            tool_name="send_email",
            sink=SinkClass.EXTERNAL_EMAIL,
            side_effect=SideEffect.SEND,
            task_id="task-1",
            value_id="summary-1",
            purpose="customer_reply",
            recipient="customer@example.com",
            nonce="nonce-1",
            policy_hash="policy:v1",
            trace_hash="trace-1",
        )
        approval = ApprovalBinding(
            task_id="task-1",
            value_id="summary-1",
            sink=SinkClass.EXTERNAL_EMAIL,
            purpose="customer_reply",
            recipient="customer@example.com",
            nonce="nonce-1",
            expiry="2026-05-28T00:00:00Z",
            policy_hash="policy:v1",
        )
        cert = RepairCertificateView(
            trace_hash="trace-1",
            policy_hash="policy:v1",
            approval=approval,
            invariants=frozenset({"bound_approval", "no_raw_body"}),
        )
        self.assertTrue(broker_side_effect(request, cert, profile).allowed)

        swapped = BrokerRequest(
            **{**request.__dict__, "recipient": "attacker@example.com"}
        )
        decision = broker_side_effect(swapped, cert, profile)
        self.assertFalse(decision.allowed)
        self.assertIn("approval_binding_mismatch", decision.reason)

    def test_sanitizer_evidence_requires_independent_verification(self):
        input_text = "Alice email alice@example.com and phone 415-555-1212"
        output_text = "Alice contact information was removed."
        evidence = SanitizerEvidence(
            sanitizer_id="pii-redactor",
            tier=AssuranceTier.VERIFIED,
            input_hash=stable_hash(input_text),
            output_hash=stable_hash(output_text),
            obligation=Obligation.atom("redact", **{"class": "PII"}),
            policy_hash="policy:v1",
            verifier_id="regex+ner:v1",
            verifier_passed=True,
            removed_spans=("alice@example.com", "415-555-1212"),
            residual_risk="low",
        )
        decision = verify_sanitizer_evidence(
            evidence, input_text=input_text, output_text=output_text
        )
        self.assertTrue(decision.accepted)
        self.assertEqual(decision.discharge_tier, "verified_discharge")

        leaky = "Alice email alice@example.com"
        bad = SanitizerEvidence(
            **{**evidence.__dict__, "output_hash": stable_hash(leaky)}
        )
        decision = verify_sanitizer_evidence(bad, input_text=input_text, output_text=leaky)
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.reason, "removed_span_still_present")

    def test_semantic_sanitizer_obligation_does_not_auto_discharge(self):
        evidence = SanitizerEvidence(
            sanitizer_id="semantic-filter",
            tier=AssuranceTier.VERIFIED,
            input_hash=stable_hash("secret strategy"),
            output_hash=stable_hash("safe summary"),
            obligation=Obligation.atom("remove_confidential_strategy"),
            policy_hash="policy:v1",
            verifier_id="llm-judge",
            verifier_passed=True,
        )
        decision = verify_sanitizer_evidence(
            evidence, input_text="secret strategy", output_text="safe summary"
        )
        self.assertFalse(decision.accepted)
        self.assertEqual(decision.discharge_tier, "heuristic_only")

    def test_residual_attack_surface_is_explicit(self):
        surfaces = {row["surface"] for row in residual_attack_surface()}
        self.assertIn("capability_broker_compromise", surfaces)
        self.assertIn("verifier_unsoundness", surfaces)


if __name__ == "__main__":
    unittest.main()
