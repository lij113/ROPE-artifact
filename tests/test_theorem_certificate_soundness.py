import unittest
from dataclasses import replace

from rope_bench.phase3_demo import raw_private_email_label
from rope_core import (
    CertificateReplayContext,
    Event,
    EventKind,
    RepairCertificate,
    parse_action,
    repair_raw_external_send,
    search_space_satisfies_host_policy,
    verify_repair_certificate_bundle,
)


def _raw_send_event() -> Event:
    return Event(
        event_id="certificate.raw_send",
        kind=EventKind.CALL,
        payload={
            "input_values": ("v_raw_email_body_attack",),
            "recipient": "attacker@example.com",
            "tool": "send_email",
        },
        action=parse_action(
            {
                "action": "send_email",
                "resource": "external_email",
                "sink": "external_email",
                "side_effect": "send",
                "purpose": "send_raw_customer_email",
            }
        ),
    )


def _context(**overrides) -> CertificateReplayContext:
    data = {
        "policy_hash": "paper_v0_policy_hash",
        "effect_profile_hash": "paper_v0_profile_hash",
        "approval_nonce": "phase3-demo-nonce",
        "approval_expiry": "2026-05-25T23:59:59Z",
        "current_time": "2026-05-25T12:00:00Z",
    }
    data.update(overrides)
    return CertificateReplayContext(**data)


class CertificateSoundnessTests(unittest.TestCase):
    def test_bundle_replay_accepts_canonical_equivalent_trace(self):
        outcome = repair_raw_external_send(_raw_send_event(), raw_private_email_label())
        old_trace = tuple(
            replace(event, payload=dict(reversed(list(event.payload.items()))))
            for event in outcome.old_trace
        )

        self.assertTrue(
            verify_repair_certificate_bundle(
                outcome.certificate,
                old_trace,
                outcome.new_trace,
                expected_context=_context(),
                observed_context=_context(),
            )
        )

    def test_bundle_replay_rejects_policy_profile_nonce_and_expiry_mismatch(self):
        outcome = repair_raw_external_send(_raw_send_event(), raw_private_email_label())

        for observed in (
            _context(policy_hash="changed_policy"),
            _context(effect_profile_hash="changed_profile"),
            _context(approval_nonce="changed_nonce"),
            _context(current_time="2026-05-26T00:00:00Z"),
        ):
            self.assertFalse(
                verify_repair_certificate_bundle(
                    outcome.certificate,
                    outcome.old_trace,
                    outcome.new_trace,
                    expected_context=_context(),
                    observed_context=observed,
                )
            )

    def test_bundle_replay_rejects_changed_value_identity(self):
        outcome = repair_raw_external_send(_raw_send_event(), raw_private_email_label())
        tampered = []
        for event in outcome.new_trace:
            if event.action is not None and event.action.action == "create_draft":
                payload = dict(event.payload)
                payload["input_values"] = ("v_redacted_summary_other",)
                tampered.append(replace(event, payload=payload))
            else:
                tampered.append(event)

        self.assertFalse(
            verify_repair_certificate_bundle(
                outcome.certificate,
                outcome.old_trace,
                tuple(tampered),
                expected_context=_context(),
                observed_context=_context(),
            )
        )

    def test_certificate_rejects_trivially_small_declared_search_space(self):
        outcome = repair_raw_external_send(_raw_send_event(), raw_private_email_label())
        narrow = RepairCertificate(
            old_trace_hash=outcome.certificate.old_trace_hash,
            new_trace_hash=outcome.certificate.new_trace_hash,
            discharged_obligations=outcome.certificate.discharged_obligations,
            contract_path=outcome.certificate.contract_path,
            invariants=outcome.certificate.invariants,
            search_space=("switch_to_local_draft",),
            cost_bound=outcome.certificate.cost_bound,
        )

        self.assertFalse(search_space_satisfies_host_policy(narrow.search_space))
        self.assertFalse(
            verify_repair_certificate_bundle(
                narrow,
                outcome.old_trace,
                outcome.new_trace,
                expected_context=_context(),
                observed_context=_context(),
            )
        )


if __name__ == "__main__":
    unittest.main()
