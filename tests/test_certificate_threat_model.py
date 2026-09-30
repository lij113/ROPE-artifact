import unittest

from rope_bench.phase3_demo import raw_private_email_label
from rope_core import (
    CertificateReplayContext,
    Event,
    EventKind,
    parse_action,
    repair_raw_external_send,
    verify_repair_certificate_bundle,
    witness_cache_valid,
)


def _raw_send_event() -> Event:
    return Event(
        event_id="certificate-threat.raw_send",
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
        "task_id": "task-email-draft-1",
        "session_id": "session-a",
        "sanitizer_manifest_hash": "sanitizers:v1",
        "tool_availability_hash": "tools:v1",
        "permission_epoch": "permissions:v1",
        "external_state_hash": "mailbox-snapshot:v1",
    }
    data.update(overrides)
    return CertificateReplayContext(**data)


class CertificateThreatModelTests(unittest.TestCase):
    def _repair_outcome(self):
        return repair_raw_external_send(_raw_send_event(), raw_private_email_label())

    def _verify_with(self, observed: CertificateReplayContext) -> bool:
        outcome = self._repair_outcome()
        return verify_repair_certificate_bundle(
            outcome.certificate,
            outcome.old_trace,
            outcome.new_trace,
            expected_context=_context(),
            observed_context=observed,
        )

    def test_certificate_is_bound_to_task_and_session(self):
        self.assertFalse(self._verify_with(_context(task_id="other-task")))
        self.assertFalse(self._verify_with(_context(session_id="session-b")))

    def test_certificate_rejects_sanitizer_or_tool_drift(self):
        self.assertFalse(
            self._verify_with(_context(sanitizer_manifest_hash="sanitizers:v2"))
        )
        self.assertFalse(
            self._verify_with(_context(tool_availability_hash="tools:v2"))
        )

    def test_certificate_rejects_permission_or_external_state_drift(self):
        self.assertFalse(self._verify_with(_context(permission_epoch="permissions:v2")))
        self.assertFalse(
            self._verify_with(_context(external_state_hash="mailbox-snapshot:v2"))
        )

    def test_witness_cache_is_not_reused_across_stale_context(self):
        self.assertTrue(witness_cache_valid(_context(), _context()))
        self.assertFalse(
            witness_cache_valid(_context(), _context(policy_hash="policy:v2"))
        )
        self.assertFalse(
            witness_cache_valid(_context(), _context(current_time="2026-05-26T00:00:00Z"))
        )


if __name__ == "__main__":
    unittest.main()
