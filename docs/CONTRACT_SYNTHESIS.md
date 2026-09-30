# Contract Synthesis Boundary

ROPE treats contract synthesis as verified proposal, not trusted natural
language interpretation. A model may draft task-specific slots, but a
deterministic verifier decides whether those slots can enter the trusted runtime
contract.

## Pipeline

1. Proposer drafts slots:
   - template
   - source classes
   - output artifact
   - allowed final sinks
   - required transformations
   - permission budget
   - approval tuple
2. Runtime merges the draft with the non-overridable global safety envelope.
3. Verifier checks:
   - schema completeness
   - private source to external/public sink obligations
   - approval binding over data, sink, purpose, recipient, nonce, expiry
   - permission budget and over-stepup
   - trusted-discharge-only requirement
4. Counterexample suite probes raw exfiltration, public-web laundering, stale
   approval, recipient swap, over-stepup, untrusted sanitizer, and destructive
   write without step-up.
5. Refinement either adds obligations, removes unsafe sinks, down-scopes
   permissions, binds approval tuples, or falls back to local-review only.

## Examples

| Draft | Verifier result | Runtime outcome |
|---|---|---|
| Private email -> local draft -> external email after redact, summarize, bound approval, send-after-approval | Accepted; no counterexamples | Trusted contract with frozen policy/profile hash |
| "Send the client the relevant details" -> broad `mail.send`, no source class, no bound recipient | Rejected as underspecified and overbroad | Local-review-only contract or clarification request |
| Private Drive -> public web with no sanitizer evidence | Counterexamples: public-web laundering, raw exfiltration, untrusted sanitizer | Public sink removed; trusted discharge required; fallback if still fail-open |

## Boundary

The verifier can reject or refine a draft, but it cannot infer missing user
intent. When the request is underspecified, ROPE deliberately fails closed into
local review or asks for more fields. This is a utility cost, not a safety
success, and it should be measured in false-rejection/refinement reports.
