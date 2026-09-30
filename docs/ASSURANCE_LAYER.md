# ROPE Assurance Layer

The assurance layer reduces trust in arbitrary MCP tools by moving high-risk
authority into small host-side artifacts:

| Artifact | Purpose | Cannot do |
| --- | --- | --- |
| Trust-tiered profile | Classifies tool effects and discharge authority | Server metadata cannot promote itself |
| Capability broker | Holds high-risk side-effect tokens and executes sends/writes/step-ups | Does not run LLMs or accept unbound approvals |
| Drift monitor | Downgrades changed schemas, identities, sinks, or side effects | Never promotes a profile |
| Sanitizer evidence verifier | Checks input/output hashes and obligation-specific evidence | Does not accept model sanitizer self-certification |
| Global safety envelope | Bounds generated contracts and task slots | Cannot be overridden by LLM-generated contracts |

## Remaining Attack Surface

| Surface | Risk | Control |
| --- | --- | --- |
| Broker compromise | Broker holds high-risk tokens | Keep API minimal; require cert, nonce, recipient, value, task, and policy binding |
| Verifier unsoundness | A leaky output is accepted as sanitized | Prefer deterministic verifiers; semantic obligations fall back to approval/human review |
| Drift-induced denial of service | Attackers trigger schema/effect changes to force downgrade | Drift only downgrades; observation mode and local-only fallback preserve review workflows |
| Profile promotion bug | Server hints become trusted | Tier transitions are host-only and covered by tests |
| Approval replay | Old approval reused for new sink/value/recipient | Single-use nonce, expiry, and policy/profile hash binding |

The layer does not eliminate TCB risk. It narrows the TCB from every MCP tool to
the host broker, verifier registry, policy store, and profile reviewer.
