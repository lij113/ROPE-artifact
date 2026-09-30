# Certificate Threat Model

ROPE repair certificates are verifier artifacts, not free-standing claims that
the external world can be replayed exactly.

## Consumers

| Consumer | Use | Trust level |
|---|---|---|
| Runtime verifier | Decides whether a repaired trace is certified under the current policy/profile context. | Primary proof surface. |
| Audit log | Stores what was repaired, which obligations were discharged, and which hashes/bindings were checked. | Derived from verifier result. |
| User explanation | Summarizes why the runtime blocked or repaired an action. | Human-readable explanation, not proof. |
| Compliance evidence | Provides replayable artifacts for later inspection. | Evidence bundle, not a legal guarantee by itself. |

## Replay Binding

A certificate replay context binds:

- `policy_hash`
- `effect_profile_hash`
- `task_id`
- `session_id`
- `approval_nonce`
- `approval_expiry`
- `sanitizer_manifest_hash`
- `tool_availability_hash`
- `permission_epoch`
- `external_state_hash`
- `current_time`

Replay rejects if any of these fields drift. The current artifact enforces this
in `verify_repair_certificate_bundle` and uses the same context comparison for
cached continuation witnesses.

## Boundary Cases

- Nondeterministic tools are not re-executed. The verifier checks recorded
  events, value ids, payload hashes, effect classes, approvals, and declared
  invariants.
- Mutable external state must be represented by a snapshot/hash. If the state
  hash changes, the certificate is stale and the runtime must rerun
  admissibility.
- Sanitizer implementation changes require a new sanitizer manifest hash and
  new evidence for discharged atoms.
- Certificates cannot be replayed across tasks or sessions.
- FutureAccept witnesses are advisory. They are not standing authorizations and
  cannot be reused after policy, profile, permission, tool, approval,
  sanitizer, or external-state drift.
