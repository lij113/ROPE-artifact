# ROPE Semantic Spec

Version: `paper_v0`

ROPE accepts a candidate MCP event only when the finite admissibility judgment
holds:

```text
Admit(Gamma, e) =
  LocalValid(Gamma, e)
  and ObligationSafe(Gamma, e)
  and NecessaryPerms(Gamma, e)
  and FutureAccept(Gamma, e)
```

`Gamma` contains the task phase, provenance-obligation graph identifier, value
labels, permission state, approval state, model-context label state, and audit
state.

`FutureAccept` does not search over raw prompts or concrete tool arguments. It
searches over the finite abstract state:

```text
Gamma_hat = <q, rho_bar, P, B, R, N, H, T>
```

The abstraction retains:

| Component | Meaning | Why it is retained |
|---|---|---|
| `q` | task phase and accepting state | decides legal continuation phase |
| `rho_bar` | outstanding obligations by sink and protected source/value class | decides future sink legality |
| `P` | task-scoped permission / step-up state | decides permission necessity |
| `B` | disclosure, write, public-network, and step-up budget | decides budget exhaustion |
| `R` | canonical recipient, domain, purpose, task id, value id, sink class | prevents approval or recipient laundering |
| `N` | approval nonce, expiry, approved tuple, approval status | prevents stale or replayed approval |
| `H` | policy hash, profile hash, schema hash, server identity, trust tier | prevents profile/policy drift confusion |
| `T` | abstract tool, broker, trusted sanitizer, and local fallback availability | decides whether a legal continuation is executable |

The abstraction discards raw natural-language wording, concrete token bytes,
cosmetic formatting, exact OAuth token contents, and concrete tool names when
multiple tools implement the same trusted abstract effect. These fields may be
discarded only after their policy-relevant effects are folded into the retained
components above.

## Executable Search (`rope_core/future.py`, `rope_core/runtime.py`)

The host runtime (`HostRuntime`) keeps the concrete state: phase, value store
with labels and completed trusted transforms, remaining resources, granted
permissions, recorded approvals and spent nonces, realized goals, budgets, and
the model-context label. Before every event it builds the abstract view that
`admit` searches:

| Abstract component | Implementation |
|---|---|
| `q` | contract phase; accepting phases and required (non-optional) goals define the marked states |
| `rho_bar` | every source-derived value as (data class, sources, completed transforms, residual atoms per sink); atoms discharged by a valid bound approval are removed; `stepup(p)` atoms count as discharged once `p` is granted |
| `P` | granted permissions |
| `B` | remaining disclosure, public-network, write, and step-up budgets |
| `R`, `N` | folded into `rho_bar`: an approval discharges its atom only for the value, sink, purpose, recipient, task, policy version, unexpired window, and unspent nonce it binds |
| `H` | a profile whose schema, identity, sink, or side effect drifts is downgraded to the pessimistic profile and leaves the search space |
| `T` | abstract actions derived from the contract's task tools and their host profiles: reads of allowed sources that still exist, trusted transforms, deliveries to contract goals, removals, user approvals for goal tuples, and step-ups within the contract's permission budget |

`FutureAccept` simulates the event on a copy of the runtime, abstracts the
post-event state, and runs a breadth-first search of depth at most `k`
(default 8) for a marked state. A candidate witness is returned only after it
replays through the same transition function. `NecessaryPerms` accepts a
step-up for `p` only if the same search, started from the current state with
`p` granted, finds a witness containing an action that uses `p`, or if `p` is a
declared early permission in the trusted contract's permission plan and the
request binds purpose, resource, nonce, and expiry. A step-up request cannot
declare its own need.

Precision rule: recipient, purpose, nonce, expiry, policy/profile version, sink
class, side-effect class, trust tier, and trusted tool availability are not
optional metadata. If a proposed abstraction drops one of these fields for a
high-risk action, the profile or contract is under-specified and the runtime
must reject, ask, or fall back to local-only behavior.

## Necessary Permissions and Early Consent

`NecessaryPerms` is not a ban on all early authorization. It rejects unbounded
permission front-running while allowing two bounded cases:

- Witnessed step-up: the permission appears in a bounded legal continuation
  from the current abstract state.
- Declared early step-up: the permission is listed in a trusted task contract or
  workflow permission plan and the request binds purpose, resource, approval
  nonce, expiry, policy/profile version, and recipient for send-like scopes.

The declared-early path is how ROPE represents batched consent,
user-configured workflows, or explicitly declared future permission needs. It
does not accept wildcard, admin, all-resource, or any-recipient grants as early
evidence. If the task intent is underspecified, the compiler creates a
local-review contract or an approval/clarification node rather than treating a
future permission as necessary.

The Phase 5.1 freeze fixes:

- task phases: `CollectSources`, `Transform`, `PrepareOutput`, `UserReview`,
  `CommitOrSend`
- future-search bound: `8` for the host runtime; the trace suites also report `4`, `6`, and `10`
- sink classes: local display, local file, internal service, same-org message,
  external email, public web, code execution, payment, destructive write
- obligation atoms: `top`, `redact`, `summarize`, `approve`, `localize`,
  `stepup`, `bind`, `audit`
- repair search space: `redact`, `summarize`, `downscope_args`,
  `switch_to_local_draft`, `ask_confirm`

## Obligation Composition

For a derived value `v' = f(v1, ..., vn)`, obligations are joined per sink:

```text
rho_v'(s) = (rho_v1(s) and ... and rho_vn(s) and rho_f_add(s)) - D_f(s)
```

Rules:

- Multi-source merge is a sink-specific union/conjunction of required atoms,
  not an intersection. If one source owes `redact(PII)` and another owes
  `audit(reason)`, the derived value owes both for that sink.
- Public and private sources are not averaged. Private-source obligations
  remain attached to the mixed derived value.
- `summarize(k)` and `redact(c)` are separate atoms. A verifier for one does
  not discharge the other.
- Transform order is represented by derivation edges, not by ordering inside
  the conjunction. `summarize` then `redact` and `redact` then `summarize` are
  both valid only when the final output has trusted discharge evidence for all
  required atoms. If a later transform consumes the raw source again, raw-source
  obligations rejoin the output.
- Partial sanitizer discharge removes only exact matching atoms from the
  declared output value. Remaining atoms stay residual.
- Approval is not a global permission. It must bind the candidate disclosure by
  exact value id or certified source-to-derived relation, and must match data
  class, sink, purpose, recipient, task id, nonce, expiry, and policy/profile
  version. Approval for a redacted summary does not authorize raw-body
  disclosure; approval for one recipient or purpose does not transfer.

Boundedness: `FutureAccept` is a finite search over the abstract task automaton
and retained obligation/binding state. The prototype does not claim open-world
completeness for arbitrary MCP agents. Each decision must be able to report the
search bound, expanded abstract phases, and a witness continuation or failure
reason.

False-accept / false-reject boundary:

- Dropping a policy-relevant retained field can create false accepts. This is
  treated as a contract/profile error, not as an allowed optimization.
- Keeping too much detail, missing tool availability, or using too small a
  bound can create false rejections. The review-v3 false-rejection taxonomy
  reports these as utility risks and feeds profile/contract refinement.
