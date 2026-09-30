# Expressiveness Taxonomy

This note answers the recurring novelty question:

> Is ROPE more than IFC with declassification, approval tokens, typestate, and
> runtime verification?

## Short Answer

ROPE should **not** claim absolute expressiveness beyond arbitrary runtime
verification. A sufficiently large finite automaton can simulate any finite
ROPE instance.

The defensible novelty claim is narrower and stronger:

ROPE identifies the right runtime object for tool-using agents: a residual
future containing task state, provenance-labeled values, sink-indexed residual
obligations, approval bindings, permission necessity, trust/profile versions,
and bounded legal-continuation witnesses. If IFC, approval, and typestate are
extended to carry that object and return repair/certificate witnesses, the
result is ROPE-like.

## Formal Shape

ROPE admits an event when:

```text
Admit(Gamma, e) =
  LocalValid(Gamma, e)
  and ObligationSafe(Gamma, e)
  and NecessaryPerms(Gamma, e)
  and exists kappa <= k.
      Accepts(C, simulate(Gamma, e), kappa)
      and kappa satisfies obligations and permission necessity
```

IFC/declassification checks current source-to-sink release.
Typestate/runtime verification checks event sequencing.
Approval/capability systems check authority.

ROPE checks whether the **post-event prefix** still has a legal continuation
under the joined state of all three.

## Minimal Separation Examples

| Omitted object | Trace prefix | Local mechanism result | ROPE result |
| --- | --- | --- | --- |
| Compound value obligations | `send(summary, raw_attachment)` after approving only the summary | IFC/declass may see an approved release for the summary argument | Rejects because `raw_attachment` still owes external-email obligations |
| Approval binding | approved redacted summary to `client@example.com`, then replay approval for raw body or different recipient | Approval token may remain valid at resource/action level | Rejects value/recipient/purpose/nonce mismatch |
| Permission necessity | poisoned tool result asks for `email.send` before review | Scope or step-up system may permit the request | Rejects if no legal continuation from the post-stepup prefix needs that permission |
| Future legality | local call is phase-valid, but consumes a budget or phase edge that leaves no legal completion | Typestate local transition may accept | Rejects because bounded reachability has no witness continuation |
| Repair/certificate witness | unsafe external send can be converted to redacted local draft | Monitor can block but does not construct audit evidence | Synthesizes a bounded repair and emits replayable certificate |

## Compilability Statement

For a finite task contract, finite live-value set, finite sink set, finite
obligation atom set, finite approval/permission universe, and bound `k`, ROPE
can be compiled into a monolithic runtime-verification automaton whose state is:

```text
(q, rho_bar, permissions, approvals, budgets,
 recipient/purpose bindings, nonces/expiry,
 policy/profile/schema hashes, trust tier, tool availability)
```

The construction is not the contribution. The contribution is exposing these
objects compositionally so that enforcement, repair, and certificate replay use
the same state.

## Paper Wording

Allowed:

- "ROPE is not more expressive than arbitrary finite runtime verification; it
  identifies and operationalizes the residual-future state needed for
  tool-agent continuation safety."
- "FutureAccept is bounded reachability over a finite abstract effect graph."
- "Residual obligations can be viewed as dynamic, per-value, per-sink
  declassification preconditions, but ROPE keeps them residual after each
  prefix and uses them for permission necessity, repair, and certificate
  replay."

Avoid:

- "ROPE is strictly more expressive than IFC/declassification."
- "FutureAccept is a new planning algorithm."
- "Typestate cannot express ROPE."
