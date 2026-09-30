# Theorem-To-Test Matrix

Version: `paper_v0`

| Claim | Tests | Evidence required |
| --- | --- | --- |
| Obligation non-bypass | `tests/test_theorem_obligation_non_bypass.py` | Raw private values cannot reach protected sinks before matching discharge; matching discharge allows conditional sink use. |
| Continuation preservation | `tests/test_theorem_continuation_preservation.py`, `tests/test_runtime_semantics.py` | Accepted events carry a bounded future witness; bounded failure reports pruning reasons; removing the only source before it is read is rejected. |
| Permission necessity | `tests/test_theorem_permission_necessity.py`, `tests/test_runtime_semantics.py` | Step-up is accepted only when a replayed witness uses the permission or a trusted contract declares it with bindings; a request cannot declare its own need. |
| Repair certificate soundness | `tests/test_theorem_certificate_soundness.py`, `tests/test_runtime_semantics.py` | Certificate replay accepts canonical equivalent traces and rejects changed policy, profile, nonce, expiry, value identity, task, or session. |
| MCP trust boundary | `tests/test_phase4_proxy.py` | Forged server `_meta` trust, effect, task state, or arg labels are overridden by host-side state. |
| Executed suites | `tests/test_trace_suites.py` | On executed controlled and stress traces, the runtime accepts no harmful attack, completes the benign workflows, and only the full runtime stops premature cleanup under a coarse contract; the certificate ablation executes replayed plans that the full runtime rejects. |

This matrix is a proof-aid, not a full mechanized proof. It ties theorem
premises to executable regression tests and records where boundedness or
observable-invariant assumptions enter the prototype.
