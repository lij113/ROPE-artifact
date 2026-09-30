# ROPE Threat Model

ROPE trusts the host-side sidecar, host policy store, trusted approval UI, and
certificate verifier. It does not trust the closed model's internal reasoning,
remote MCP servers, server-supplied tool descriptions, or server-supplied
`_meta` fields.

Attacker capabilities:

- inject instructions through web pages, email bodies, issues, documents, or
  tool results
- poison MCP tool descriptions and metadata
- operate a malicious or compromised MCP server
- induce out-of-scope tool calls, private-data sink use, sink laundering, or
  unnecessary permission step-up
- replay or tamper with repair certificates

Non-goals:

- ROPE does not make model reasoning immune to prompt injection.
- ROPE does not prove full natural-language semantic preservation of rewrites.
- ROPE does not trust MCP `_meta` as a security authority unless written by the
  host or a trusted adapter.
