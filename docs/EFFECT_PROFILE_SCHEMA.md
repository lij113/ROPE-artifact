# Effect Profile Schema

Version: `paper_v0`

Each host-side tool profile contains:

| Field | Meaning |
| --- | --- |
| `tool` | Tool name as exposed through MCP discovery. |
| `source` | Profile source, such as `host_policy`, `audited`, or `server_hint`. |
| `trust` | Trust level used for obligation discharge decisions. |
| `action` | Abstract action name consumed by the task contract. |
| `resource` | Abstract resource class. |
| `sink` | Sink class affected by the tool call. |
| `side_effect` | `read`, `transform`, `write`, `send`, `stepup`, or `none`. |
| `purpose` | Task purpose associated with the action. |
| `discharges` | Obligations this tool can discharge when its trust level is sufficient. |
| `annotation_fields` | Effort proxy used for deployability reporting. |

Server-provided profiles are hints only. The host registry is authoritative.
Unknown tools receive a pessimistic public-web send profile with default trust.

## Assurance Fields

ROPE now treats effect profiles as assurance artifacts rather than static trust
claims. Host-reviewed profiles should additionally record:

| Field | Meaning |
| --- | --- |
| `assurance_tier` | `server_hint`, `observed`, `host_reviewed`, `constrained`, `verified`, or `untrusted`. |
| `schema_hash` | Canonical hash of the tool schema used for drift detection. |
| `server_identity` | Host-observed server identity bound to the profile. |
| `policy_hash` | Global safety envelope / policy version. |
| `allowed_sinks` | Sink classes this profile may affect. |
| `allowed_side_effects` | Side-effect classes this profile may perform. |
| `broker_required` | Whether high-risk side effects must be executed by the host capability broker. |
| `regression_cases` | Host regression cases required for `verified` profiles. |

Only `constrained` and `verified` profiles may discharge obligations. High-risk
send/write/payment/step-up effects require the broker. Schema, server identity,
observed sink, or observed side-effect drift can only downgrade authority.
