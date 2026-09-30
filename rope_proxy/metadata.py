"""Namespaced MCP metadata keys used by the host-side ROPE proxy."""

ROPE_META_KEYS = {
    "tool_profile": "rope/toolProfile",
    "profile_trust": "rope/profileTrust",
    "task_state": "rope/taskState",
    "arg_labels": "rope/argLabels",
    "result_labels": "rope/resultLabels",
    "repair_cert": "rope/repairCert",
    "audit": "rope/audit",
}


def attach_meta(message: dict, key: str, value: object) -> dict:
    if key not in ROPE_META_KEYS:
        raise KeyError(f"Unknown ROPE metadata key: {key}")
    updated = dict(message)
    meta = dict(updated.get("_meta", {}))
    meta[ROPE_META_KEYS[key]] = value
    updated["_meta"] = meta
    return updated


def read_meta(message: dict, key: str, default: object = None) -> object:
    if key not in ROPE_META_KEYS:
        raise KeyError(f"Unknown ROPE metadata key: {key}")
    return dict(message.get("_meta", {})).get(ROPE_META_KEYS[key], default)

