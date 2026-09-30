"""Context-granular provenance for raw-text model arguments.

ROPE's strongest non-bypass property needs host-visible derivations. Raw-text
agents violate that premise because the model can read private text and later
emit a fresh literal argument. Context-closed provenance is the conservative
runtime adaptation: every model-visible protected value is joined into a model
context label, and fresh model-generated arguments inherit that context label
until a trusted context reset starts a clean epoch.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace

from rope_core.model import ModelContext, ProvenanceMode, ValueLabel
from rope_core.semantics import propagate_label

CONTEXT_PROVENANCE_MODES = {
    ProvenanceMode.CONTEXT_CLOSED,
    ProvenanceMode.CONTEXT_EPOCH,
    ProvenanceMode.OPAQUE_HANDLE,
}


def empty_context(
    *,
    epoch_id: str = "epoch-0",
    mode: ProvenanceMode = ProvenanceMode.CONTEXT_CLOSED,
) -> ModelContext:
    return ModelContext(epoch_id=epoch_id, mode=mode)


def observe_model_input(
    context: ModelContext,
    *,
    value_id: str,
    label: ValueLabel,
) -> ModelContext:
    """Join a model-visible value into the current context label."""

    visible_label = (
        propagate_label((context.visible_label, label))
        if context.visible_label is not None
        else label
    )
    return replace(
        context,
        visible_label=visible_label,
        visible_value_ids=context.visible_value_ids | frozenset({value_id}),
    )


def label_model_generated_argument(
    context: ModelContext | None,
    *,
    explicit_labels: Sequence[ValueLabel] = (),
    scanner_label: ValueLabel | None = None,
) -> ValueLabel:
    """Return the label assigned to a fresh model-generated tool argument.

    In raw-text mode, only explicit value references carry labels, which
    preserves the old failure mode for documentation and tests. In context
    closure modes, the argument inherits the joined label of values visible in
    the model context. Hybrid scanner mode can add a scanner-derived label when
    a conservative scanner fires, but scanners are a precision aid rather than
    the theorem-level mechanism.
    """

    labels: list[ValueLabel] = []
    if context is not None and context.mode in CONTEXT_PROVENANCE_MODES and context.visible_label is not None:
        labels.append(context.visible_label)
    if context is not None and context.mode == ProvenanceMode.HYBRID_SCANNER and scanner_label is not None:
        labels.append(scanner_label)
    labels.extend(explicit_labels)
    return propagate_label(labels)


def clear_context(
    context: ModelContext,
    *,
    new_epoch_id: str,
    retained_labels: Sequence[ValueLabel] = (),
) -> ModelContext:
    """Start a clean model-context epoch after a trusted host reset.

    Retained labels should correspond to host-verified values that remain
    visible after the reset, such as a redacted summary. Passing no retained
    labels yields a public empty context.
    """

    return ModelContext(
        epoch_id=new_epoch_id,
        mode=context.mode,
        visible_label=propagate_label(retained_labels) if retained_labels else None,
        visible_value_ids=frozenset(),
    )
