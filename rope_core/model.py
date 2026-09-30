"""Typed model objects for ROPE.

These dataclasses define the vocabulary shared by code, fixtures, tests, and
the paper. Semantic operations live in sibling modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class EventKind(str, Enum):
    USER = "user"
    LIST_TOOLS = "list_tools"
    CALL = "call"
    RESULT = "result"
    APPROVE = "approve"
    REWRITE = "rewrite"
    SINK_USE = "sink_use"
    STEPUP = "stepup"


class SinkClass(str, Enum):
    LOCAL_DISPLAY = "local_display"
    LOCAL_FILE = "local_file"
    INTERNAL_SERVICE = "internal_service"
    SAME_ORG_MESSAGE = "same_org_message"
    EXTERNAL_EMAIL = "external_email"
    PUBLIC_WEB = "public_web"
    CODE_EXECUTION = "code_execution"
    PAYMENT = "payment"
    DESTRUCTIVE_WRITE = "destructive_write"


class SideEffect(str, Enum):
    READ = "read"
    TRANSFORM = "transform"
    WRITE = "write"
    SEND = "send"
    STEPUP = "stepup"
    APPROVAL = "approval"
    NONE = "none"


class TaskPhase(str, Enum):
    COLLECT_SOURCES = "CollectSources"
    TRANSFORM = "Transform"
    PREPARE_OUTPUT = "PrepareOutput"
    USER_REVIEW = "UserReview"
    COMMIT_OR_SEND = "CommitOrSend"


class TrustLevel(str, Enum):
    AUDITED = "audited"
    ORG_POLICY = "org_policy"
    SIGNED_THIRD_PARTY = "signed_third_party"
    OBSERVED = "observed"
    SERVER_HINT = "server_hint"
    DEFAULT = "default"
    UNTRUSTED = "untrusted"


class DecisionKind(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    REPAIR = "repair"
    BLOCK = "block"


class ProvenanceMode(str, Enum):
    RAW_TEXT = "raw_text"
    HYBRID_SCANNER = "hybrid_scanner"
    CONTEXT_CLOSED = "context_closed"
    CONTEXT_EPOCH = "context_epoch"
    OPAQUE_HANDLE = "opaque_handle"


@dataclass(frozen=True)
class StructuredAction:
    action: str
    resource: str
    sink: SinkClass
    side_effect: SideEffect
    purpose: str


@dataclass(frozen=True)
class Obligation:
    """A residual obligation atom or conjunction."""

    name: str
    args: Mapping[str, str] = field(default_factory=dict)
    children: tuple["Obligation", ...] = ()

    @classmethod
    def top(cls) -> "Obligation":
        return cls("top")

    @classmethod
    def atom(cls, name: str, **args: str) -> "Obligation":
        return cls(name=name, args=dict(args))

    @classmethod
    def conjunction(cls, *children: "Obligation") -> "Obligation":
        flattened: list[Obligation] = []
        for child in children:
            if child.is_top():
                continue
            if child.name == "and":
                flattened.extend(child.children)
            else:
                flattened.append(child)
        if not flattened:
            return cls.top()
        if len(flattened) == 1:
            return flattened[0]
        return cls(name="and", children=tuple(flattened))

    def is_top(self) -> bool:
        return self.name == "top"

    def atoms(self) -> tuple["Obligation", ...]:
        if self.is_top():
            return ()
        if self.name == "and":
            atoms: list[Obligation] = []
            for child in self.children:
                atoms.extend(child.atoms())
            return tuple(atoms)
        return (self,)

    def matches(self, other: "Obligation") -> bool:
        return self.name == other.name and dict(self.args) == dict(other.args)

    def pretty(self) -> str:
        if self.is_top():
            return "top"
        if self.name == "and":
            return " and ".join(child.pretty() for child in self.children)
        if not self.args:
            return self.name
        args = ",".join(f"{key}={value}" for key, value in sorted(self.args.items()))
        return f"{self.name}({args})"

    def __str__(self) -> str:
        return self.pretty()


@dataclass(frozen=True)
class ValueLabel:
    source_ids: frozenset[str]
    sensitivity: str
    purposes: frozenset[str]
    obligations: Mapping[SinkClass, Obligation]


@dataclass(frozen=True)
class ModelContext:
    """Provenance summary for values currently visible to the model."""

    epoch_id: str
    mode: ProvenanceMode = ProvenanceMode.RAW_TEXT
    visible_label: ValueLabel | None = None
    visible_value_ids: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ToolEffect:
    tool_name: str
    action: StructuredAction
    trust: TrustLevel
    adds_obligations: Mapping[SinkClass, Obligation] = field(default_factory=dict)
    discharges: tuple[Obligation, ...] = ()
    cost: float = 1.0


@dataclass(frozen=True)
class TaskContract:
    contract_id: str
    initial_phase: TaskPhase
    accepting_phases: frozenset[TaskPhase]
    phase_order: tuple[TaskPhase, ...]
    sink_policy: Mapping[TaskPhase, Mapping[SinkClass, str]]


@dataclass(frozen=True)
class Event:
    event_id: str
    kind: EventKind
    payload: Mapping[str, Any] = field(default_factory=dict)
    action: StructuredAction | None = None


@dataclass(frozen=True)
class RuntimeState:
    task_phase: TaskPhase
    provenance_graph_id: str
    labels: Mapping[str, ValueLabel] = field(default_factory=dict)
    permissions: frozenset[str] = frozenset()
    approvals: tuple[str, ...] = ()
    model_context: ModelContext | None = None


@dataclass(frozen=True)
class Repair:
    name: str
    cost: float
    parameters: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RepairCertificate:
    old_trace_hash: str
    new_trace_hash: str
    discharged_obligations: tuple[str, ...]
    contract_path: tuple[TaskPhase, ...]
    invariants: tuple[str, ...]
    search_space: tuple[str, ...]
    cost_bound: float


@dataclass(frozen=True)
class AdmissibilityDecision:
    kind: DecisionKind
    reason: str
    required_obligations: tuple[Obligation, ...] = ()
    repairs: Sequence[Repair] = ()
    evidence: Mapping[str, Any] = field(default_factory=dict)
