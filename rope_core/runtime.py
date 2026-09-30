from __future__ import annotations

import copy
import hashlib
import itertools
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from rope_core.ablations import admit_no_future
from rope_core.assurance import (
    DISCHARGE_TIERS,
    AssuranceDecisionKind,
    AssuranceTier,
    ProfileAssurance,
    SanitizerEvidence,
    ToolObservation,
    apply_profile_drift,
    stable_hash,
    verify_sanitizer_evidence,
)
from rope_core.context_provenance import (
    clear_context,
    empty_context,
    observe_model_input,
)
from rope_core.contracts import next_phase
from rope_core.future import (
    AbstractAction,
    AbstractState,
    AbstractValue,
    AtomKey,
    SearchContext,
    SearchSpace,
    TaskGoal,
    approval_matches,
    atom_key,
    atom_keys,
    atom_text,
    open_atoms,
)
from rope_core.model import (
    AdmissibilityDecision,
    DecisionKind,
    Event,
    EventKind,
    ModelContext,
    Obligation,
    ProvenanceMode,
    RuntimeState,
    SideEffect,
    SinkClass,
    StructuredAction,
    TaskContract,
    TaskPhase,
    TrustLevel,
    ValueLabel,
)
from rope_core.obligations import approve as approve_atom
from rope_core.obligations import remove_discharged
from rope_core.obligations import stepup as stepup_atom
from rope_core.repair import (
    PHASE3_REPAIR_SEARCH_SPACE,
    CertificateReplayContext,
    search_space_satisfies_host_policy,
)
from rope_core.semantics import TRUSTED_DISCHARGE_LEVELS, admit, propagate_label

# 需要合约绑定（接收方或目标）的高风险汇点
BOUND_SINKS = frozenset(
    {
        SinkClass.EXTERNAL_EMAIL,
        SinkClass.PUBLIC_WEB,
        SinkClass.SAME_ORG_MESSAGE,
        SinkClass.PAYMENT,
        SinkClass.DESTRUCTIVE_WRITE,
        SinkClass.CODE_EXECUTION,
    }
)
REPAIR_COSTS = {
    "downscope_args": 0.25,
    "switch_to_local_draft": 0.5,
    "redact": 1.0,
    "summarize": 1.0,
    "ask_confirm": 1.0,
}
REPAIR_COST_BOUND = 4.0
SANITIZER_ATOMS = {"redact": "redact", "summarize": "summarize"}


@dataclass(frozen=True)
class HostProfile:
    # 主机侧效果档案；服务器元数据只是提示，权威来自主机审查
    tool: str
    action: str
    sink: SinkClass
    side_effect: SideEffect
    purpose: str
    trust: TrustLevel
    tier: AssuranceTier
    discharges: tuple[Obligation, ...] = ()
    permission: str = ""
    advances_to: TaskPhase | None = None
    binding_arg: str = ""
    resource_arg: str = ""
    schema_hash: str = ""
    server_identity: str = ""
    source: str = "host_policy"
    # 产出值的数据类别：输出在继承输入义务之外，再加上该类别的义务策略
    adds_class: str = ""

    @property
    def can_discharge(self) -> bool:
        return (
            bool(self.discharges)
            and self.trust in TRUSTED_DISCHARGE_LEVELS
            and self.tier in DISCHARGE_TIERS
        )


def pessimistic_profile(tool: str, *, source: str = "pessimistic_default") -> HostProfile:
    # 未审查或漂移后的工具：每次调用都按发往公网处理，不能解除任何义务
    return HostProfile(
        tool=tool,
        action=tool,
        sink=SinkClass.PUBLIC_WEB,
        side_effect=SideEffect.SEND,
        purpose="unknown",
        trust=TrustLevel.DEFAULT,
        tier=AssuranceTier.SERVER_HINT,
        source=source,
    )


@dataclass(frozen=True)
class ContractSpec:
    # 任务合约：阶段自动机与汇点策略，加上义务策略、交付目标、允许来源、任务工具和权限预算
    contract: TaskContract
    task_id: str
    obligation_policy: Mapping[str, Mapping[SinkClass, Obligation]] = field(default_factory=dict)
    goals: tuple[TaskGoal, ...] = ()
    sources: Mapping[str, str] = field(default_factory=dict)
    resources: frozenset[str] = frozenset()
    tools: tuple[str, ...] = ()
    permission_budget: frozenset[str] = frozenset()
    budgets: Mapping[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeConfig:
    max_depth: int = 8
    provenance_mode: ProvenanceMode = ProvenanceMode.CONTEXT_CLOSED
    # 消融开关
    use_provenance: bool = True
    use_obligations: bool = True
    use_future: bool = True
    use_repair: bool = True
    use_certificates: bool = True
    policy_hash: str = "policy:v1"
    now: str = "2026-09-28T12:00:00Z"
    session_id: str = "session-1"


@dataclass(frozen=True)
class HostValue:
    value_id: str
    data_class: str
    sources: frozenset[str]
    label: ValueLabel
    transforms: frozenset[AtomKey] = frozenset()
    text: str = ""
    spans: tuple[str, ...] = ()
    untrusted: bool = False


@dataclass(frozen=True)
class Approval:
    # 主机界面上的用户审批，绑定值、数据类别、汇点、用途、接收方、任务、nonce、有效期和策略版本
    value_id: str
    data_class: str
    sink: SinkClass
    purpose: str
    recipient: str
    task_id: str
    nonce: str
    expiry: str
    policy_hash: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    evidence: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RepairPlan:
    # 修复计划：替换被拒绝调用的步骤序列及其证书
    steps: tuple[tuple[str, Any, Any], ...]
    moves: tuple[str, ...]
    cost: float
    certificate: Mapping[str, Any]
    context: CertificateReplayContext


def canonical_hash(data: Any) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def transform_output_id(value_id: str, tool: str) -> str:
    # 主机变换工具的输出值 id 约定，修复模拟和执行环境共用
    return f"{value_id}~{tool}"


class HostRuntime:
    def __init__(
        self,
        spec: ContractSpec,
        profiles: Mapping[str, HostProfile],
        config: RuntimeConfig = RuntimeConfig(),
    ) -> None:
        self.spec = spec
        self.profiles: dict[str, HostProfile] = dict(profiles)
        self.config = config
        self.phase: TaskPhase = spec.contract.initial_phase
        self.values: dict[str, HostValue] = {}
        self.resources: set[str] = set(spec.resources) | set(spec.sources)
        self.permissions: set[str] = set()
        self.approvals: list[Approval] = []
        self.spent_nonces: set[str] = set()
        self.realized: set[str] = set()
        self.budgets: dict[str, int] = dict(spec.budgets)
        self.context: ModelContext = empty_context(mode=config.provenance_mode)
        self.accepted: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 状态查询

    def clone(self) -> "HostRuntime":
        return copy.deepcopy(self)

    def profile(self, tool: str) -> HostProfile:
        return self.profiles.get(tool) or pessimistic_profile(tool)

    def profile_hash(self) -> str:
        return canonical_hash(
            {
                tool: [p.action, p.sink.value, p.side_effect.value, p.trust.value, p.tier.value, p.schema_hash]
                for tool, p in sorted(self.profiles.items())
            }
        )

    def task_complete(self) -> bool:
        return self.phase in self.spec.contract.accepting_phases and all(
            goal.goal_id in self.realized for goal in self.spec.goals
        )

    def abstract_state(self) -> AbstractState:
        values = frozenset(
            self._abstract_value(value) for value in self.values.values() if value.sources
        )
        return AbstractState(
            phase=self.phase,
            resources=frozenset(self.resources),
            values=values,
            permissions=frozenset(self.permissions),
            realized=frozenset(self.realized),
            budgets=tuple(sorted(self.budgets.items())),
        )

    def search_space(self) -> SearchSpace:
        spec = self.spec
        actions: list[AbstractAction] = []
        for tool in spec.tools:
            profile = self.profile(tool)
            if profile.source.startswith(("pessimistic", "drift")):
                continue
            advance = profile.advances_to
            if profile.side_effect is SideEffect.READ and profile.resource_arg:
                for resource, data_class in sorted(spec.sources.items()):
                    actions.append(
                        AbstractAction(
                            name=f"{tool}:{resource}",
                            sink=profile.sink,
                            side_effect=SideEffect.READ,
                            reads=resource,
                            value_class=data_class,
                            permission=profile.permission,
                            advances_to=advance,
                        )
                    )
            elif profile.adds_class:
                actions.append(
                    AbstractAction(
                        name=tool,
                        sink=profile.sink,
                        side_effect=profile.side_effect,
                        takes_value=True,
                        adds_class=profile.adds_class,
                        permission=profile.permission,
                        advances_to=advance,
                    )
                )
            elif profile.can_discharge:
                actions.append(
                    AbstractAction(
                        name=tool,
                        sink=profile.sink,
                        side_effect=profile.side_effect,
                        takes_value=True,
                        discharges=frozenset(atom_key(atom) for atom in profile.discharges),
                        permission=profile.permission,
                        advances_to=advance,
                    )
                )
            elif profile.side_effect in (SideEffect.SEND, SideEffect.WRITE, SideEffect.NONE) and profile.sink is not SinkClass.DESTRUCTIVE_WRITE:
                for goal in spec.goals:
                    if goal.removes or goal.sink is not profile.sink:
                        continue
                    actions.append(
                        AbstractAction(
                            name=f"{tool}->{goal.goal_id}",
                            sink=profile.sink,
                            side_effect=profile.side_effect,
                            takes_value=True,
                            delivers=True,
                            recipient=goal.recipient,
                            purpose=goal.purpose,
                            permission=profile.permission,
                            consumes=_budget_name(profile.sink),
                            advances_to=advance,
                        )
                    )
                if advance is not None and profile.sink not in BOUND_SINKS:
                    actions.append(
                        AbstractAction(
                            name=f"{tool}:progress",
                            sink=profile.sink,
                            side_effect=profile.side_effect,
                            permission=profile.permission,
                            advances_to=advance,
                        )
                    )
            elif profile.sink is SinkClass.DESTRUCTIVE_WRITE and profile.resource_arg:
                for goal in spec.goals:
                    if goal.sink is not SinkClass.DESTRUCTIVE_WRITE:
                        continue
                    if goal.removes:
                        actions.append(
                            AbstractAction(
                                name=f"{tool}:{goal.removes}",
                                sink=SinkClass.DESTRUCTIVE_WRITE,
                                side_effect=SideEffect.WRITE,
                                removes=goal.removes,
                                permission=profile.permission,
                                consumes="write",
                                advances_to=advance,
                            )
                        )
                    else:
                        # 提交型写入：把一个值写到绑定的目标上
                        actions.append(
                            AbstractAction(
                                name=f"{tool}->{goal.goal_id}",
                                sink=SinkClass.DESTRUCTIVE_WRITE,
                                side_effect=SideEffect.WRITE,
                                takes_value=True,
                                delivers=True,
                                recipient=goal.recipient,
                                purpose=goal.purpose,
                                permission=profile.permission,
                                consumes="write",
                                advances_to=advance,
                            )
                        )
        for goal in spec.goals:
            if goal.removes:
                continue
            if any(
                approval_needed(obligation, goal)
                for policy in spec.obligation_policy.values()
                for sink, obligation in policy.items()
                if sink is goal.sink
            ):
                actions.append(AbstractAction(name=f"approve:{goal.goal_id}", takes_value=True, approves=goal))
        for permission in sorted(spec.permission_budget):
            actions.append(
                AbstractAction(
                    name=f"stepup:{permission}",
                    sink=SinkClass.INTERNAL_SERVICE,
                    side_effect=SideEffect.STEPUP,
                    grants=permission,
                    consumes="stepup",
                )
            )
        policy = {
            data_class: {sink: atom_keys(obligation) for sink, obligation in sinks.items()}
            for data_class, sinks in spec.obligation_policy.items()
        }
        return SearchSpace(
            phase_order=spec.contract.phase_order,
            accepting=spec.contract.accepting_phases,
            sink_policy=spec.contract.sink_policy,
            goals=spec.goals,
            actions=tuple(actions),
            obligation_policy=policy,
        )

    # ------------------------------------------------------------------
    # 观察事件

    def observe_approval(self, approval: Approval) -> None:
        self.approvals.append(approval)

    def observe_metadata(self, tool: str, observation: ToolObservation) -> None:
        # 模式、身份、汇点或副作用漂移只会降低权限
        profile = self.profiles.get(tool)
        if profile is None:
            return
        assurance = ProfileAssurance(
            tool_name=profile.tool,
            tier=profile.tier,
            trust=profile.trust,
            schema_hash=profile.schema_hash,
            server_identity=profile.server_identity,
            policy_hash=self.config.policy_hash,
            allowed_sinks=frozenset({profile.sink}),
            allowed_side_effects=frozenset({profile.side_effect}),
            discharge_obligations=profile.discharges,
        )
        decision = apply_profile_drift(assurance, observation)
        if decision.kind is AssuranceDecisionKind.DOWNGRADE:
            self.profiles[tool] = pessimistic_profile(tool, source="drift_downgrade")

    def reset_context(self, retained: Sequence[str] = ()) -> None:
        labels = [self.values[value_id].label for value_id in retained]
        self.context = clear_context(self.context, new_epoch_id=f"epoch-{len(self.accepted)}", retained_labels=labels)

    # ------------------------------------------------------------------
    # 调用判定

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        call = self._resolve(tool, args)
        if call["contract_reason"]:
            return Decision(False, call["contract_reason"])
        decision = self._admit_event(
            call["event"],
            call["labels"],
            call["discharged"],
            lambda sim: sim._apply_call(call, _symbolic_outputs(sim, call)),
        )
        return Decision(decision.kind is DecisionKind.ALLOW, decision.reason, dict(decision.evidence))

    def commit_call(self, tool: str, args: Mapping[str, Any], outputs: Sequence[Mapping[str, Any]] = ()) -> None:
        call = self._resolve(tool, args)
        self._apply_call(call, outputs)

    def check_stepup(self, permission: str, bindings: Mapping[str, str] | None = None) -> Decision:
        event = Event(
            event_id=f"stepup:{permission}:{len(self.accepted)}",
            kind=EventKind.STEPUP,
            payload={"permission": permission, **dict(bindings or {})},
        )
        decision = self._admit_event(event, (), (), lambda sim: sim.permissions.add(permission))
        return Decision(decision.kind is DecisionKind.ALLOW, decision.reason, dict(decision.evidence))

    def commit_stepup(self, permission: str) -> None:
        self.permissions.add(permission)
        if "stepup" in self.budgets:
            self.budgets["stepup"] -= 1
        self.accepted.append({"kind": "stepup", "permission": permission})

    def _admit_event(
        self,
        event: Event,
        labels: Sequence[ValueLabel],
        discharged: Sequence[Obligation],
        simulate: Callable[["HostRuntime"], None],
    ) -> AdmissibilityDecision:
        state = RuntimeState(
            task_phase=self.phase,
            provenance_graph_id=self.spec.task_id,
            permissions=frozenset(self.permissions),
            model_context=self.context,
        )
        if not self.config.use_obligations:
            labels = ()
        if not self.config.use_future:
            return admit_no_future(
                self.spec.contract,
                state,
                event,
                input_labels=labels,
                discharged=discharged,
                permission_budget=self.spec.permission_budget,
            )
        simulated = self.clone()
        simulate(simulated)
        search = SearchContext(
            space=self.search_space(),
            pre_state=self.abstract_state(),
            post_state=simulated.abstract_state(),
        )
        return admit(
            self.spec.contract,
            state,
            event,
            input_labels=labels,
            discharged=discharged,
            max_depth=self.config.max_depth,
            search=search,
        )

    def _resolve(self, tool: str, args: Mapping[str, Any]) -> dict[str, Any]:
        profile = self.profile(tool)
        binding = _text(args.get(profile.binding_arg)) if profile.binding_arg else ""
        resource = _text(args.get(profile.resource_arg)) if profile.resource_arg else ""
        payload = {
            key: value
            for key, value in args.items()
            if key not in (profile.binding_arg, profile.resource_arg)
        }
        refs, literals = embeds(payload)
        for ref in refs:
            if ref not in self.values:
                raise KeyError(f"call {tool} references unknown value {ref}")
        goal = self._matching_goal(profile, binding, resource, bool(refs))
        purpose = goal.purpose if goal is not None and goal.purpose else profile.purpose
        labels = self._input_labels(refs, literals)
        discharged = self._discharged_atoms(refs, profile.sink, binding or resource, purpose)
        action = StructuredAction(
            action=profile.action,
            resource=resource or tool,
            sink=profile.sink,
            side_effect=profile.side_effect,
            purpose=purpose,
        )
        event = Event(
            event_id=f"call:{tool}:{len(self.accepted)}",
            kind=EventKind.CALL,
            payload={"tool": tool, "args": _jsonable(args)},
            action=action,
        )
        return {
            "tool": tool,
            "args": dict(args),
            "profile": profile,
            "binding": binding,
            "resource": resource,
            "refs": refs,
            "literals": literals,
            "goal": goal,
            "purpose": purpose,
            "labels": labels,
            "discharged": discharged,
            "event": event,
            "contract_reason": self._contract_reason(profile, binding, resource, bool(refs)),
        }

    def _contract_reason(self, profile: HostProfile, binding: str, resource: str, has_payload: bool) -> str:
        # LocalValid 的前置条件与合约迁移：工具所需权限已授予；读取在允许来源内且资源仍存在；高风险汇点绑定到合约目标
        if profile.permission and profile.permission not in self.permissions:
            return "permission_not_held"
        if profile.side_effect is SideEffect.READ and profile.resource_arg:
            if self.spec.sources and resource not in self.spec.sources:
                return "source_outside_contract"
            if resource not in self.resources:
                return "resource_unavailable"
        if profile.sink in BOUND_SINKS:
            if self._matching_goal(profile, binding, resource, has_payload) is None:
                return "effect_outside_contract"
            if profile.sink is SinkClass.DESTRUCTIVE_WRITE and (resource or binding) not in self.resources:
                return "resource_unavailable"
        return ""

    def _matching_goal(self, profile: HostProfile, binding: str, resource: str, has_payload: bool) -> TaskGoal | None:
        # 删除型写入对应删除目标；带载荷的写入或发送对应交付目标（可选目标也算合约允许的效果）
        target = binding or resource
        for goal in self.spec.goals:
            if goal.sink is not profile.sink:
                continue
            if goal.removes:
                if profile.sink is SinkClass.DESTRUCTIVE_WRITE and not has_payload and goal.removes == target:
                    return goal
                continue
            if profile.sink is SinkClass.DESTRUCTIVE_WRITE and not has_payload:
                continue
            if not goal.recipient or goal.recipient == target:
                return goal
        return None

    def _input_labels(self, refs: Sequence[str], literals: Sequence[str]) -> list[ValueLabel]:
        if not self.config.use_provenance:
            # 消融：没有值级来源时，所有参数只能继承模型上下文的合并标签
            if refs or literals:
                return [self.context.visible_label] if self.context.visible_label is not None else []
            return []
        labels = [self.values[ref].label for ref in refs]
        for literal in literals:
            label = self._literal_label(literal)
            if label is not None:
                labels.append(label)
        return labels

    def _literal_label(self, literal: str) -> ValueLabel | None:
        mode = self.config.provenance_mode
        if mode in (ProvenanceMode.CONTEXT_CLOSED, ProvenanceMode.CONTEXT_EPOCH):
            return self.context.visible_label
        if mode is ProvenanceMode.HYBRID_SCANNER:
            hits = [
                value.label
                for value in self.values.values()
                if value.value_id in self.context.visible_value_ids
                and any(span and span in literal for span in value.spans)
            ]
            return propagate_label(hits) if hits else None
        return None

    def _discharged_atoms(
        self,
        refs: Sequence[str],
        sink: SinkClass,
        binding: str,
        purpose: str,
    ) -> list[Obligation]:
        # 已由绑定审批或已授予的权限解除的原子
        atoms: list[Obligation] = [stepup_atom(permission) for permission in sorted(self.permissions)]
        for approval in self._valid_approvals():
            if approval.sink is not sink or approval.recipient != binding or approval.purpose != purpose:
                continue
            if approval.value_id not in refs:
                continue
            atoms.append(approve_atom(approval.data_class, sink.value, purpose, binding))
        return atoms

    def _valid_approvals(self) -> list[Approval]:
        return [
            approval
            for approval in self.approvals
            if approval.task_id == self.spec.task_id
            and approval.policy_hash == self.config.policy_hash
            and approval.expiry >= self.config.now
            and approval.nonce not in self.spent_nonces
        ]

    def _abstract_value(self, value: HostValue) -> AbstractValue:
        residual: set[tuple[SinkClass, AtomKey]] = set()
        for sink, obligation in value.label.obligations.items():
            approved = {
                atom_key(approve_atom(approval.data_class, sink.value, approval.purpose, approval.recipient))
                for approval in self._valid_approvals()
                if approval.value_id == value.value_id and approval.sink is sink
            }
            for atom in atom_keys(obligation):
                if atom not in approved:
                    residual.add((sink, atom))
        return AbstractValue(
            value_class=value.data_class,
            sources=value.sources,
            transforms=value.transforms,
            residual=frozenset(residual),
        )

    # ------------------------------------------------------------------
    # 状态更新（已接受事件）

    def _apply_call(self, call: Mapping[str, Any], outputs: Sequence[Mapping[str, Any]]) -> None:
        profile: HostProfile = call["profile"]
        action = call["event"].action
        target = profile.advances_to
        if target is not None and self.phase in self.spec.contract.phase_order and target in self.spec.contract.phase_order:
            if self.spec.contract.phase_order.index(target) > self.spec.contract.phase_order.index(self.phase):
                self.phase = target
        elif target is None and action is not None and self.phase in self.spec.contract.phase_order:
            self.phase = next_phase(self.spec.contract, self.phase, action)

        inputs = [self.values[ref] for ref in call["refs"]]
        for output in outputs:
            self._add_output(profile, inputs, output)

        if profile.sink is SinkClass.DESTRUCTIVE_WRITE and not call["refs"]:
            target_resource = call["resource"] or call["binding"]
            self.resources.discard(target_resource)
            for goal in self.spec.goals:
                if goal.removes and goal.removes == target_resource:
                    self.realized.add(goal.goal_id)
            if "write" in self.budgets:
                self.budgets["write"] -= 1
        elif profile.side_effect in (SideEffect.SEND, SideEffect.WRITE, SideEffect.NONE) and not outputs:
            self._deliver(call, inputs)
        self.accepted.append({"kind": "call", "tool": call["tool"], "args": _jsonable(call["args"])})

    def _deliver(self, call: Mapping[str, Any], inputs: Sequence[HostValue]) -> None:
        profile: HostProfile = call["profile"]
        target = call["binding"] or call["resource"]
        used = [
            approval
            for approval in self._valid_approvals()
            if approval.sink is profile.sink
            and approval.recipient == target
            and approval.purpose == call["purpose"]
            and approval.value_id in call["refs"]
        ]
        for goal in self.spec.goals:
            if goal.removes or goal.sink is not profile.sink:
                continue
            if goal.recipient and goal.recipient != target:
                continue
            if goal.purpose and goal.purpose != call["purpose"]:
                continue
            for value in inputs:
                abstract = self._abstract_value(value)
                if goal.value_class and goal.value_class != value.data_class:
                    continue
                if (
                    goal.sources.issubset(value.sources)
                    and goal.transforms.issubset(value.transforms)
                    and not open_atoms(self.abstract_state(), abstract, goal.sink)
                ):
                    self.realized.add(goal.goal_id)
        for approval in used:
            self.spent_nonces.add(approval.nonce)
        name = _budget_name(profile.sink)
        if name in self.budgets:
            self.budgets[name] -= 1

    def _add_output(self, profile: HostProfile, inputs: Sequence[HostValue], output: Mapping[str, Any]) -> None:
        value_id = str(output["value_id"])
        data_class = str(output.get("data_class") or (inputs[0].data_class if inputs else profile.action))
        text = str(output.get("text", ""))
        untrusted = bool(output.get("untrusted", False))
        if inputs:
            label = propagate_label([value.label for value in inputs])
            sources = frozenset().union(*(value.sources for value in inputs))
            transforms = frozenset().union(*(value.transforms for value in inputs))
            if profile.can_discharge and self._sanitizer_verified(profile, inputs, text):
                removed = profile.discharges
                label = ValueLabel(
                    source_ids=label.source_ids,
                    sensitivity=label.sensitivity,
                    purposes=label.purposes,
                    obligations={
                        sink: remove_discharged(obligation, removed)
                        for sink, obligation in label.obligations.items()
                    },
                )
                transforms = transforms | frozenset(atom_key(atom) for atom in removed)
        else:
            resource = str(output.get("resource", ""))
            obligations = dict(self.spec.obligation_policy.get(data_class, {}))
            label = ValueLabel(
                source_ids=frozenset({resource}) if resource else frozenset(),
                sensitivity="private" if obligations else "public",
                purposes=frozenset(),
                obligations=obligations,
            )
            sources = frozenset({resource}) if resource and resource in self.spec.sources else frozenset()
            transforms = frozenset()
        if profile.adds_class:
            data_class = profile.adds_class
            label = propagate_label(
                [label],
                added_obligations=dict(self.spec.obligation_policy.get(profile.adds_class, {})),
            )
        value = HostValue(
            value_id=value_id,
            data_class=data_class,
            sources=sources,
            label=label,
            transforms=transforms,
            text=text,
            spans=tuple(str(span) for span in output.get("spans", ())),
            untrusted=untrusted,
        )
        self.values[value_id] = value
        if self.config.provenance_mode is not ProvenanceMode.OPAQUE_HANDLE:
            self.context = observe_model_input(self.context, value_id=value_id, label=label)

    def _sanitizer_verified(self, profile: HostProfile, inputs: Sequence[HostValue], text: str) -> bool:
        # 独立验证器检查净化证据；符号模拟时没有文本，按工具的审查结论处理
        if text == _SYMBOLIC_TEXT:
            return True
        input_text = "\n".join(value.text for value in inputs)
        for atom in profile.discharges:
            evidence = SanitizerEvidence(
                sanitizer_id=profile.tool,
                tier=profile.tier,
                input_hash=stable_hash(input_text),
                output_hash=stable_hash(text),
                obligation=atom,
                policy_hash=self.config.policy_hash,
                verifier_id="host_verifier",
                verifier_passed=True,
                removed_spans=tuple(span for value in inputs for span in value.spans),
            )
            result = verify_sanitizer_evidence(evidence, input_text=input_text, output_text=text)
            if not result.accepted:
                return False
        return True

    # ------------------------------------------------------------------
    # 有界修复与证书

    def plan_repair(self, tool: str, args: Mapping[str, Any]) -> RepairPlan | None:
        if not self.config.use_repair:
            return None
        call = self._resolve(tool, args)
        profile: HostProfile = call["profile"]
        if profile.side_effect not in (SideEffect.SEND, SideEffect.WRITE) or profile.sink is SinkClass.DESTRUCTIVE_WRITE:
            return None
        moves = [move for move in PHASE3_REPAIR_SEARCH_SPACE if move in REPAIR_COSTS]
        candidates: list[tuple[float, tuple[str, ...]]] = []
        for size in range(1, len(moves) + 1):
            for combo in itertools.combinations(moves, size):
                cost = sum(REPAIR_COSTS[move] for move in combo)
                if cost <= REPAIR_COST_BOUND:
                    candidates.append((cost, combo))
        candidates.sort(key=lambda item: (item[0], item[1]))
        for cost, combo in candidates:
            steps = self._repair_steps(call, combo)
            if steps is None:
                continue
            trial = self.clone()
            if not trial._replay(steps):
                continue
            return self._certify(call, steps, combo, cost)
        return None

    def _repair_steps(self, call: Mapping[str, Any], moves: Sequence[str]) -> tuple[tuple[str, Any, Any], ...] | None:
        profile: HostProfile = call["profile"]
        refs = list(call["refs"])
        if not refs:
            # 没有可替换的值，修复空间里没有可用的动作
            return None
        binding = call["binding"]
        steps: list[tuple[str, Any, Any]] = []
        tool = call["tool"]
        args = dict(call["args"])
        if "downscope_args" in moves:
            goal = next(
                (g for g in self.spec.goals if not g.removes and g.sink is profile.sink and g.recipient),
                None,
            )
            if goal is None:
                return None
            binding = goal.recipient
            if profile.binding_arg:
                args[profile.binding_arg] = binding
            # 去掉合约交付目标不需要的值，只保留覆盖目标来源的值
            kept = [ref for ref in refs if goal.sources.issubset(self.values[ref].sources)]
            if not kept:
                return None
            refs = kept[:1]
            args = _rebuild_payload(args, profile, refs)
        for move in ("redact", "summarize"):
            if move not in moves:
                continue
            transformer = self._host_transformer(move)
            if transformer is None:
                return None
            new_refs = []
            for ref in refs:
                steps.append(("call", transformer, {"input": {"$value": ref}}))
                new_refs.append(transform_output_id(ref, transformer))
            refs = new_refs
            args = _rebuild_payload(args, profile, refs)
        if "switch_to_local_draft" in moves:
            drafter = next(
                (
                    name
                    for name in self.spec.tools
                    if self.profile(name).sink is SinkClass.LOCAL_FILE
                    and self.profile(name).side_effect is SideEffect.WRITE
                ),
                None,
            )
            if drafter is None:
                return None
            tool = drafter
            args = {"content": [{"$value": ref} for ref in refs]} if len(refs) > 1 else {"content": {"$value": refs[0]}}
            # 草稿写到合约里本地交付目标绑定的位置
            local_goal = next(
                (g for g in self.spec.goals if g.sink is SinkClass.LOCAL_FILE and not g.optional and g.recipient),
                None,
            )
            drafter_profile = self.profile(drafter)
            binding = local_goal.recipient if local_goal is not None else ""
            if drafter_profile.binding_arg and binding:
                args[drafter_profile.binding_arg] = binding
        if "ask_confirm" in moves:
            goal = next(
                (g for g in self.spec.goals if not g.removes and g.sink is self.profile(tool).sink and g.recipient == binding),
                None,
            )
            if goal is None or not refs:
                return None
            for ref in refs:
                value = self.values.get(ref)
                data_class = value.data_class if value is not None else self._planned_class(ref)
                steps.append(
                    (
                        "approve",
                        Approval(
                            value_id=ref,
                            data_class=data_class,
                            sink=goal.sink,
                            purpose=goal.purpose,
                            recipient=goal.recipient,
                            task_id=self.spec.task_id,
                            nonce=f"repair-{self.spec.task_id}-{len(self.accepted)}-{ref}",
                            expiry=self.config.now,
                            policy_hash=self.config.policy_hash,
                        ),
                        None,
                    )
                )
        steps.append(("call", tool, args))
        return tuple(steps)

    def _planned_class(self, ref: str) -> str:
        base = ref.split("~", 1)[0]
        return self.values[base].data_class

    def _host_transformer(self, move: str) -> str | None:
        for name in self.spec.tools:
            profile = self.profile(name)
            if profile.can_discharge and any(atom.name == SANITIZER_ATOMS[move] for atom in profile.discharges):
                return name
        return None

    def _replay(self, steps: Sequence[tuple[str, Any, Any]]) -> bool:
        # 在副本上按同一判定规则逐步重放修复后的后续
        for kind, first, second in steps:
            if kind == "approve":
                self.observe_approval(first)
                continue
            decision = self.check_call(first, second)
            if not decision.allowed:
                return False
            resolved = self._resolve(first, second)
            self._apply_call(resolved, _symbolic_outputs(self, resolved))
        return True

    def replay_context(self) -> CertificateReplayContext:
        return CertificateReplayContext(
            policy_hash=self.config.policy_hash,
            effect_profile_hash=self.profile_hash(),
            approval_nonce="",
            approval_expiry=self.config.now,
            current_time=self.config.now,
            task_id=self.spec.task_id,
            session_id=self.config.session_id,
        )

    def _certify(self, call: Mapping[str, Any], steps: Sequence[tuple[str, Any, Any]], moves: Sequence[str], cost: float) -> RepairPlan:
        old_trace = [{"tool": call["tool"], "args": _jsonable(call["args"])}]
        new_trace = [step_json(step) for step in steps]
        trial = self.clone()
        trial._replay(steps)
        final_kind, final_tool, final_args = steps[-1]
        final = trial._resolve(final_tool, final_args) if final_kind == "call" else None
        invariants = ["replayed_admission", "no_open_obligation_at_sink"]
        if final is not None:
            invariants.append(f"sink={final['profile'].sink.value}")
            if final["binding"]:
                invariants.append(f"binding={final['binding']}")
        certificate = {
            "old_trace_hash": canonical_hash(old_trace),
            "new_trace_hash": canonical_hash(new_trace),
            "discharged_obligations": sorted(
                atom_text(atom)
                for step in steps
                if step[0] == "call" and self.profile(step[1]).can_discharge
                for atom in (atom_key(a) for a in self.profile(step[1]).discharges)
            ),
            "contract_path": [trial.phase.value],
            "invariants": invariants,
            "search_space": list(PHASE3_REPAIR_SEARCH_SPACE),
            "cost_bound": REPAIR_COST_BOUND,
            "moves": list(moves),
            "cost": cost,
        }
        return RepairPlan(
            steps=tuple(steps),
            moves=tuple(moves),
            cost=cost,
            certificate=certificate,
            context=self.replay_context(),
        )

    def accepts_certified_plan(self, plan: RepairPlan) -> bool:
        # 关闭证书校验的消融直接信任修复求解器给出的计划
        if not self.config.use_certificates:
            return True
        return self.verify_plan(plan)

    def verify_plan(self, plan: RepairPlan) -> bool:
        # 证书校验器：独立于求解器，重算哈希、核对上下文、在副本上重放并检查不变式
        if not search_space_satisfies_host_policy(plan.certificate.get("search_space", ())):
            return False
        if plan.certificate.get("new_trace_hash") != canonical_hash([step_json(step) for step in plan.steps]):
            return False
        expected = self.replay_context()
        observed = plan.context
        for name in (
            "policy_hash",
            "effect_profile_hash",
            "task_id",
            "session_id",
            "sanitizer_manifest_hash",
            "tool_availability_hash",
            "permission_epoch",
            "external_state_hash",
        ):
            if getattr(expected, name) != getattr(observed, name):
                return False
        if observed.current_time > observed.approval_expiry:
            return False
        trial = self.clone()
        if not trial._replay(plan.steps):
            return False
        kind, tool, args = plan.steps[-1]
        if kind != "call":
            return False
        final = trial._resolve(tool, args)
        for invariant in plan.certificate.get("invariants", ()):
            if invariant.startswith("binding=") and invariant.split("=", 1)[1] != final["binding"]:
                return False
            if invariant.startswith("sink=") and invariant.split("=", 1)[1] != final["profile"].sink.value:
                return False
        return True


_SYMBOLIC_TEXT = "<symbolic>"


def approval_needed(obligation: Obligation, goal: TaskGoal) -> bool:
    return any(approval_matches(atom, goal) for atom in atom_keys(obligation))


def _symbolic_outputs(runtime: HostRuntime, call: Mapping[str, Any]) -> list[dict[str, Any]]:
    # 模拟调用效果时使用的符号输出：读取产生来源值，可信变换产生派生值
    profile: HostProfile = call["profile"]
    if profile.side_effect is SideEffect.READ and profile.resource_arg:
        resource = call["resource"]
        data_class = runtime.spec.sources.get(resource, "")
        if not data_class:
            return []
        return [{"value_id": f"sym:{resource}", "data_class": data_class, "resource": resource, "text": _SYMBOLIC_TEXT}]
    if profile.side_effect is SideEffect.TRANSFORM and call["refs"]:
        return [
            {"value_id": transform_output_id(ref, call["tool"]), "text": _SYMBOLIC_TEXT}
            for ref in call["refs"][:1]
        ]
    return []


def _budget_name(sink: SinkClass) -> str:
    if sink in (SinkClass.EXTERNAL_EMAIL, SinkClass.SAME_ORG_MESSAGE, SinkClass.PAYMENT):
        return "disclosure"
    if sink is SinkClass.PUBLIC_WEB:
        return "public_network"
    if sink is SinkClass.DESTRUCTIVE_WRITE:
        return "write"
    return ""


def embeds(value: Any) -> tuple[list[str], list[str]]:
    # Embeds：参数里引用的值 id（句柄、结构化字段）与模型新写的字面量
    refs: list[str] = []
    literals: list[str] = []

    def walk(item: Any) -> None:
        if isinstance(item, Mapping):
            if "$value" in item:
                refs.append(str(item["$value"]))
                return
            for inner in item.values():
                walk(inner)
        elif isinstance(item, (list, tuple)):
            for inner in item:
                walk(inner)
        elif item is None:
            return
        else:
            text = str(item)
            if text.strip():
                literals.append(text)

    walk(value)
    return refs, literals


def _rebuild_payload(args: Mapping[str, Any], profile: HostProfile, refs: Sequence[str]) -> dict[str, Any]:
    kept = {
        key: value
        for key, value in args.items()
        if key in (profile.binding_arg, profile.resource_arg)
    }
    kept["content"] = [{"$value": ref} for ref in refs] if len(refs) > 1 else {"$value": refs[0]}
    return kept


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ",".join(_text(item) for item in value)
    return str(value)


def _jsonable(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def step_json(step: tuple[str, Any, Any]) -> dict[str, Any]:
    kind, first, second = step
    if kind == "approve":
        return {"kind": "approve", "approval": _jsonable(first.__dict__)}
    return {"kind": "call", "tool": first, "args": _jsonable(second)}
