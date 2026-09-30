from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from rope_core.assurance import PII_PATTERNS, ToolObservation
from rope_core.contracts import next_phase, sink_policy
from rope_core.model import ProvenanceMode, SideEffect, SinkClass, StructuredAction, TaskPhase
from rope_core.runtime import (
    BOUND_SINKS,
    Approval,
    ContractSpec,
    Decision,
    HostProfile,
    HostRuntime,
    RepairPlan,
    RuntimeConfig,
    embeds,
    pessimistic_profile,
)

from rope_bench.trace_world import Scenario

REVIEW_PHASES = (TaskPhase.USER_REVIEW, TaskPhase.COMMIT_OR_SEND)


@dataclass
class _Value:
    protected: bool
    untrusted: bool
    declassified: bool
    text: str


class BaselineMonitor:
    # 基线监控的共同状态：值的来源信息、审批记录、权限、阶段；各基线只改判定规则
    name = "baseline"

    def __init__(self, spec: ContractSpec, profiles: Mapping[str, HostProfile]) -> None:
        self.spec = spec
        self.profiles = dict(profiles)
        self.values: dict[str, _Value] = {}
        self.approvals: list[Approval] = []
        self.permissions: set[str] = set()
        self.phase = spec.contract.initial_phase
        self.saw_transform = False
        self.now = RuntimeConfig().now
        self.policy_hash = RuntimeConfig().policy_hash
        self.spent: set[str] = set()

    # ------------------------------------------------------------------
    # 共同接口

    def profile(self, tool: str) -> HostProfile:
        return self.profiles.get(tool) or pessimistic_profile(tool)

    def check_stepup(self, permission: str, bindings: Mapping[str, str] | None = None) -> Decision:
        return Decision(True, "stepup_not_governed")

    def commit_stepup(self, permission: str) -> None:
        self.permissions.add(permission)

    def observe_approval(self, approval: Approval) -> None:
        self.approvals.append(approval)

    def observe_metadata(self, tool: str, observation: ToolObservation) -> None:
        return None

    def plan_repair(self, tool: str, args: Mapping[str, Any]) -> RepairPlan | None:
        return None

    def verify_plan(self, plan: RepairPlan) -> bool:
        return False

    def accepts_certified_plan(self, plan: RepairPlan) -> bool:
        return False

    def commit_call(self, tool: str, args: Mapping[str, Any], outputs: Sequence[Mapping[str, Any]] = ()) -> None:
        profile = self.profile(tool)
        refs, _literals = self._payload(profile, args)
        action = StructuredAction(profile.action, tool, profile.sink, profile.side_effect, profile.purpose)
        order = self.spec.contract.phase_order
        if profile.advances_to is not None and self.phase in order and profile.advances_to in order:
            if order.index(profile.advances_to) > order.index(self.phase):
                self.phase = profile.advances_to
        elif profile.advances_to is None and self.phase in order:
            self.phase = next_phase(self.spec.contract, self.phase, action)
        inputs = [self.values[ref] for ref in refs if ref in self.values]
        for output in outputs:
            value_id = str(output["value_id"])
            if inputs:
                trusted_transform = profile.can_discharge
                self.values[value_id] = _Value(
                    protected=any(value.protected for value in inputs),
                    untrusted=any(value.untrusted for value in inputs),
                    declassified=trusted_transform or all(value.declassified for value in inputs),
                    text=str(output.get("text", "")),
                )
                if trusted_transform:
                    self.saw_transform = True
            else:
                data_class = str(output.get("data_class", ""))
                self.values[value_id] = _Value(
                    protected=bool(self.spec.obligation_policy.get(data_class)),
                    untrusted=bool(output.get("untrusted", False)),
                    declassified=False,
                    text=str(output.get("text", "")),
                )
        if profile.sink in BOUND_SINKS and profile.sink is not SinkClass.DESTRUCTIVE_WRITE:
            binding = self._binding(profile, args)
            for approval in self._valid_bound_approvals(profile.sink, binding):
                self.spent.add(approval.nonce)

    # ------------------------------------------------------------------
    # 辅助判定

    def _payload(self, profile: HostProfile, args: Mapping[str, Any]) -> tuple[list[str], list[str]]:
        payload = {k: v for k, v in args.items() if k not in (profile.binding_arg, profile.resource_arg)}
        return embeds(payload)

    def _binding(self, profile: HostProfile, args: Mapping[str, Any]) -> str:
        key = profile.binding_arg or profile.resource_arg
        value = args.get(key) if key else None
        return "" if value is None else str(value)

    def _in_scope(self, tool: str) -> bool:
        return tool in self.spec.tools

    def _goal_binding_ok(self, profile: HostProfile, args: Mapping[str, Any]) -> bool:
        binding = self._binding(profile, args)
        refs, literals = self._payload(profile, args)
        has_payload = bool(refs or literals)
        for goal in self.spec.goals:
            if goal.sink is not profile.sink:
                continue
            if goal.removes:
                if profile.sink is SinkClass.DESTRUCTIVE_WRITE and not has_payload and goal.removes == binding:
                    return True
                continue
            if profile.sink is SinkClass.DESTRUCTIVE_WRITE and not has_payload:
                continue
            if not goal.recipient or goal.recipient == binding:
                return True
        return False

    def _source_ok(self, profile: HostProfile, args: Mapping[str, Any]) -> bool:
        if profile.side_effect is not SideEffect.READ or not profile.resource_arg:
            return True
        return not self.spec.sources or str(args.get(profile.resource_arg)) in self.spec.sources

    def _valid_bound_approvals(self, sink: SinkClass, binding: str) -> list[Approval]:
        return [
            approval
            for approval in self.approvals
            if approval.sink is sink
            and approval.recipient == binding
            and approval.task_id == self.spec.task_id
            and approval.expiry >= self.now
            and approval.policy_hash == self.policy_hash
            and approval.nonce not in self.spent
        ]

    def _payload_text(self, refs: Sequence[str], literals: Sequence[str]) -> str:
        return "\n".join([self.values[ref].text for ref in refs if ref in self.values] + list(literals))

    def _budget_ok(self, permission: str) -> Decision:
        if permission in self.spec.permission_budget:
            return Decision(True, "within_permission_budget")
        return Decision(False, "permission_outside_budget")

    def _is_sink(self, profile: HostProfile) -> bool:
        return profile.sink in BOUND_SINKS


class NoMonitor(BaselineMonitor):
    # 不设监控：用于确定每个攻击用例在无人拦截时是否真的达成攻击目标
    name = "none"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        return Decision(True, "unmonitored")


class ScopeGate(BaselineMonitor):
    # 工具白名单：只允许任务范围内的工具
    name = "scope-gate"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        return Decision(self._in_scope(tool), "tool_in_scope" if self._in_scope(tool) else "tool_outside_scope")


class ApprovalGate(ScopeGate):
    # 外发效果前需要存在一次用户审批（不绑定对象）
    name = "approval-gate"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        if self._is_sink(self.profile(tool)) and not self.approvals:
            return Decision(False, "no_approval")
        return base


class BoundApproval(ScopeGate):
    # 审批绑定汇点、接收方、任务、nonce 和有效期，但不绑定被发送的值
    name = "bound-approval"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        profile = self.profile(tool)
        if self._is_sink(profile) and profile.sink is not SinkClass.DESTRUCTIVE_WRITE:
            if not self._valid_bound_approvals(profile.sink, self._binding(profile, args)):
                return Decision(False, "no_bound_approval")
        return base


class TaintBlock(ScopeGate):
    # 值级污点：私有或不可信来源的值及其派生值不得进入外发汇点，没有降密
    name = "taint-block"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        profile = self.profile(tool)
        if self._is_sink(profile):
            refs, _literals = self._payload(profile, args)
            if any(self.values[ref].protected or self.values[ref].untrusted for ref in refs if ref in self.values):
                return Decision(False, "tainted_payload")
        return base


class IFCDeclass(ScopeGate):
    # 信息流控制：私有值经可信变换降密后才能外发，不区分汇点、不要求审批
    name = "ifc-declass"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        profile = self.profile(tool)
        if self._is_sink(profile):
            refs, _literals = self._payload(profile, args)
            for ref in refs:
                value = self.values.get(ref)
                if value is not None and value.protected and not value.declassified:
                    return Decision(False, "secret_payload")
        return base


class IFCDeclassApproval(IFCDeclass):
    name = "ifc-declass+bound-approval"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        profile = self.profile(tool)
        if self._is_sink(profile) and profile.sink is not SinkClass.DESTRUCTIVE_WRITE:
            if not self._valid_bound_approvals(profile.sink, self._binding(profile, args)):
                return Decision(False, "no_bound_approval")
        return base


class CapabilityHandles(ScopeGate):
    # 私有值只以不透明句柄出现，任何私有派生值都不能进入外发汇点
    name = "capability-handles"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        profile = self.profile(tool)
        if self._is_sink(profile):
            refs, _literals = self._payload(profile, args)
            if any(self.values[ref].protected for ref in refs if ref in self.values):
                return Decision(False, "private_handle_to_sink")
        return base


class CurrentPredicates(ScopeGate):
    # 逐调用谓词：接收方或目标在合约名单内、载荷内容不含个人信息模式、读取在允许来源内、提权在预算内
    name = "current-predicates"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        profile = self.profile(tool)
        if not self._source_ok(profile, args):
            return Decision(False, "source_outside_contract")
        if self._is_sink(profile):
            if not self._goal_binding_ok(profile, args):
                return Decision(False, "binding_not_listed")
            refs, literals = self._payload(profile, args)
            text = self._payload_text(refs, literals)
            if any(pattern.search(text) for pattern in PII_PATTERNS):
                return Decision(False, "pii_in_payload")
        return base

    def check_stepup(self, permission: str, bindings: Mapping[str, str] | None = None) -> Decision:
        return self._budget_ok(permission)


class TemporalPhase(ScopeGate):
    # 阶段自动机加事件次序：条件汇点要求之前出现过可信变换和审批，不看值
    name = "temporal-phase"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        profile = self.profile(tool)
        policy = sink_policy(self.spec.contract, self.phase, profile.sink)
        if policy == "deny":
            return Decision(False, "phase_denies_sink")
        if policy == "conditional" and not (self.saw_transform and self.approvals):
            return Decision(False, "order_constraint_unmet")
        return base

    def check_stepup(self, permission: str, bindings: Mapping[str, str] | None = None) -> Decision:
        return self._budget_ok(permission)


class TraceContract(ScopeGate):
    # 只用合约：阶段汇点策略、读取来源和效果绑定，不跟踪值与义务
    name = "trace-contract"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        profile = self.profile(tool)
        if sink_policy(self.spec.contract, self.phase, profile.sink) == "deny":
            return Decision(False, "phase_denies_sink")
        if not self._source_ok(profile, args):
            return Decision(False, "source_outside_contract")
        if self._is_sink(profile) and not self._goal_binding_ok(profile, args):
            return Decision(False, "effect_outside_contract")
        return base

    def check_stepup(self, permission: str, bindings: Mapping[str, str] | None = None) -> Decision:
        return self._budget_ok(permission)


class ArgumentProvenance(ScopeGate):
    # 参数级来源约束：绑定参数必须来自用户给出的合约，载荷不得来自不可信内容
    name = "argument-provenance"

    def check_call(self, tool: str, args: Mapping[str, Any]) -> Decision:
        base = super().check_call(tool, args)
        if not base.allowed:
            return base
        profile = self.profile(tool)
        if self._is_sink(profile):
            if not self._goal_binding_ok(profile, args):
                return Decision(False, "binding_not_grounded")
            refs, _literals = self._payload(profile, args)
            if any(self.values[ref].untrusted for ref in refs if ref in self.values):
                return Decision(False, "untrusted_payload")
        return base

    def check_stepup(self, permission: str, bindings: Mapping[str, str] | None = None) -> Decision:
        return self._budget_ok(permission)


BASELINES: dict[str, type[BaselineMonitor]] = {
    cls.name: cls
    for cls in (
        NoMonitor,
        ScopeGate,
        ApprovalGate,
        BoundApproval,
        TaintBlock,
        IFCDeclass,
        IFCDeclassApproval,
        CapabilityHandles,
        CurrentPredicates,
        TemporalPhase,
        TraceContract,
        ArgumentProvenance,
    )
}

ROPE_VARIANTS: dict[str, RuntimeConfig] = {
    "rope-no-provenance": RuntimeConfig(use_provenance=False),
    "rope-no-obligations": RuntimeConfig(use_obligations=False),
    "rope-no-future": RuntimeConfig(use_future=False),
    "rope-no-repair": RuntimeConfig(use_repair=False),
    "rope-no-certificate": RuntimeConfig(use_certificates=False),
    "rope-raw-text": RuntimeConfig(provenance_mode=ProvenanceMode.RAW_TEXT),
    "rope-scanner": RuntimeConfig(provenance_mode=ProvenanceMode.HYBRID_SCANNER),
    "rope": RuntimeConfig(),
}

SYSTEM_ORDER = tuple(BASELINES) + tuple(ROPE_VARIANTS)


def monitor_factory(system: str, *, max_depth: int | None = None) -> Callable[[Scenario], Any]:
    if system in BASELINES:
        cls = BASELINES[system]
        return lambda scenario: cls(scenario.spec, scenario.profiles)
    config = ROPE_VARIANTS[system]
    if max_depth is not None:
        config = replace(config, max_depth=max_depth)
    return lambda scenario: HostRuntime(scenario.spec, scenario.profiles, config)
