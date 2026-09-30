from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace

from rope_core.model import Obligation, SideEffect, SinkClass, TaskContract, TaskPhase

# 义务原子的可哈希形式：(名称, 排序后的参数)
AtomKey = tuple[str, tuple[tuple[str, str], ...]]


def atom_key(atom: Obligation) -> AtomKey:
    return (atom.name, tuple(sorted((str(key), str(value)) for key, value in atom.args.items())))


def atom_keys(obligation: Obligation) -> frozenset[AtomKey]:
    return frozenset(atom_key(atom) for atom in obligation.atoms())


def atom_text(key: AtomKey) -> str:
    name, args = key
    if not args:
        return name
    return f"{name}(" + ",".join(f"{k}={v}" for k, v in args) + ")"


@dataclass(frozen=True)
class AbstractValue:
    # 抽象值：值类别、派生来源、可信变换已完成的原子、各汇点剩余的义务原子
    value_class: str
    sources: frozenset[str] = frozenset()
    transforms: frozenset[AtomKey] = frozenset()
    residual: frozenset[tuple[SinkClass, AtomKey]] = frozenset()

    def residual_for(self, sink: SinkClass) -> frozenset[AtomKey]:
        return frozenset(atom for atom_sink, atom in self.residual if atom_sink is sink)


@dataclass(frozen=True)
class TaskGoal:
    # 合约的交付目标：值到达某个汇点（绑定用途、接收方、来源和必需的可信变换），或删除某个资源
    goal_id: str
    sink: SinkClass
    purpose: str = ""
    recipient: str = ""
    sources: frozenset[str] = frozenset()
    transforms: frozenset[AtomKey] = frozenset()
    removes: str = ""
    # 可选目标：合约允许的效果，但完成任务不要求它发生
    optional: bool = False
    # 交付值必须属于的数据类别（空表示不限）
    value_class: str = ""


@dataclass(frozen=True)
class AbstractAction:
    # 任务合法后续可用的抽象效果，由主机档案和合约给出
    name: str
    sink: SinkClass = SinkClass.LOCAL_DISPLAY
    side_effect: SideEffect = SideEffect.NONE
    reads: str = ""
    value_class: str = ""
    takes_value: bool = False
    discharges: frozenset[AtomKey] = frozenset()
    approves: TaskGoal | None = None
    delivers: bool = False
    recipient: str = ""
    purpose: str = ""
    removes: str = ""
    permission: str = ""
    grants: str = ""
    consumes: str = ""
    advances_to: TaskPhase | None = None
    # 产出某数据类别的变换：输出加上该类别的义务
    adds_class: str = ""


@dataclass(frozen=True)
class AbstractState:
    # 附录 A 的抽象状态：阶段、仍存在的资源、带剩余义务的值、权限、已实现目标、剩余预算
    phase: TaskPhase
    resources: frozenset[str] = frozenset()
    values: frozenset[AbstractValue] = frozenset()
    permissions: frozenset[str] = frozenset()
    realized: frozenset[str] = frozenset()
    budgets: tuple[tuple[str, int], ...] = ()

    def budget(self, name: str) -> int | None:
        for key, remaining in self.budgets:
            if key == name:
                return remaining
        return None


@dataclass(frozen=True)
class SearchSpace:
    phase_order: tuple[TaskPhase, ...]
    accepting: frozenset[TaskPhase]
    sink_policy: Mapping[TaskPhase, Mapping[SinkClass, str]]
    goals: tuple[TaskGoal, ...] = ()
    actions: tuple[AbstractAction, ...] = ()
    obligation_policy: Mapping[str, Mapping[SinkClass, frozenset[AtomKey]]] = field(default_factory=dict)
    # 合约没有动作模型时，每一步可以把阶段推进一格
    free_phase_advance: bool = False


@dataclass(frozen=True)
class SearchContext:
    # 运行时交给 Admit 的抽象视图：搜索空间、事件前状态、模拟事件后的状态
    space: SearchSpace
    pre_state: AbstractState
    post_state: AbstractState


def phase_space(contract: TaskContract) -> SearchSpace:
    return SearchSpace(
        phase_order=contract.phase_order,
        accepting=contract.accepting_phases,
        sink_policy=contract.sink_policy,
        free_phase_advance=True,
    )


def sink_policy(space: SearchSpace, phase: TaskPhase, sink: SinkClass) -> str:
    return space.sink_policy.get(phase, {}).get(sink, "deny")


def marked(space: SearchSpace, state: AbstractState) -> bool:
    if state.phase not in space.accepting:
        return False
    if any(goal.goal_id not in state.realized for goal in space.goals if not goal.optional):
        return False
    return all(remaining >= 0 for _name, remaining in state.budgets)


def open_atoms(state: AbstractState, value: AbstractValue, sink: SinkClass) -> frozenset[AtomKey]:
    # 仍未解除的原子；提权原子在对应权限已授予时视为解除
    granted = {("stepup", (("permission", permission),)) for permission in state.permissions}
    return frozenset(atom for atom in value.residual_for(sink) if atom not in granted)


def goal_satisfied_by_delivery(
    goal: TaskGoal,
    action: AbstractAction,
    value: AbstractValue,
    state: AbstractState,
) -> bool:
    if goal.removes or goal.sink is not action.sink:
        return False
    if goal.purpose and goal.purpose != action.purpose:
        return False
    if goal.recipient and goal.recipient != action.recipient:
        return False
    if goal.value_class and goal.value_class != value.value_class:
        return False
    if not goal.sources.issubset(value.sources):
        return False
    if not goal.transforms.issubset(value.transforms):
        return False
    return not open_atoms(state, value, goal.sink)


def approval_matches(atom: AtomKey, goal: TaskGoal) -> bool:
    name, args = atom
    if name != "approve":
        return False
    fields = dict(args)
    return (
        fields.get("sink") == goal.sink.value
        and fields.get("purpose", "") == goal.purpose
        and fields.get("recipient", "") == goal.recipient
    )


def successors(
    space: SearchSpace,
    state: AbstractState,
) -> Iterator[tuple[str, AbstractState, AbstractAction | None]]:
    if space.free_phase_advance and state.phase in space.phase_order:
        index = space.phase_order.index(state.phase)
        if index + 1 < len(space.phase_order):
            nxt = space.phase_order[index + 1]
            yield f"advance:{nxt.value}", replace(state, phase=nxt), None
    for action in space.actions:
        for label, nxt in _apply(space, state, action):
            yield label, nxt, action


def _advance(space: SearchSpace, state: AbstractState, target: TaskPhase | None) -> AbstractState:
    if target is None or target not in space.phase_order or state.phase not in space.phase_order:
        return state
    if space.phase_order.index(target) > space.phase_order.index(state.phase):
        return replace(state, phase=target)
    return state


def _consume(state: AbstractState, name: str) -> AbstractState:
    if not name:
        return state
    return replace(
        state,
        budgets=tuple(
            (key, remaining - 1 if key == name else remaining)
            for key, remaining in state.budgets
        ),
    )


def _apply(
    space: SearchSpace,
    state: AbstractState,
    action: AbstractAction,
) -> Iterator[tuple[str, AbstractState]]:
    if action.permission and action.permission not in state.permissions:
        return
    if action.consumes:
        remaining = state.budget(action.consumes)
        if remaining is not None and remaining <= 0:
            return
    policy = sink_policy(space, state.phase, action.sink)
    if policy == "deny":
        return

    if action.grants:
        if action.grants in state.permissions:
            return
        granted = replace(state, permissions=state.permissions | {action.grants})
        yield action.name, _advance(space, _consume(granted, action.consumes), action.advances_to)
        return

    if action.reads:
        if action.reads not in state.resources:
            return
        residual = frozenset(
            (sink, atom)
            for sink, atoms in space.obligation_policy.get(action.value_class, {}).items()
            for atom in atoms
        )
        value = AbstractValue(
            value_class=action.value_class,
            sources=frozenset({action.reads}),
            residual=residual,
        )
        if value in state.values:
            return
        read = replace(state, values=state.values | {value})
        yield action.name, _advance(space, _consume(read, action.consumes), action.advances_to)
        return

    if action.removes:
        if action.removes not in state.resources:
            return
        removed = replace(state, resources=state.resources - {action.removes})
        realized = removed.realized | {
            goal.goal_id for goal in space.goals if goal.removes == action.removes
        }
        removed = replace(removed, realized=realized)
        yield action.name, _advance(space, _consume(removed, action.consumes), action.advances_to)
        return

    if not action.takes_value:
        # 只推进阶段的动作（如本地草稿、展示给用户）
        advanced = _advance(space, _consume(state, action.consumes), action.advances_to)
        if advanced.phase != state.phase:
            yield action.name, advanced
        return
    for value in sorted(state.values, key=_value_order):
        label = f"{action.name}[{value.value_class}|{_transform_tag(value)}]"
        if action.adds_class:
            added = frozenset(
                (sink, atom)
                for sink, atoms in space.obligation_policy.get(action.adds_class, {}).items()
                for atom in atoms
            )
            out = AbstractValue(
                value_class=action.adds_class,
                sources=value.sources,
                transforms=value.transforms,
                residual=value.residual | added,
            )
            if out in state.values:
                continue
            nxt = replace(state, values=state.values | {out})
            yield label, _advance(space, _consume(nxt, action.consumes), action.advances_to)
        elif action.discharges:
            out = AbstractValue(
                value_class=value.value_class,
                sources=value.sources,
                transforms=value.transforms | action.discharges,
                residual=frozenset(
                    (sink, atom) for sink, atom in value.residual if atom not in action.discharges
                ),
            )
            if out == value or out in state.values:
                continue
            nxt = replace(state, values=state.values | {out})
            yield label, _advance(space, _consume(nxt, action.consumes), action.advances_to)
        elif action.approves is not None:
            goal = action.approves
            kept = frozenset(
                (sink, atom)
                for sink, atom in value.residual
                if not (sink is goal.sink and approval_matches(atom, goal))
            )
            if kept == value.residual:
                continue
            out = replace(value, residual=kept)
            if out in state.values:
                continue
            nxt = replace(state, values=state.values | {out})
            yield label, _advance(space, _consume(nxt, action.consumes), action.advances_to)
        elif action.delivers:
            if policy == "conditional" and open_atoms(state, value, action.sink):
                continue
            realized = state.realized | {
                goal.goal_id
                for goal in space.goals
                if goal_satisfied_by_delivery(goal, action, value, state)
            }
            nxt = replace(state, realized=realized)
            nxt = _advance(space, _consume(nxt, action.consumes), action.advances_to)
            if nxt == state:
                continue
            yield label, nxt


def _value_order(value: AbstractValue) -> tuple:
    return (value.value_class, sorted(value.sources), sorted(value.transforms), sorted(
        (sink.value, atom) for sink, atom in value.residual
    ))


def _transform_tag(value: AbstractValue) -> str:
    done = "+".join(sorted(atom_text(atom) for atom in value.transforms)) or "raw"
    open_atoms = len(value.residual)
    return f"{done}|open={open_atoms}"


def replay_witness(space: SearchSpace, start: AbstractState, labels: Sequence[str]) -> AbstractState | None:
    # 见证重放：沿同一转移关系逐步重放候选后续，任何一步不可行即失败
    state = start
    for label in labels:
        for candidate, nxt, _action in successors(space, state):
            if candidate == label:
                state = nxt
                break
        else:
            return None
    return state


def bounded_search(
    space: SearchSpace,
    start: AbstractState,
    max_depth: int,
    *,
    must_use_permission: str = "",
) -> dict[str, object]:
    # 深度不超过 k 的广度优先搜索；must_use_permission 非空时，见证中必须有动作使用该权限
    def done(state: AbstractState, used: bool) -> bool:
        return marked(space, state) and (not must_use_permission or used)

    if done(start, False):
        return _report(space, start, True, max_depth, 1, 0, (), [start.phase], [])

    queue: deque[tuple[AbstractState, tuple[str, ...], tuple[TaskPhase, ...], bool]] = deque(
        [(start, (), (start.phase,), False)]
    )
    visited: set[tuple[AbstractState, bool]] = {(start, False)}
    expanded = 0
    frontier = 1
    bound_hit = False
    while queue:
        state, path, phases, used = queue.popleft()
        if len(path) >= max_depth:
            bound_hit = True
            continue
        expanded += 1
        for label, nxt, action in successors(space, state):
            now_used = used or bool(
                must_use_permission and action is not None and action.permission == must_use_permission
            )
            key = (nxt, now_used)
            if key in visited:
                continue
            visited.add(key)
            new_path = path + (label,)
            new_phases = phases if nxt.phase == phases[-1] else phases + (nxt.phase,)
            if done(nxt, now_used):
                replayed = replay_witness(space, start, new_path)
                if replayed is not None and marked(space, replayed):
                    return _report(space, replayed, True, max_depth, frontier, expanded, new_path, list(new_phases), [])
                continue
            queue.append((nxt, new_path, new_phases, now_used))
        frontier = max(frontier, len(queue))
    pruned = ["bound"] if bound_hit else ["exhausted"]
    return _report(space, start, False, max_depth, frontier, expanded, (), [start.phase], pruned)


def _report(
    space: SearchSpace,
    final: AbstractState,
    accepted: bool,
    bound: int,
    frontier: int,
    expanded: int,
    actions: Sequence[str],
    phases: Iterable[TaskPhase],
    pruned_by: list[str],
) -> dict[str, object]:
    failed: list[str] = []
    if not accepted:
        failed.extend(sorted(phase.value for phase in space.accepting))
        failed.extend(
            sorted(goal.goal_id for goal in space.goals if not goal.optional and goal.goal_id not in final.realized)
        )
    return {
        "accepted": accepted,
        "bound": bound,
        "frontier_size": frontier,
        "expanded": expanded,
        "witness": [phase.value for phase in phases],
        "actions": list(actions),
        "failed_goals": failed,
        "pruned_by": pruned_by,
    }
