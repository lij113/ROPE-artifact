import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rope_bench.agentdojo_inloop_eval import GENERIC_CONTRACT, SUITE_PROFILES  # noqa: E402
from rope_core.model import (  # noqa: E402
    Event,
    EventKind,
    ModelContext,
    Obligation,
    ProvenanceMode,
    RuntimeState,
    SideEffect,
    SinkClass,
    StructuredAction,
    TaskPhase,
    ValueLabel,
)
from rope_core.semantics import admit  # noqa: E402

# 用当前引擎重放 AgentDojo 运行中存下的每一条 ROPE 汇点判定（义务与已解除原子取自日志），核对是否与原判定一致


def parse_atom(text: str) -> Obligation:
    name, _, rest = text.partition("(")
    args = {}
    for part in rest.rstrip(")").split(","):
        if part:
            key, _, value = part.partition("=")
            args[key] = value
    return Obligation.atom(name, **args)


def sink_for(suite: str, tool: str) -> SinkClass:
    # 审计后的 v2 档案把 get_webpage 记为出站读取（公网汇点）
    if tool == "get_webpage":
        return SinkClass.PUBLIC_WEB
    return SUITE_PROFILES[suite][tool].sink


def replay(record: dict) -> bool:
    suite = record["suite"]
    tool = record["tool"]
    sink = sink_for(suite, tool)
    required = [parse_atom(atom) for atom in record["obligations"]]
    discharged = [parse_atom(atom) for atom in record["discharged"]]
    obligation = Obligation.conjunction(*required) if required else Obligation.top()
    label = ValueLabel(
        source_ids=frozenset({"untrusted_observation"}),
        sensitivity="internal",
        purposes=frozenset({"user_task"}),
        obligations={sink: obligation},
    )
    profile = SUITE_PROFILES[suite].get(tool)
    side = SideEffect.WRITE if profile is not None and profile.kind == "destructive" else SideEffect.SEND
    event = Event(
        event_id=f"call:{tool}",
        kind=EventKind.CALL,
        payload={"tool": tool},
        action=StructuredAction(action=tool, resource=suite, sink=sink, side_effect=side, purpose="user_task"),
    )
    state = RuntimeState(
        task_phase=TaskPhase.COMMIT_OR_SEND,
        provenance_graph_id="agentdojo_trace",
        model_context=ModelContext(epoch_id="agentdojo", mode=ProvenanceMode.RAW_TEXT),
    )
    decision = admit(GENERIC_CONTRACT, state, event, input_labels=(label,), discharged=tuple(discharged))
    return decision.kind.value == "allow"


def main() -> None:
    files = sorted((ROOT / "bench/results/agentdojo_compromised").rglob("decisions*.jsonl"))
    files += sorted((ROOT / "bench/results/agentdojo_inloop").rglob("decisions*.jsonl"))
    counts = Counter()
    mismatches = []
    for path in files:
        inloop_rope = "_rope_" in path.name
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            system = record.get("system", "rope" if inloop_rope else "")
            if not str(system).startswith("rope"):
                continue
            if record.get("reason") == "non_sink_tool":
                counts["non_sink"] += 1
                continue
            counts["replayed"] += 1
            if replay(record) == bool(record["allowed"]):
                counts["same"] += 1
            else:
                mismatches.append((str(path.relative_to(ROOT)), record["tool"], record["allowed"]))
    print(json.dumps({"files": len(files), **counts, "mismatches": len(mismatches)}, indent=1))
    for item in mismatches[:20]:
        print(item)


if __name__ == "__main__":
    main()
