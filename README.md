# ROPE artifact

Code, host effect profiles, benchmark configurations and result files for the article
"ROPE: Residual Obligations and Provenance Enforcement for MCP-Style Agents"
by Jieyu Li, Yuyi Zhang, Yuliang Xue, Sheng Li, Xinpeng Zhang and Zhenxing Qian
(School of Computer Science, Fudan University), submitted to *Computers & Security*.

ROPE is a host-side runtime semantics for MCP-style tool-using agents. It admits a tool
call only if the task contract permits it, every protected value it carries has its
sink-indexed obligations discharged by trusted transforms or bound approvals, any
permission step-up is used by some legal continuation, and a bounded, replayed search
shows that the task can still be completed legally. Rejected calls can be repaired under
certificates that an independent verifier replays.

## Repository layout

| Path | Content |
| --- | --- |
| `rope_core/` | Semantics: events, provenance labels, obligations, task contracts, admission (`Admit`), the bounded search behind `FutureAccept` and `NecessaryPerms` (`future.py`), the host runtime (`runtime.py`), repair, certificates |
| `rope_proxy/` | MCP host-side proxy: `tools/list` and `tools/call` interception, host effect profiles, `_meta["rope/*"]` |
| `rope_bench/` | Evaluation code: AgentDojo compromised planner and in-loop runs, the executed trace suites (`trace_world.py`, `trace_monitors.py`, `controlled_suite.py`, `stress_suite.py`, `trace_eval.py`), the judge probe |
| `rope_attacklab/` | Multi-step attack templates |
| `scripts/` | Entry points for the experiments and table generation |
| `tests/` | Unit tests |
| `fixtures/`, `bench/profiles/`, `bench/configs/`, `bench/contracts/`, `bench/mcp_servers/`, `bench/attacks/` | Workflows, host-reviewed effect profiles, benchmark configuration |
| `bench/mcp_traces/paper_v1/` | Tool lists and capture summaries of the MCP servers captured for the article; raw call payloads are not published because they contain data of the test accounts |
| `bench/results/` | Result files behind the tables of the article and its supplementary material |
| `docs/` | Specification notes: semantics, effect-profile schema, threat models |
| `reports/` | Output of the running-example demo |

## Setup

The core, the unit tests and the executed trace suites need Python 3.10 or newer and no
model access:

    python3 -m venv .venv
    .venv/bin/pip install -e . pytest
    .venv/bin/python -m pytest -q

The AgentDojo experiments use a Python 3.12 environment with AgentDojo at commit
`18b501a630db736e1d0496a496d8d7aa947c596d` (package version 0.1.35) and the `openai`
client:

    python3.12 -m venv .venv-agentdojo
    .venv-agentdojo/bin/pip install "agentdojo @ git+https://github.com/ethz-spylab/agentdojo@18b501a630db736e1d0496a496d8d7aa947c596d" openai
    .venv-agentdojo/bin/pip install -e .

Runs that call a model (look-ahead judges, live agents) use OpenAI-compatible
chat-completions endpoints. The route names and the environment variables each route
reads are defined in `rope_bench/agentdojo_baseline_monitors.py` (`JUDGE_ROUTES`) and
`rope_bench/standard_agentdojo_eval.py`.

## Recomputing the tables from stored results

    .venv/bin/python scripts/summarize_journal_tables.py
    .venv/bin/python scripts/write_trace_tables.py --out <paper>/tables

The first prints every number of the compromised-planner table, the profile audit, the
held-out check, the judge comparison, the live-utility table and the live-model pilot.
The second writes the controlled-suite, judge-probe, stress-suite, family, false-rejection,
provenance-mode, decision-cost and repair tables. Both read only `bench/results` and call
no model.

## Re-running the experiments

`C` below stands for `.venv-agentdojo/bin/python scripts/run_agentdojo_compromised.py`,
`T` for `.venv/bin/python scripts/run_trace_suite.py`, and result paths are relative to
`bench/results/`. The decisions of the trace suites are deterministic: with
`PYTHONHASHSEED=0` a re-run reproduces every stored row of `rows.csv.gz` except its
wall-clock `seconds` column, and `summary.json` except its timing fields.

| Table or result | Command | Results |
| --- | --- | --- |
| Compromised planner: no monitor, ROPE as-published (v1) and audited (v2) profiles | `C --systems base,rope,rope_v2 --run-id e4_compromised_v2b` | `agentdojo_compromised/e4_compromised_v2b` |
| Session taint block | `C --systems taint_block --run-id e4_baseline_taint_block` | `agentdojo_compromised/e4_baseline_taint_block` |
| Monotone value budget | `C --systems monotone_budget --run-id e4_baseline_monotone` | `agentdojo_compromised/e4_baseline_monotone` |
| Look-ahead judge, claude-sonnet-5 | `ROPE_JUDGE_ROUTE=claude-api C --systems llm_lookahead,llm_lookahead_strict` over user-task slices (`--suites`, `--user-task-offset`, `--user-task-limit`); the adaptive injection adds `--monitor-note --no-benign --systems llm_lookahead` | `agentdojo_compromised/e4_llm_*`, `agentdojo_compromised/e4_llm_note_*` |
| Look-ahead judge, deepseek-flash | the same with `ROPE_JUDGE_ROUTE=deepseek-api` | `agentdojo_compromised/e7_wj_deepseek-flash_*`, `agentdojo_compromised/e7_wj_note_deepseek-flash_*` |
| Profile audit, one rule left out at a time | `ROPE_AGENTDOJO_V2_RULES=fetch,commit,ident C --systems rope_v2 --run-id e4_ablation_no_fields`, and likewise for `fetch`, `commit`, `ident`; `e4_ablation_all` keeps all four rules | `agentdojo_compromised/e4_ablation_*` |
| Held-out reworded injections | `C --benchmark-version v1.2.2 --systems base,rope,rope_v2 --run-id e4_heldout_v122`; the article counts the banking injections 0–6 and 8 and the travel injections 2 and 5, whose goals v1.2.2 rewords and which carry attacker ground truth | `agentdojo_compromised/e4_heldout_v122` |
| Controlled suite, executed | `T --suite controlled --run-id controlled_v1` | `trace_suites/controlled_v1` |
| Premature cleanup | `T --suite cleanup --run-id cleanup` | `trace_suites/cleanup` |
| Stress suite, executed, with the search-bound sweep | `T --suite stress --run-id stress_v1 --k-sweep 4,6,8,10` | `trace_suites/stress_v1` |
| Provenance modes | `T --suite stress --systems none,rope,rope-raw-text,rope-scanner --run-id stress_modes` | `trace_suites/stress_modes` |
| Decision cost | `.venv/bin/python scripts/measure_decision_cost.py --attack-limit 2000 --benign-limit 500` | `trace_suites/decision_cost.json` |
| Judge comparison on the stress-suite sample | `ROPE_JUDGE_ROUTE=claude-api .venv/bin/python scripts/run_controlled_judge_probe.py`, and `ROPE_JUDGE_ROUTE=deepseek-api`; the stored verdict caches make this run offline, and `--online` asks the judge for any verdict not cached | `controlled_judge_probe/` |
| Running-example certificate replay | `.venv/bin/python scripts/replay_certificate.py` | `certificate_replay/` |
| Replay of every stored AgentDojo sink decision through the current engine | `.venv-agentdojo/bin/python scripts/replay_agentdojo_decisions.py` | prints the counts; all 13,677 decisions reproduce |
| Live utility | `.venv-agentdojo/bin/python scripts/run_agentdojo_inloop.py --suites workspace,travel,banking,slack --routes <route> --systems base,rope --injection-task-limit 0 --run-id e4_benign_v1_<route>`; the audited profile sets `ROPE_AGENTDOJO_PROFILE=v2` with `--systems rope --run-id e4_benign_v2_<route>` | `agentdojo_inloop/e4_benign_*` |
| Live models on AgentDojo's own attacks | `.venv-agentdojo/bin/python scripts/run_agentdojo_inloop.py --suites banking,slack --routes <route> --systems base --user-task-limit 8 --injection-task-limit 3 --no-benign --attack important_instructions_no_model_name`, and `--attack tool_knowledge` | `agentdojo_inloop/e4_pilot_*` |
| AgentDojo in-loop results and scope split (run `inloop_main_v4`) | `.venv-agentdojo/bin/python scripts/run_agentdojo_inloop_report.py` | `agentdojo_inloop/inloop_main_v4` |

## Executed trace suites

Every monitor in `rope_bench/trace_monitors.py` (ROPE, its ablations and provenance modes,
eleven baseline monitors, and `none`) decides the same event traces through
`rope_bench/trace_world.py`. The environment executes each admitted call; an oracle that no
monitor sees marks an attack successful when the executed effects achieve an attacker goal
of the article's threat model, and only traces that achieve a goal with no monitor are
scored. The baselines are executable abstractions of published monitor objects, not those
systems' code.

## License

The code and the result files of this repository are released under the MIT License
(see `LICENSE`). Third-party material keeps its own license, as listed below.

## Third-party material

AgentDojo (MIT License, https://github.com/ethz-spylab/agentdojo) supplies the suites,
tasks and injections of the AgentDojo experiments; the stored transcripts contain its
synthetic user data.
