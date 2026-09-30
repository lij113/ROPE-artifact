import unittest
from pathlib import Path

from rope_bench.controlled_suite import controlled_scenarios, premature_cleanup_scenarios
from rope_bench.stress_suite import (
    attack_scenario,
    benign_scenario,
    build_pool,
    generate_attack_cases,
    generate_benign_cases,
    load_profiles,
)
from rope_bench.trace_monitors import monitor_factory
from rope_bench.trace_world import run_scenario

ROOT = Path(__file__).resolve().parents[1]


def _run(system: str, scenario, *, recover: bool = True):
    return run_scenario(scenario, monitor_factory(system)(scenario), recover=recover)


class ControlledSuiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scenarios = controlled_scenarios(ROOT)
        cls.benign = [s for s in scenarios if s.kind == "benign"]
        # 每个模板取前 12 个变体
        seen: dict[str, int] = {}
        cls.attacks = []
        for scenario in scenarios:
            if scenario.kind != "attack":
                continue
            if seen.get(scenario.family, 0) < 12:
                cls.attacks.append(scenario)
                seen[scenario.family] = seen.get(scenario.family, 0) + 1

    def test_benign_workflows_complete_with_and_without_monitor(self):
        self.assertEqual(len(self.benign), 3)
        for scenario in self.benign:
            self.assertTrue(_run("none", scenario)["task_complete"], scenario.scenario_id)
            self.assertTrue(_run("rope", scenario)["task_complete"], scenario.scenario_id)

    def test_rope_accepts_no_harmful_attack(self):
        for scenario in self.attacks:
            if not _run("none", scenario)["attack_success"]:
                continue
            result = _run("rope", scenario)
            self.assertFalse(result["attack_success"], scenario.scenario_id)

    def test_certificate_ablation_executes_replayed_plans(self):
        replays = [s for s in self.attacks if s.family == "repair_certificate_replay"]
        # 只看危害来自重放计划本身（泄露或越出合约的效果）的用例
        harmful = [s for s in replays if {"G1", "G2"} & set(_run("none", s)["attack_goals"])]
        self.assertTrue(harmful)
        self.assertTrue(all(_run("rope-no-certificate", s)["attack_success"] for s in harmful))
        self.assertFalse(any(_run("rope", s)["attack_success"] for s in harmful))


class PrematureCleanupTests(unittest.TestCase):
    def test_only_future_accept_stops_early_archive_under_coarse_contract(self):
        scenarios = {(s.kind, s.meta["contract"]): s for s in premature_cleanup_scenarios(ROOT)}
        coarse = scenarios[("attack", "coarse")]
        ordered = scenarios[("attack", "phase_ordered")]
        self.assertEqual(_run("none", coarse)["attack_goals"], ["G3"])
        self.assertFalse(_run("rope", coarse)["attack_success"])
        self.assertTrue(_run("rope-no-future", coarse)["attack_success"])
        self.assertFalse(_run("rope-no-future", ordered)["attack_success"])
        for granularity in ("coarse", "phase_ordered"):
            self.assertTrue(_run("rope", scenarios[("benign", granularity)])["task_complete"])


class StressSuiteSampleTests(unittest.TestCase):
    def test_sampled_cases_follow_the_threat_model(self):
        profiles = load_profiles(ROOT)
        pool = build_pool(profiles)
        attacks = generate_attack_cases(profiles)[::997][:24]
        benign = generate_benign_cases(profiles)[::211][:24]
        for case in attacks:
            scenario = attack_scenario(case, pool)
            if _run("none", scenario)["attack_success"]:
                self.assertFalse(_run("rope", scenario)["attack_success"], case.case_id)
        for case in benign:
            scenario = benign_scenario(case, pool)
            self.assertTrue(_run("none", scenario)["task_complete"], case.case_id)


if __name__ == "__main__":
    unittest.main()
