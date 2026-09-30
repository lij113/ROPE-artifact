import csv
import tempfile
import unittest
from pathlib import Path

from rope_bench.agentdojo_inloop_report import summarize_agentdojo_inloop_run


class AgentDojoInloopReportTests(unittest.TestCase):
    def test_report_aggregates_native_security_and_utility_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "bench/results/agentdojo_inloop/test_run"
            run_dir.mkdir(parents=True)
            attack_path = run_dir / "attack_rows_workspace_glm.csv"
            benign_path = run_dir / "benign_rows_workspace_glm.csv"
            error_path = run_dir / "errors_workspace_glm.csv"

            with attack_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "system",
                        "route",
                        "suite",
                        "user_task",
                        "injection_task",
                        "utility",
                        "security_pass",
                        "attack_success",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "system": "base",
                        "route": "glm",
                        "suite": "workspace",
                        "user_task": "user_task_0",
                        "injection_task": "injection_task_0",
                        "utility": "1",
                        "security_pass": "0",
                        "attack_success": "1",
                    }
                )
                writer.writerow(
                    {
                        "system": "rope",
                        "route": "glm",
                        "suite": "workspace",
                        "user_task": "user_task_0",
                        "injection_task": "injection_task_0",
                        "utility": "1",
                        "security_pass": "1",
                        "attack_success": "0",
                    }
                )

            with benign_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["system", "route", "suite", "user_task", "utility"],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "system": "base",
                        "route": "glm",
                        "suite": "workspace",
                        "user_task": "user_task_0",
                        "utility": "1",
                    }
                )
                writer.writerow(
                    {
                        "system": "rope",
                        "route": "glm",
                        "suite": "workspace",
                        "user_task": "user_task_0",
                        "utility": "1",
                    }
                )
            error_path.write_text("", encoding="utf-8")

            summary = summarize_agentdojo_inloop_run(root, run_id="test_run")
            by_system = {row["system"]: row for row in summary["aggregate_rows"]}
            scope_rows = {
                (row["scope"], row["system"]): row for row in summary["scope_rows"]
            }

            self.assertEqual(summary["status"], "completed")
            self.assertEqual(summary["matched_status"], "completed")
            self.assertEqual(by_system["base"]["agentdojo_asr"], 1.0)
            self.assertEqual(by_system["rope"]["agentdojo_asr"], 0.0)
            self.assertEqual(
                scope_rows[("sink_governed", "base")]["agentdojo_asr"], 1.0
            )
            self.assertEqual(
                scope_rows[("sink_governed", "rope")]["agentdojo_asr"], 0.0
            )
            self.assertTrue(
                (root / "paper/rope/tables/table_agentdojo_inloop.tex").exists()
            )
            self.assertTrue(
                (root / "paper/rope/tables/table_agentdojo_scope_split.tex").exists()
            )

    def test_report_distinguishes_matched_status_from_failed_route_cells(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "bench/results/agentdojo_inloop/test_run"
            run_dir.mkdir(parents=True)
            with (run_dir / "attack_rows_workspace_glm.csv").open(
                "w", encoding="utf-8", newline=""
            ) as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "system",
                        "route",
                        "suite",
                        "user_task",
                        "injection_task",
                        "utility",
                        "security_pass",
                        "attack_success",
                    ],
                )
                writer.writeheader()
                for system in ("base", "rope"):
                    writer.writerow(
                        {
                            "system": system,
                            "route": "glm",
                            "suite": "workspace",
                            "user_task": "user_task_0",
                            "injection_task": "injection_task_0",
                            "utility": "1",
                            "security_pass": "1",
                            "attack_success": "0",
                        }
                    )
            with (run_dir / "benign_rows_workspace_glm.csv").open(
                "w", encoding="utf-8", newline=""
            ) as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["system", "route", "suite", "user_task", "utility"],
                )
                writer.writeheader()
                for system in ("base", "rope"):
                    writer.writerow(
                        {
                            "system": system,
                            "route": "glm",
                            "suite": "workspace",
                            "user_task": "user_task_0",
                            "utility": "1",
                        }
                    )
            with (run_dir / "errors_workspace_gpt-api.csv").open(
                "w", encoding="utf-8", newline=""
            ) as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=["system", "suite", "injection_task", "error"]
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "system": "base",
                        "suite": "workspace",
                        "injection_task": "injection_task_0",
                        "error": "APIConnectionError: Connection error.",
                    }
                )

            summary = summarize_agentdojo_inloop_run(root, run_id="test_run")
            table = (
                root / "paper/rope/tables/table_agentdojo_inloop.tex"
            ).read_text(encoding="utf-8")

            self.assertEqual(summary["status"], "partial")
            self.assertEqual(summary["matched_status"], "completed")
            self.assertEqual(len(summary["failed_route_cells"]), 1)
            self.assertIn("matched-complete cells", table)
            self.assertIn("route-level status partial", table)

    def test_report_splits_sink_governed_and_text_output_attacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "bench/results/agentdojo_inloop/test_run"
            run_dir.mkdir(parents=True)
            with (run_dir / "attack_rows_travel_glm.csv").open(
                "w", encoding="utf-8", newline=""
            ) as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "system",
                        "route",
                        "suite",
                        "user_task",
                        "injection_task",
                        "utility",
                        "security_pass",
                        "attack_success",
                    ],
                )
                writer.writeheader()
                for system, inj0, inj6 in (
                    ("base", "1", "1"),
                    ("rope", "0", "1"),
                ):
                    writer.writerow(
                        {
                            "system": system,
                            "route": "glm",
                            "suite": "travel",
                            "user_task": "user_task_0",
                            "injection_task": "injection_task_0",
                            "utility": "1",
                            "security_pass": "0" if inj0 == "1" else "1",
                            "attack_success": inj0,
                        }
                    )
                    writer.writerow(
                        {
                            "system": system,
                            "route": "glm",
                            "suite": "travel",
                            "user_task": "user_task_0",
                            "injection_task": "injection_task_6",
                            "utility": "1",
                            "security_pass": "0",
                            "attack_success": inj6,
                        }
                    )
            with (run_dir / "benign_rows_travel_glm.csv").open(
                "w", encoding="utf-8", newline=""
            ) as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["system", "route", "suite", "user_task", "utility"],
                )
                writer.writeheader()
                for system in ("base", "rope"):
                    writer.writerow(
                        {
                            "system": system,
                            "route": "glm",
                            "suite": "travel",
                            "user_task": "user_task_0",
                            "utility": "1",
                        }
                    )

            summary = summarize_agentdojo_inloop_run(root, run_id="test_run")
            scope_rows = {
                (row["scope"], row["system"]): row for row in summary["scope_rows"]
            }
            scope_table = (
                root / "paper/rope/tables/table_agentdojo_scope_split.tex"
            ).read_text(encoding="utf-8")

            self.assertEqual(
                scope_rows[("sink_governed", "base")]["agentdojo_asr"], 1.0
            )
            self.assertEqual(
                scope_rows[("sink_governed", "rope")]["agentdojo_asr"], 0.0
            )
            self.assertEqual(
                scope_rows[("text_output", "base")]["agentdojo_asr"], 1.0
            )
            self.assertEqual(
                scope_rows[("text_output", "rope")]["agentdojo_asr"], 1.0
            )
            self.assertIn("Out-of-scope (text-output)", scope_table)


if __name__ == "__main__":
    unittest.main()
