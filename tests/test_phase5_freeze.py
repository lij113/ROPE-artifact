import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Phase51FreezeTests(unittest.TestCase):
    def test_paper_v0_config_and_docs_exist(self):
        required = [
            ROOT / "bench" / "configs" / "paper_v0.yaml",
            ROOT / "bench" / "contracts" / "paper_v0" / "contracts.json",
            ROOT / "bench" / "profiles" / "paper_v0" / "tool_profiles.json",
            ROOT / "bench" / "attacks" / "paper_v0" / "attack_templates.json",
            ROOT / "docs" / "SEMANTIC_SPEC.md",
            ROOT / "docs" / "THREAT_MODEL.md",
            ROOT / "docs" / "EFFECT_PROFILE_SCHEMA.md",
            ROOT / "docs" / "THEOREM_TEST_MATRIX.md",
        ]

        for path in required:
            self.assertTrue(path.exists(), str(path))

    def test_frozen_profile_schema_has_annotation_effort_proxy(self):
        data = json.loads(
            (ROOT / "bench" / "profiles" / "paper_v0" / "tool_profiles.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(data["version"], "paper_v0")
        self.assertGreaterEqual(len(data["profiles"]), 8)
        self.assertTrue(
            all(profile["annotation_fields"] > 0 for profile in data["profiles"])
        )

    def test_frozen_attack_config_matches_template_count(self):
        attack_config = json.loads(
            (ROOT / "bench" / "attacks" / "paper_v0" / "attack_templates.json").read_text(
                encoding="utf-8"
            )
        )
        fixture_templates = json.loads(
            (ROOT / "fixtures" / "attack_templates.json").read_text(encoding="utf-8")
        )

        self.assertEqual(attack_config["version"], "paper_v0")
        self.assertEqual(attack_config["template_count"], len(fixture_templates))


if __name__ == "__main__":
    unittest.main()
