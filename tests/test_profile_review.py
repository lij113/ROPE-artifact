import unittest
from pathlib import Path

from rope_bench.profile_review import review_captured_profiles


ROOT = Path(__file__).resolve().parents[1]


class ProfileReviewTests(unittest.TestCase):
    def test_reviewed_profiles_keep_discharge_untrusted(self):
        result = review_captured_profiles(ROOT)

        self.assertGreater(result["profile_count"], 0)
        self.assertTrue(
            all(not item["trusted_for_obligation_discharge"] for item in result["profiles"])
        )
        self.assertTrue(
            (ROOT / "bench/profiles/paper_v1/host_reviewed_profiles.json").exists()
        )


if __name__ == "__main__":
    unittest.main()
