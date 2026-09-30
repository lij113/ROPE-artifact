import unittest


class ImportSmokeTests(unittest.TestCase):
    def test_phase1_packages_import(self) -> None:
        import rope_attacklab
        import rope_bench
        import rope_core
        import rope_proxy

        self.assertEqual(rope_core.EventKind.CALL.value, "call")
        self.assertIn("repair_cert", rope_proxy.ROPE_META_KEYS)
        self.assertTrue(callable(rope_bench.load_fixture))
        self.assertTrue(hasattr(rope_attacklab, "AttackTemplate"))


if __name__ == "__main__":
    unittest.main()
