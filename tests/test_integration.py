"""End-to-end test: starts the whole system and runs every attack scenario of the demo."""
import unittest

import _env  # noqa: F401  (must be first)

from zt.scenarios import Lab, run_all
from zt.stack import Stack


class ZeroTrustEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = Stack().start()
        cls.results = run_all(Lab(cls.stack))

    @classmethod
    def tearDownClass(cls):
        cls.stack.stop()

    def test_every_scenario_behaves_as_expected(self):
        self.assertGreaterEqual(len(self.results), 20)
        for r in self.results:
            with self.subTest(r.tc):
                self.assertTrue(r.ok, '%s %s -> expected %s but observed %s' % (r.tc, r.title, r.expected, r.observed))


if __name__ == '__main__':
    unittest.main()
