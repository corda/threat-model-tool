# -*- coding: utf-8 -*-

from .context import R3ThreatModeling

import unittest


class AdvancedTestSuite(unittest.TestCase):
    """Advanced test cases."""

    def test_thoughts(self):
        self.assertIsNone(R3ThreatModeling.hmm())


if __name__ == '__main__':
    unittest.main()
