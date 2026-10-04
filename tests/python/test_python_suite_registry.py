# SPDX-License-Identifier: GPL-3.0-or-later
"""Meta-test for scripts/run-python-suites.py (audit F-62).

The registry must account for every tests/python suite, both ways, and a
DRIVEN suite's driver must still name it; each failure mode is exercised on
a synthetic tree so a regression in the checker cannot hide behind a clean
real tree.
Run: python3 -I tests/python/test_python_suite_registry.py -v
"""

import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = runpy.run_path(str(ROOT / "scripts" / "run-python-suites.py"))
problems_of = RUNNER["registry_problems"]


def reader(files):
    return files.get


class SuiteRegistryTests(unittest.TestCase):
    def test_the_checked_in_registry_covers_every_suite(self):
        self.assertEqual(RUNNER["check"](ROOT), [])

    def test_a_consistent_registry_has_no_problems(self):
        problems = problems_of(
            {"test_a.py", "test_b.py", "test_c.py"},
            [("test_a.py", [])],
            {"test_b.py": "tests/x.rs"},
            {"test_c.py": "needs hardware"},
            reader({"tests/x.rs": 'run("tests/python/test_b.py")'}),
        )
        self.assertEqual(problems, [])

    def test_an_unregistered_suite_fails(self):
        problems = problems_of(
            {"test_a.py", "test_new.py"}, [("test_a.py", [])], {}, {}, reader({})
        )
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("test_new.py is not registered", problems[0])

    def test_a_registered_suite_that_is_gone_fails(self):
        problems = problems_of(set(), [("test_gone.py", [])], {}, {}, reader({}))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("does not exist", problems[0])

    def test_a_driver_that_no_longer_names_its_suite_fails(self):
        for files in ({"tests/x.rs": "nothing here"}, {}):
            problems = problems_of(
                {"test_b.py"}, [], {"test_b.py": "tests/x.rs"}, {}, reader(files)
            )
            self.assertEqual(len(problems), 1, problems)
            self.assertIn("test_b.py: driver tests/x.rs", problems[0])

    def test_a_pattern_driver_naming_the_file_is_accepted(self):
        problems = problems_of(
            {"test_b.py"},
            [],
            {"test_b.py": "scripts/s.py"},
            {},
            reader({"scripts/s.py": '"-p", "test_b.py",'}),
        )
        self.assertEqual(problems, [])

    def test_a_suite_registered_twice_or_excluded_silently_fails(self):
        problems = problems_of(
            {"test_a.py", "test_c.py"},
            [("test_a.py", [])],
            {"test_a.py": "tests/x.rs"},
            {"test_c.py": " "},
            reader({"tests/x.rs": '"tests/python/test_a.py"'}),
        )
        self.assertEqual(len(problems), 2, problems)
        self.assertIn("registered more than once", problems[0])
        self.assertIn("excluded without a reason", problems[1])

    def test_the_same_suite_may_run_with_different_arguments(self):
        problems = problems_of(
            {"test_a.py"},
            [("test_a.py", ["--bits", "32"]), ("test_a.py", ["--bits", "64"])],
            {},
            {},
            reader({}),
        )
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
