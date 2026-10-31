"""The CI runner reports unittest outcomes in its exit status and result JSON."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "ci" / "run_unittest.py"
MODULE = "test_cqa_ci_fixture"


class CiRunnerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="cqa-ci-runner-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.suite = self.tmp / "suite"
        self.suite.mkdir()
        self.result_json = self.tmp / "out" / "results.json"

    def _run(self, body=None, start=None):
        if body is not None:
            (self.suite / f"{MODULE}.py").write_text(
                "import unittest\n\n\nclass Fixture(unittest.TestCase):\n" + textwrap.indent(textwrap.dedent(body), "    "),
                encoding="utf-8",
            )
        completed = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--start-directory",
                str(start or self.suite),
                "--result-json",
                str(self.result_json),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertTrue(self.result_json.is_file(), completed.stdout + completed.stderr)
        return completed, json.loads(self.result_json.read_text(encoding="utf-8"))

    def test_passing_test_exits_zero(self):
        completed, data = self._run("""
        def test_ok(self):
            self.assertEqual(1 + 1, 2)
        """)
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertTrue(data["success"])
        self.assertEqual(data["tests_run"], 1)
        self.assertEqual(data["failures"], 0)
        self.assertEqual(data["errors"], 0)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["platform"], sys.platform)
        self.assertIn(f"({MODULE}.Fixture.test_ok) ... ok", completed.stdout)

    def test_failing_test_exits_nonzero(self):
        completed, data = self._run("""
        def test_broken(self):
            self.assertEqual(1 + 1, 3)
        """)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(data["success"])
        self.assertEqual(data["tests_run"], 1)
        self.assertEqual(data["failures"], 1)
        self.assertEqual(data["errors"], 0)
        self.assertEqual(data["failure_details"][0]["id"], f"{MODULE}.Fixture.test_broken")
        self.assertIn("AssertionError", data["failure_details"][0]["traceback"])

    def test_skipped_test_records_its_reason(self):
        completed, data = self._run("""
        @unittest.skip("platform facility is absent")
        def test_platform(self):
            raise AssertionError("must not run")
        """)
        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertTrue(data["success"])
        self.assertEqual(data["skipped"], 1)
        self.assertEqual(
            data["skipped_details"],
            [{"id": f"{MODULE}.Fixture.test_platform", "reason": "platform facility is absent"}],
        )

    def test_erroring_test_exits_nonzero(self):
        completed, data = self._run("""
        def test_raises(self):
            raise RuntimeError("boom")
        """)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(data["success"])
        self.assertEqual(data["failures"], 0)
        self.assertEqual(data["errors"], 1)
        self.assertEqual(data["error_details"][0]["id"], f"{MODULE}.Fixture.test_raises")
        self.assertIn("RuntimeError: boom", data["error_details"][0]["traceback"])

    def test_missing_start_directory_exits_nonzero(self):
        completed, data = self._run(start=self.tmp / "absent")
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(data["success"])
        self.assertEqual(data["tests_run"], 0)
        self.assertTrue(data["discovery_errors"])

    def test_empty_selection_exits_nonzero(self):
        completed, data = self._run()
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(data["success"])
        self.assertEqual(data["tests_run"], 0)


if __name__ == "__main__":
    unittest.main()
