import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from benchmark.vul4py_adapter import execute_evaluation


class TestExecutor(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = config.CASES[0]
        self.runs = self.root / "runs"
        self.workspaces = self.root / "workspaces"

        workspace = self.workspaces / self.case
        workspace.mkdir(parents=True)
        (workspace / "meta.json").write_text("{}")
        (workspace / "vulnerable").mkdir()

        self.run_dir = self.runs / "student" / self.case
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "patch.diff").write_text("TEST PATCH\n")

    def test_successful_execution(self):
        def fake_run(command, **kwargs):
            self.assertIn("--strict-workspaces", command)
            self.assertIn("--runs", command)
            self.assertIn("--workspaces", command)

            evaluation = {
                "vuln_id": self.case,
                "apply_ok": False,
                "functional_rc": None,
                "exploit_rc": None,
            }

            (self.run_dir / "eval.json").write_text(
                json.dumps(evaluation)
            )

            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("subprocess.run", side_effect=fake_run):
            result = execute_evaluation(
                self.case, self.runs, self.workspaces
            )

        self.assertFalse(result["apply_ok"])
        self.assertIsNone(result["functional_rc"])

    def test_process_failure(self):
        with patch("subprocess.run") as mocked:
            mocked.return_value = subprocess.CompletedProcess(
                [], 1, "", "Evaluation error"
            )

            with self.assertRaises(RuntimeError):
                execute_evaluation(
                    self.case, self.runs, self.workspaces
                )

    def test_missing_evaluation(self):
        with patch("subprocess.run") as mocked:
            mocked.return_value = subprocess.CompletedProcess(
                [], 0, "", ""
            )

            with self.assertRaises(RuntimeError):
                execute_evaluation(
                    self.case, self.runs, self.workspaces
                )

    def test_invalid_evaluation(self):
        def fake_run(command, **kwargs):
            (self.run_dir / "eval.json").write_text(
                json.dumps({
                    "vuln_id": self.case,
                    "apply_ok": "False"
                })
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("subprocess.run", side_effect=fake_run):
            with self.assertRaises(ValueError):
                execute_evaluation(
                    self.case, self.runs, self.workspaces
                )


if __name__ == "__main__":
    unittest.main()
