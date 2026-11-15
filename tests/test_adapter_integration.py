import tempfile
import unittest
from pathlib import Path

import config
from benchmark.vul4py_adapter import prepare_evaluation


class TestAdapterIntegration(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.runs = self.root / "runs"
        self.workspaces = self.root / "workspaces"
        self.case = config.CASES[0]

        workspace = self.workspaces / self.case
        workspace.mkdir(parents=True)
        (workspace / "meta.json").write_text("{}")
        (workspace / "vulnerable").mkdir()

        self.case_run = self.runs / "student" / self.case
        self.case_run.mkdir(parents=True)
        (self.case_run / "patch.diff").write_text("TEST PATCH\n")

    def test_valid_command(self):
        command = prepare_evaluation(
            self.case,
            self.runs,
            self.workspaces
        )

        self.assertIn("--workspaces", command)
        self.assertIn("--runs", command)
        self.assertIn("--vuln-id", command)
        self.assertEqual(
            command[command.index("--vuln-id") + 1],
            self.case
        )
        self.assertEqual(
            command[command.index("--workspaces") + 1],
            str(self.workspaces.resolve())
        )
        self.assertEqual(
            command[command.index("--runs") + 1],
            str(self.runs.resolve())
        )

    def test_existing_evaluation_is_protected(self):
        (self.case_run / "eval.json").write_text("{}")

        with self.assertRaises(FileExistsError):
            prepare_evaluation(
                self.case,
                self.runs,
                self.workspaces
            )

    def test_missing_patch_is_rejected(self):
        (self.case_run / "patch.diff").unlink()

        with self.assertRaises(FileNotFoundError):
            prepare_evaluation(
                self.case,
                self.runs,
                self.workspaces
            )

    def test_unauthorized_agent_is_rejected(self):
        with self.assertRaises(ValueError):
            prepare_evaluation(
                self.case,
                self.runs,
                self.workspaces,
                agent="other"
            )


if __name__ == "__main__":
    unittest.main()
