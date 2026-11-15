import tempfile
import unittest
from pathlib import Path

import config
from benchmark.vul4py_adapter import prepare_evaluation


class TestAdapter(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runs = self.root / "runs"
        self.workspaces = self.root / "workspaces"
        self.case = config.CASES[0]

    def test_historical_directory_blocked(self):
        with self.assertRaises(PermissionError):
            prepare_evaluation(
                self.case,
                config.RUNS_ROOT.parent,
                self.workspaces
            )

    def test_missing_workspace(self):
        with self.assertRaises(FileNotFoundError):
            prepare_evaluation(
                self.case,
                self.runs,
                self.workspaces
            )

    def test_invalid_case(self):
        with self.assertRaises(ValueError):
            prepare_evaluation(
                "CVE-NO-AUTORIZADO",
                self.runs,
                self.workspaces
            )

    def test_same_directories_rejected(self):
        with self.assertRaises(ValueError):
            prepare_evaluation(
                self.case,
                self.runs,
                self.runs
            )


if __name__ == "__main__":
    unittest.main()
