import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from pipeline import verify_isolated_case


class TestPipelineAfter(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.case = config.CASES[0]
        self.runs = self.root / "runs"
        self.workspaces = self.root / "workspaces"
        self.candidate = (
            self.workspaces / self.case / "student_candidate"
        )

    def fake_evaluator(self, *args, **kwargs):
        self.assertTrue(kwargs["keep_candidate"])
        self.candidate.mkdir(parents=True)
        (self.candidate / "example.py").write_text(
            "print('test')\n", encoding="utf-8"
        )

        return {
            "vuln_id": self.case,
            "apply_ok": True,
            "functional_rc": 0,
            "exploit_rc": 0,
        }

    def test_semgrep_after_and_cleanup(self):
        with patch(
            "pipeline.execute_evaluation",
            side_effect=self.fake_evaluator
        ), patch(
            "pipeline.load_semgrep_result",
            return_value={"findings": 0}
        ), patch(
            "pipeline.scan_directory",
            return_value={"findings": 0}
        ) as scanner:

            result = verify_isolated_case(
                self.case, self.runs, self.workspaces
            )

        scanner.assert_called_once()
        self.assertEqual(result["verified_repair"], 1)
        self.assertEqual(result["false_assurance"], 0)
        self.assertEqual(result["semgrep_findings_after"], 0)
        self.assertFalse(self.candidate.exists())

    def test_semgrep_error_cleanup(self):
        with patch(
            "pipeline.execute_evaluation",
            side_effect=self.fake_evaluator
        ), patch(
            "pipeline.load_semgrep_result",
            return_value={"findings": 0}
        ), patch(
            "pipeline.scan_directory",
            side_effect=RuntimeError("Semgrep fallo")
        ):

            with self.assertRaises(RuntimeError):
                verify_isolated_case(
                    self.case, self.runs, self.workspaces
                )

        self.assertFalse(self.candidate.exists())

    def test_existing_candidate_protected(self):
        self.candidate.mkdir(parents=True)
        marker = self.candidate / "IMPORTANT.txt"
        marker.write_text("DO NOT DELETE", encoding="utf-8")

        with patch("pipeline.execute_evaluation") as evaluator:
            with self.assertRaises(FileExistsError):
                verify_isolated_case(
                    self.case, self.runs, self.workspaces
                )

        evaluator.assert_not_called()
        self.assertEqual(
            marker.read_text(encoding="utf-8"),
            "DO NOT DELETE"
        )


if __name__ == "__main__":
    unittest.main()
