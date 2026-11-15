import unittest
from pathlib import Path
from unittest.mock import patch

import config
from pipeline import verify_isolated_case


class TestPipeline(unittest.TestCase):

    def setUp(self):
        self.case = config.CASES[0]
        self.runs = Path("/tmp/redes_test_runs")
        self.workspaces = Path("/tmp/redes_test_workspaces")

    def test_failed_patch_with_positive_claim(self):
        evaluation = {
            "vuln_id": self.case,
            "apply_ok": False,
            "functional_rc": None,
            "exploit_rc": None,
        }

        with patch(
            "pipeline.execute_evaluation",
            return_value=evaluation
        ) as evaluator:
            with patch(
                "pipeline.load_semgrep_result",
                return_value={"findings": 0}
            ):
                result = verify_isolated_case(
                    self.case,
                    self.runs,
                    self.workspaces
                )

        evaluator.assert_called_once()

        self.assertEqual(result["patch_applied"], 0)
        self.assertEqual(result["verified_repair"], 0)
        self.assertEqual(result["false_assurance"], 1)
        self.assertFalse(result["functional_test_executed"])
        self.assertFalse(result["security_test_executed"])
        self.assertEqual(result["semgrep_findings_before"], 0)
        self.assertIsNone(result["semgrep_findings_after"])

    def test_invalid_case_is_rejected(self):
        with self.assertRaises(ValueError):
            verify_isolated_case(
                "CVE-NO-AUTORIZADO",
                self.runs,
                self.workspaces
            )

    def test_invalid_evaluation_is_rejected(self):
        evaluation = {
            "vuln_id": self.case,
            "apply_ok": False,
            "functional_rc": 0,
            "exploit_rc": 0,
        }

        with patch(
            "pipeline.execute_evaluation",
            return_value=evaluation
        ):
            with self.assertRaises(ValueError):
                verify_isolated_case(
                    self.case,
                    self.runs,
                    self.workspaces
                )


if __name__ == "__main__":
    unittest.main()
