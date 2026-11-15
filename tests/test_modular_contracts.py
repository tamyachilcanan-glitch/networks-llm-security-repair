import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from models import EvaluationResult, AnalyzerResult
from benchmarks.base import BenchmarkAdapter
from benchmarks.vul4py import Vul4PyAdapter
from analyzers.base import Analyzer
from analyzers.semgrep import SemgrepAnalyzer


class TestModularContracts(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = config.CASES[0]
        self.runs = self.root / "runs"
        self.workspaces = self.root / "workspaces"

    def adapter(self):
        return Vul4PyAdapter(
            runs_root=self.runs,
            workspaces_root=self.workspaces
        )

    def test_benchmark_contract(self):
        adapter = self.adapter()
        self.assertIsInstance(adapter, BenchmarkAdapter)

    def test_rejected_patch_mapping(self):
        result = self.adapter()._to_result(
            self.case,
            {
                "vuln_id": self.case,
                "apply_ok": False,
                "functional_rc": None,
                "exploit_rc": None,
            }
        )

        self.assertIsInstance(result, EvaluationResult)
        self.assertFalse(result.patch_applied)
        self.assertFalse(result.functional_test_pass)
        self.assertFalse(result.security_test_pass)

    def test_successful_patch_mapping(self):
        result = self.adapter()._to_result(
            self.case,
            {
                "vuln_id": self.case,
                "apply_ok": True,
                "functional_rc": 0,
                "exploit_rc": 0,
            }
        )

        self.assertTrue(result.patch_applied)
        self.assertTrue(result.functional_test_pass)
        self.assertTrue(result.security_test_pass)

    def test_frozen_patch_is_protected(self):
        adapter = self.adapter()

        run_dir = self.runs / "student" / self.case
        run_dir.mkdir(parents=True)

        (run_dir / "patch.diff").write_text(
            "ORIGINAL PATCH\n",
            encoding="utf-8"
        )

        with patch(
            "benchmarks.vul4py.prepare_evaluation",
            return_value=["python", "evaluate.py"]
        ), patch(
            "benchmarks.vul4py.execute_evaluation"
        ) as executor:

            with self.assertRaises(ValueError):
                adapter.apply_patch(
                    self.case,
                    "DIFFERENT PATCH\n"
                )

            executor.assert_not_called()

    def test_read_saved_evaluation(self):
        adapter = self.adapter()

        run_dir = self.runs / "student" / self.case
        run_dir.mkdir(parents=True)

        (run_dir / "eval.json").write_text(
            json.dumps({
                "vuln_id": self.case,
                "apply_ok": False,
                "functional_rc": None,
                "exploit_rc": None,
            }),
            encoding="utf-8"
        )

        candidate = (
            self.workspaces / self.case / "student_candidate"
        )

        result = adapter.evaluate(self.case, candidate)
        self.assertFalse(result.patch_applied)

    def test_analyzer_contract_and_results(self):
        original = self.root / "original"
        candidate = self.root / "candidate"

        original.mkdir()
        candidate.mkdir()

        analyzer = SemgrepAnalyzer(self.root / "reports")

        self.assertIsInstance(analyzer, Analyzer)

        with patch(
            "analyzers.semgrep.scan_directory",
            return_value={"findings": 2, "errors": 0}
        ) as scanner:

            result = analyzer.run(original, candidate)

        self.assertIsInstance(result, AnalyzerResult)
        self.assertEqual(scanner.call_count, 2)

        self.assertEqual(
            result.values["semgrep_findings_before"], 2
        )

        self.assertEqual(
            result.values["semgrep_findings_after"], 2
        )


if __name__ == "__main__":
    unittest.main()
