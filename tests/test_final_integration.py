import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from pipeline import verify_isolated_case


class TestFinalIntegration(unittest.TestCase):

    def test_real_semgrep_and_candidate_cleanup(self):
        with tempfile.TemporaryDirectory(
            prefix="redes_final_validation_"
        ) as temporary:

            root = Path(temporary)
            case = config.CASES[0]
            runs = root / "runs"
            workspaces = root / "workspaces"
            candidate = (
                workspaces / case / "student_candidate"
            )

            def simulated_evaluation(*args, **kwargs):
                self.assertTrue(kwargs["keep_candidate"])

                candidate.mkdir(parents=True)

                (candidate / "example.py").write_text(
                    "import hashlib\n"
                    "def digest(data):\n"
                    "    return hashlib.sha1(data).hexdigest()\n",
                    encoding="utf-8"
                )

                return {
                    "vuln_id": case,
                    "apply_ok": True,
                    "functional_rc": 0,
                    "exploit_rc": 0,
                }

            with patch(
                "pipeline.execute_evaluation",
                side_effect=simulated_evaluation
            ):
                result = verify_isolated_case(
                    case,
                    runs,
                    workspaces
                )

            report = (
                runs / "student" / case / "semgrep_after.json"
            )

            self.assertTrue(report.is_file())
            self.assertFalse(candidate.exists())
            self.assertEqual(result["verified_repair"], 1)
            self.assertEqual(result["false_assurance"], 0)
            self.assertIsInstance(
                result["semgrep_findings_after"], int
            )

            print("\n===== INTEGRACION FINAL =====")
            print("Reporte Semgrep:", report.is_file())
            print(
                "Hallazgos posteriores:",
                result["semgrep_findings_after"]
            )
            print("Candidato eliminado:", not candidate.exists())
            print("INTEGRACION POSTERIOR VERIFICADA")


if __name__ == "__main__":
    unittest.main()
