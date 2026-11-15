"""Adaptador modular de Vul4Py para evaluaciones aisladas."""

import csv
import json
from pathlib import Path

import config
from models import EvaluationResult
from benchmark.vul4py_adapter import (
    prepare_evaluation,
    execute_evaluation,
)


class Vul4PyAdapter:
    """Implementa el contrato BenchmarkAdapter."""

    def __init__(self, root=None, runs_root=None, workspaces_root=None):
        self.root = Path(
            root if root is not None else config.VUL4PY_ROOT
        ).resolve()

        self.runs_root = (
            Path(runs_root).resolve()
            if runs_root is not None else None
        )

        self.workspaces_root = (
            Path(workspaces_root).resolve()
            if workspaces_root is not None else None
        )

    def valid_cases(self):
        valid = set()

        for folder in ("workspaces", "workspaces_extra"):
            report = self.root / folder / "scan_report.tsv"

            if not report.is_file():
                continue

            with report.open(
                encoding="utf-8-sig", newline=""
            ) as file:
                for row in csv.DictReader(file, delimiter="\t"):
                    if (
                        row.get("status") == "OK"
                        and row.get("cve_id") in config.CASES
                    ):
                        valid.add(row["cve_id"])

        return [
            case for case in config.CASES
            if case in valid
        ]

    def vulnerable_dir(self, case_id):
        config.validate_case(case_id)

        if case_id not in self.valid_cases():
            raise ValueError("CVE sin validacion OK")

        if self.workspaces_root is not None:
            candidates = [
                self.workspaces_root / case_id / "vulnerable"
            ]
        else:
            candidates = [
                self.root / "workspaces" / case_id / "vulnerable",
                self.root / "workspaces_extra" / case_id / "vulnerable",
            ]

        for candidate in candidates:
            if candidate.is_dir():
                return candidate

        raise FileNotFoundError(
            "No existe codigo vulnerable para " + case_id
        )

    def apply_patch(self, case_id, patch):
        """Evalua exclusivamente un parche previamente congelado."""
        config.validate_case(case_id)

        if self.runs_root is None or self.workspaces_root is None:
            raise ValueError(
                "Se requieren runs_root y workspaces_root aislados"
            )

        if not isinstance(patch, str) or not patch:
            raise ValueError("Parche invalido")

        # La validacion debe suceder antes de ejecutar Vul4Py.
        prepare_evaluation(
            case_id,
            self.runs_root,
            self.workspaces_root
        )

        frozen = (
            self.runs_root / "student" / case_id / "patch.diff"
        )

        if frozen.read_text(encoding="utf-8") != patch:
            raise ValueError(
                "El parche no coincide con el original congelado"
            )

        result = execute_evaluation(
            case_id,
            self.runs_root,
            self.workspaces_root,
            keep_candidate=True,
        )

        return self._to_result(case_id, result)

    def evaluate(self, case_id, candidate_dir):
        """Lee los resultados guardados por Vul4Py."""
        config.validate_case(case_id)

        if self.runs_root is None or self.workspaces_root is None:
            raise ValueError("No se configuraron rutas aisladas")

        expected = (
            self.workspaces_root
            / case_id
            / "student_candidate"
        ).resolve()

        if Path(candidate_dir).resolve() != expected:
            raise ValueError("Directorio candidato incorrecto")

        # Valida el entorno aislado y protege eval.json existente.
        if self.runs_root == self.workspaces_root:
            raise ValueError("Directorios superpuestos")

        path = (
            self.runs_root / "student" / case_id / "eval.json"
        )

        if not path.is_file():
            raise FileNotFoundError(path)

        with path.open(encoding="utf-8") as file:
            result = json.load(file)

        return self._to_result(case_id, result)

    def _to_result(self, case_id, result):
        if result.get("vuln_id") != case_id:
            raise ValueError("Identificador incorrecto")

        applied = result.get("apply_ok")

        if type(applied) is not bool:
            raise ValueError("Estado de aplicacion invalido")

        functional_rc = result.get("functional_rc")
        security_rc = result.get("exploit_rc")

        if not applied and (
            functional_rc is not None
            or security_rc is not None
        ):
            raise ValueError("Evaluacion inconsistente")

        candidate = (
            self.workspaces_root / case_id / "student_candidate"
            if applied and self.workspaces_root is not None
            else None
        )

        return EvaluationResult(
            patch_applied=applied,
            security_test_pass=bool(
                applied and security_rc == 0
            ),
            functional_test_pass=bool(
                applied and functional_rc == 0
            ),
            candidate_dir=candidate,
        )
