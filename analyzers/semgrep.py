"""Analizador Semgrep intercambiable para REDES."""

from pathlib import Path

import config
from models import AnalyzerResult
from analyzers.semgrep_analyzer import scan_directory


class SemgrepAnalyzer:
    name = "semgrep"

    def __init__(self, output_dir):
        self.output_dir = Path(output_dir).resolve()

        project = config.PROJECT_ROOT.resolve()

        if (
            self.output_dir == project
            or project in self.output_dir.parents
        ):
            raise PermissionError(
                "Los resultados nuevos deben guardarse fuera del proyecto"
            )

    def run(self, original_dir, candidate_dir=None):
        original = Path(original_dir).resolve()

        if not original.is_dir():
            raise NotADirectoryError(original_dir)

        candidate = None

        if candidate_dir is not None:
            raw_candidate = Path(candidate_dir)

            if raw_candidate.is_symlink():
                raise ValueError("Candidato simbolico no permitido")

            candidate = raw_candidate.resolve()

            if not candidate.is_dir():
                raise NotADirectoryError(candidate_dir)

            if candidate == original:
                raise ValueError("Original y candidato son iguales")

        for source in (original, candidate):
            if source is None:
                continue

            if (
                self.output_dir == source
                or source in self.output_dir.parents
                or self.output_dir in source.parents
            ):
                raise ValueError(
                    "Directorio de resultados superpuesto al codigo"
                )

        before = self.output_dir / "semgrep_before.json"
        after = self.output_dir / "semgrep_after.json"

        if before.exists() or after.exists():
            raise FileExistsError(
                "No se permite sobrescribir informes existentes"
            )

        before_result = scan_directory(original, before)

        after_result = None

        if candidate is not None:
            after_result = scan_directory(candidate, after)

        return AnalyzerResult(
            name=self.name,
            values={
                "semgrep_findings_before": before_result["findings"],
                "semgrep_findings_after": (
                    after_result["findings"]
                    if after_result is not None else None
                ),
                "semgrep_before_file": str(before),
                "semgrep_after_file": (
                    str(after) if after_result is not None else None
                ),
            },
        )
