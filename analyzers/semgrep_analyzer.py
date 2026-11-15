"""
Integracion de Semgrep Community Edition.

Permite leer resultados existentes y ejecutar
analisis nuevos sin modificar el codigo fuente.
"""

import json
import subprocess
from pathlib import Path

from config import SEMGREP_RESULTS, SEMGREP_CONFIG


def load_semgrep_result(case_id):
    """Lee el analisis previo de un CVE."""

    path = SEMGREP_RESULTS / f"{case_id}_before.json"

    if not path.is_file():
        raise FileNotFoundError(
            f"No existe resultado Semgrep: {case_id}"
        )

    with path.open(encoding="utf-8") as file:
        data = json.load(file)

    findings = data.get("results")
    errors = data.get("errors")

    if not isinstance(findings, list):
        raise ValueError("Resultados Semgrep invalidos")

    if not isinstance(errors, list):
        raise ValueError("Errores Semgrep invalidos")

    if errors:
        raise ValueError(
            f"Semgrep registro errores para {case_id}"
        )

    return {
        "case_id": case_id,
        "findings": len(findings),
        "errors": len(errors),
        "result_file": str(path),
    }


def scan_file(target, output):
    """
    Ejecuta Semgrep sin aplicar modificaciones.

    No sobrescribe resultados existentes.
    """

    target = Path(target)
    output = Path(output)

    if not target.is_file():
        raise FileNotFoundError(target)

    if output.exists():
        raise FileExistsError(output)

    output.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "semgrep",
        "scan",
        "--config",
        SEMGREP_CONFIG,
        "--metrics=off",
        "--json",
        "--output",
        str(output),
        str(target),
    ]

    result = subprocess.run(
        command,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Semgrep termino con codigo {result.returncode}"
        )

    if not output.is_file():
        raise RuntimeError(
            "Semgrep no genero el archivo esperado"
        )

    return output


def scan_directory(target, output):
    """Analiza un directorio candidato y conserva el JSON."""
    target = Path(target).resolve()
    output = Path(output).resolve()

    if not target.is_dir():
        raise NotADirectoryError(target)

    if output.exists():
        raise FileExistsError(output)

    if output == target or target in output.parents:
        raise ValueError(
            "El resultado Semgrep debe guardarse fuera del candidato"
        )

    output.parent.mkdir(parents=True, exist_ok=True)

    command = [
        "semgrep",
        "scan",
        "--config",
        SEMGREP_CONFIG,
        "--metrics=off",
        "--json",
        "--exclude", ".venv",
        "--exclude", "venv",
        "--exclude", ".git",
        "--exclude", "__pycache__",
        "--output", str(output),
        str(target),
    ]

    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            "Semgrep fallo: " + completed.stderr[-2000:]
        )

    if not output.is_file():
        raise RuntimeError("Semgrep no genero el JSON posterior")

    with output.open(encoding="utf-8") as file:
        data = json.load(file)

    findings = data.get("results")
    errors = data.get("errors")

    if not isinstance(findings, list):
        raise ValueError("Resultados Semgrep invalidos")

    if not isinstance(errors, list) or errors:
        raise ValueError("Semgrep registro errores")

    return {
        "findings": len(findings),
        "errors": len(errors),
        "result_file": str(output),
    }
