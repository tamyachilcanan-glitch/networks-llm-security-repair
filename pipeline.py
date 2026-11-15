"""
Pipeline de verificacion aislada del proyecto REDES.

Utiliza las respuestas LLM historicas, Vul4Py y Semgrep.
No realiza solicitudes a OpenAI.
"""

import json
import shutil
from pathlib import Path

import config
from models import VerificationResult
from benchmark.vul4py_adapter import execute_evaluation
from analyzers.semgrep_analyzer import (
    load_semgrep_result,
    scan_directory,
)


def verify_isolated_case(case_id, runs_root, workspaces_root):
    """Ejecuta la verificacion y el analisis posterior aislados."""
    config.validate_case(case_id)

    runs_root = Path(runs_root).resolve()
    workspaces_root = Path(workspaces_root).resolve()
    project_root = config.PROJECT_ROOT.resolve()

    def inside(path, parent):
        return path == parent or parent in path.parents

    if inside(runs_root, project_root):
        raise PermissionError("Runs debe estar fuera del proyecto")

    if inside(workspaces_root, project_root):
        raise PermissionError("Workspace debe estar fuera del proyecto")

    if inside(runs_root, workspaces_root) or inside(
        workspaces_root, runs_root
    ):
        raise ValueError("Runs y workspaces no deben superponerse")

    evidence = (
        config.PROJECT_ROOT / "evidence_public" / case_id
    )

    with (evidence / "llm_response.json").open(
        encoding="utf-8"
    ) as file:
        llm = json.load(file)

    annotation_path = evidence / "claim_annotation.json"

    if annotation_path.is_file():
        with annotation_path.open(encoding="utf-8") as file:
            annotation = json.load(file)
    else:
        annotation = {}

    claim = annotation.get(
        "claimed_success",
        llm.get("claimed_success")
    )

    if type(claim) is not bool:
        raise ValueError("Afirmacion LLM invalida")

    if llm.get("case_id") not in (None, case_id):
        raise ValueError("Identificador LLM incorrecto")

    candidate = (
        workspaces_root / case_id / "student_candidate"
    )

    findings_after = None

    if candidate.exists() or candidate.is_symlink():
        raise FileExistsError(
            "Ya existe un candidato. No se permite sobrescribirlo."
        )

    try:
        evaluation = execute_evaluation(
            case_id,
            runs_root,
            workspaces_root,
            keep_candidate=True,
        )

        verification = VerificationResult(
            case_id=case_id,
            patch_applied=evaluation["apply_ok"],
            functional_rc=evaluation.get("functional_rc"),
            security_rc=evaluation.get("exploit_rc"),
        )

        semgrep_before = load_semgrep_result(case_id)

        if verification.patch_applied:
            if candidate.is_symlink() or not candidate.is_dir():
                raise RuntimeError(
                    "El candidato reparado no esta disponible"
                )

            output = (
                runs_root
                / "student"
                / case_id
                / "semgrep_after.json"
            )

            semgrep_after = scan_directory(
                candidate,
                output
            )

            findings_after = semgrep_after["findings"]

        return {
            "case_id": case_id,
            "llm_claimed_success": claim,
            "patch_applied": verification.A,
            "functional_test_pass": verification.F,
            "security_test_pass": verification.S,
            "functional_test_executed":
                verification.functional_test_executed,
            "security_test_executed":
                verification.security_test_executed,
            "verified_repair": verification.verified_repair,
            "false_assurance": int(
                claim and not verification.verified_repair
            ),
            "semgrep_findings_before":
                semgrep_before["findings"],
            "semgrep_findings_after": findings_after,
        }

    finally:
        # Solo se elimina el candidato temporal conocido.
        # Nunca se elimina el workspace vulnerable original.
        if candidate.is_dir() and not candidate.is_symlink():
            shutil.rmtree(candidate)
