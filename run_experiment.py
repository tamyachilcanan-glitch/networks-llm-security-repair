"""
Controlador de auditoria del proyecto REDES.

Reconstruye resultados desde evidencias congeladas.
No llama a OpenAI, no aplica parches y no altera archivos.
"""

import argparse
import csv
import json

import config
from benchmark.vul4py_adapter import Vul4PyAdapter
from analyzers.semgrep_analyzer import load_semgrep_result
from models import VerificationResult


def read_json(path):
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def audit_case(case, evidence_root):
    config.validate_case(case)

    folder = evidence_root / case

    llm = read_json(folder / "llm_response.json")
    evaluation = read_json(folder / "eval.json")

    annotation_path = folder / "claim_annotation.json"
    annotation = (
        read_json(annotation_path)
        if annotation_path.is_file()
        else {}
    )

    claimed_success = annotation.get(
        "claimed_success",
        llm.get("claimed_success")
    )

    if type(claimed_success) is not bool:
        raise ValueError(f"{case}: afirmacion invalida")

    if llm.get("case_id") not in (None, case):
        raise ValueError(f"{case}: identificador LLM diferente")

    if evaluation.get("vuln_id") != case:
        raise ValueError(f"{case}: evaluacion incorrecta")

    verification = VerificationResult(
        case_id=case,
        patch_applied=evaluation["apply_ok"],
        functional_rc=evaluation["functional_rc"],
        security_rc=evaluation["exploit_rc"],
    )

    semgrep = load_semgrep_result(case)

    # No existe candidato reparado si no se aplico el parche.
    findings_after = None

    if verification.patch_applied:
        raise ValueError(
            f"{case}: requiere revisar analisis posterior "
            "antes de completar la auditoria"
        )

    false_assurance = int(
        claimed_success and not verification.verified_repair
    )

    return {
        "case_id": case,
        "llm_claimed_success": claimed_success,
        "patch_applied": verification.A,
        "functional_test_pass": verification.F,
        "security_test_pass": verification.S,
        "functional_test_executed":
            verification.functional_test_executed,
        "security_test_executed":
            verification.security_test_executed,
        "verified_repair": verification.verified_repair,
        "false_assurance": false_assurance,
        "semgrep_findings_before": semgrep["findings"],
        "semgrep_findings_after": findings_after,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Auditar los seis experimentos existentes"
    )
    parser.add_argument(
        "--verify-isolated",
        action="store_true"
    )
    parser.add_argument("--case")
    parser.add_argument("--runs-root")
    parser.add_argument("--workspaces-root")

    args = parser.parse_args()

    if args.audit == args.verify_isolated:
        parser.error(
            "Selecciona --audit o --verify-isolated"
        )

    if args.verify_isolated:
        if not all((
            args.case,
            args.runs_root,
            args.workspaces_root
        )):
            parser.error(
                "Faltan --case, --runs-root o --workspaces-root"
            )

        from pipeline import verify_isolated_case

        result = verify_isolated_case(
            args.case,
            args.runs_root,
            args.workspaces_root
        )

        print(json.dumps(result, indent=2))
        print("VERIFICACION AISLADA COMPLETADA")
        return

    if any((
        args.case,
        args.runs_root,
        args.workspaces_root
    )):
        parser.error(
            "Las rutas aisladas requieren --verify-isolated"
        )

    evidence_root = config.PROJECT_ROOT / "evidence_public"

    if not evidence_root.is_dir():
        raise FileNotFoundError(
            "No existe la carpeta evidence_public"
        )

    rows = [
        audit_case(case, evidence_root)
        for case in config.CASES
    ]

    # Comparar con el CSV previamente generado.
    csv_path = config.SEMGREP_RESULTS_CSV

    with csv_path.open(newline="", encoding="utf-8") as file:
        saved_rows = list(csv.DictReader(file))

    if len(saved_rows) != len(rows):
        raise ValueError("Cantidad de observaciones diferente")

    saved_by_case = {
        row["case_id"]: row for row in saved_rows
    }

    if len(saved_by_case) != len(rows):
        raise ValueError("Casos duplicados en el CSV")

    for row in rows:
        case = row["case_id"]

        if case not in saved_by_case:
            raise ValueError(f"{case}: ausente del CSV")

        saved = saved_by_case[case]

        for key, value in row.items():
            if key == "case_id":
                continue

            if isinstance(value, bool):
                expected = str(value)
            elif value is None:
                expected = ""
            else:
                expected = str(value)

            if saved.get(key) != expected:
                raise ValueError(
                    f"{case}: diferencia en {key}: "
                    f"{saved.get(key)!r} != {expected!r}"
                )

    n = len(rows)
    verified = sum(r["verified_repair"] for r in rows)
    positive = sum(r["llm_claimed_success"] for r in rows)
    false = sum(r["false_assurance"] for r in rows)

    print("===== AUDITORIA DE LOS SEIS CVE =====")

    for row in rows:
        print(
            row["case_id"],
            "| V:", row["verified_repair"],
            "| FA:", row["false_assurance"],
            "| Semgrep:", row["semgrep_findings_before"],
        )

    print("\n===== METRICAS =====")
    print("Observaciones:", n)
    print("Reparaciones verificadas:", verified)
    print("Afirmaciones positivas:", positive)
    print("Falsas seguridades:", false)

    print(
        f"VRR: {100 * verified / n:.2f}%"
        if n else "VRR: indefinido"
    )

    print(
        f"FAR: {100 * false / positive:.2f}%"
        if positive else "FAR: indefinido"
    )

    print("\nCSV comparado:", csv_path)
    print("AUDITORIA COMPLETADA CORRECTAMENTE")


if __name__ == "__main__":
    main()
