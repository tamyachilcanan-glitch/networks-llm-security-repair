import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "vul4py" / "runs" / "student"
OUTPUT = ROOT / "results" / "results_with_semgrep.csv"

CASES = [
    "CVE-2023-47163",
    "CVE-2025-46656",
    "CVE-2021-32839",
    "CVE-2022-3102",
    "CVE-2023-30608",
    "CVE-2023-6681",
]


def read_json(path):
    with path.open(encoding="utf-8") as file:
        return json.load(file)


def find_patch_log(case):
    for workspace in ("workspaces", "workspaces_extra"):
        candidate = (
            ROOT / "vul4py" / workspace / case
            / "logs" / "patch_student_candidate.log"
        )
        if candidate.exists():
            return candidate
    return None


def read_semgrep(case):
    path = ROOT / "results" / "semgrep" / f"{case}_before.json"

    if not path.is_file():
        raise ValueError(f"{case}: falta resultado Semgrep")

    data = read_json(path)

    findings = data.get("results")
    errors = data.get("errors")

    if not isinstance(findings, list):
        raise ValueError(f"{case}: resultados Semgrep invalidos")

    if not isinstance(errors, list) or errors:
        raise ValueError(f"{case}: Semgrep contiene errores")

    return len(findings)


def process_case(case):
    folder = RUNS / case

    llm = read_json(folder / "llm_response.json")
    evaluation = read_json(folder / "eval.json")

    annotation_file = folder / "claim_annotation.json"
    annotation = (
        read_json(annotation_file)
        if annotation_file.exists() else {}
    )

    claim = annotation.get(
        "claimed_success", llm.get("claimed_success")
    )
    confidence = annotation.get(
        "confidence", llm.get("confidence")
    )

    if type(claim) is not bool:
        raise ValueError(
            f"{case}: afirmacion de exito invalida"
        )

    if confidence is not None:
        if (
            type(confidence) not in (int, float)
            or not 0 <= confidence <= 1
        ):
            raise ValueError(
                f"{case}: confianza invalida"
            )

    apply_ok = evaluation.get("apply_ok")

    if type(apply_ok) is not bool:
        raise ValueError(
            f"{case}: apply_ok invalido"
        )

    functional_rc = evaluation.get("functional_rc")
    exploit_rc = evaluation.get("exploit_rc")

    functional_executed = functional_rc is not None
    security_executed = exploit_rc is not None

    if not apply_ok and (
        functional_executed or security_executed
    ):
        raise ValueError(
            f"{case}: pruebas registradas sin parche aplicado"
        )

    A = int(apply_ok)
    F = int(apply_ok and functional_rc == 0)
    S = int(apply_ok and exploit_rc == 0)

    V = A * F * S
    FA = int(claim and not V)

    error_type = ""

    if not apply_ok:
        patch_log = find_patch_log(case)

        if patch_log is None:
            raise ValueError(
                f"{case}: falta evidencia del error de parche"
            )

        log_text = patch_log.read_text(
            errors="replace"
        ).lower()

        if "error: corrupt patch at line" in log_text:
            error_type = "corrupt_patch"
        else:
            error_type = "patch_did_not_apply"

    elif not functional_executed or not security_executed:
        error_type = "tests_not_executed"

    elif not V:
        error_type = "verification_failed"

    return {
        "case_id": case,
        "model": llm.get("model"),
        "timestamp": llm.get("timestamp"),
        "llm_claimed_success": claim,
        "llm_confidence": confidence,
        "patch_applied": A,
        "functional_test_pass": F,
        "security_test_pass": S,
        "functional_test_executed": functional_executed,
        "security_test_executed": security_executed,
        "verified_repair": V,
        "false_assurance": FA,
        "status": "completed",
        "error_type": error_type,
        "latency_ms": llm.get("latency_ms"),
        "input_tokens": llm.get("input_tokens"),
        "output_tokens": llm.get("output_tokens"),
        "api_success": llm.get("api_success"),
        "semgrep_findings_before": read_semgrep(case),
        "semgrep_findings_after": None,
    }


def main():
    rows = [process_case(case) for case in CASES]

    N = len(rows)
    verified = sum(r["verified_repair"] for r in rows)
    positive = sum(r["llm_claimed_success"] for r in rows)
    false = sum(r["false_assurance"] for r in rows)

    OUTPUT.parent.mkdir(exist_ok=True)

    if OUTPUT.exists():
        raise SystemExit(
            "results_with_semgrep.csv ya existe; no se sobrescribio"
        )

    with OUTPUT.open(
        "x", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=list(rows[0])
        )
        writer.writeheader()
        writer.writerows(rows)

    print("===== RESULTADOS POR CASO =====")

    for row in rows:
        print(
            row["case_id"],
            "C=", int(row["llm_claimed_success"]),
            "A=", row["patch_applied"],
            "V=", row["verified_repair"],
            "FA=", row["false_assurance"],
        )

    print("\n===== METRICAS =====")
    print("Observaciones:", N)
    print("Reparaciones verificadas:", verified)
    print("Afirmaciones positivas:", positive)
    print("Falsas seguridades:", false)

    print(
        f"VRR: {100 * verified / N:.2f}%"
        if N else "VRR: indefinido"
    )

    print(
        f"FAR: {100 * false / positive:.2f}%"
        if positive else "FAR: indefinido"
    )

    print("CSV:", OUTPUT)


if __name__ == "__main__":
    main()
