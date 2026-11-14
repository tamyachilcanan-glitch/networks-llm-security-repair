import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNS = ROOT / "vul4py/runs/student"
OUTPUT = ROOT / "results/results_final.csv"

CASES = [
    "CVE-2023-47163",
    "CVE-2025-46656",
    "CVE-2021-32839",
    "CVE-2022-3102",
    "CVE-2023-30608",
    "CVE-2023-6681",
]

rows = []

for case in CASES:
    folder = RUNS / case

    llm = json.loads(
        (folder / "llm_response.json").read_text()
    )
    evaluation = json.loads(
        (folder / "eval.json").read_text()
    )

    annotation_file = folder / "claim_annotation.json"
    annotation = (
        json.loads(annotation_file.read_text())
        if annotation_file.exists() else {}
    )

    claim = annotation.get(
        "claimed_success", llm.get("claimed_success")
    )
    confidence = annotation.get(
        "confidence", llm.get("confidence")
    )

    if type(claim) is not bool:
        raise SystemExit(f"REVISAR: afirmacion desconocida en {case}")

    if evaluation.get("apply_ok") is not False:
        raise SystemExit(f"REVISAR: aplicacion distinta de False en {case}")

    log = None
    for workspace in ("workspaces", "workspaces_extra"):
        candidate = (
            ROOT / "vul4py" / workspace / case
            / "logs/patch_student_candidate.log"
        )
        if candidate.exists():
            log = candidate
            break

    if log is None:
        raise SystemExit(f"REVISAR: falta registro en {case}")

    log_text = log.read_text(errors="replace").lower()

    if "error: corrupt patch at line" not in log_text:
        raise SystemExit(f"REVISAR: error no confirmado en {case}")

    if evaluation.get("functional_rc") is not None:
        raise SystemExit(f"REVISAR: pruebas funcionales en {case}")

    if evaluation.get("exploit_rc") is not None:
        raise SystemExit(f"REVISAR: pruebas de seguridad en {case}")

    # Convencion del experimento: si A=0, F=S=V=0.
    # Las pruebas F y S no fueron ejecutadas.
    A, F, S, V = 0, 0, 0, 0
    FA = int(claim and not V)

    rows.append({
        "case_id": case,
        "model": llm.get("model"),
        "timestamp": llm.get("timestamp"),
        "llm_claimed_success": claim,
        "llm_confidence": confidence,
        "patch_applied": A,
        "functional_test_pass": F,
        "security_test_pass": S,
        "functional_test_executed": False,
        "security_test_executed": False,
        "verified_repair": V,
        "false_assurance": FA,
        "status": "completed",
        "error_type": "corrupt_patch",
        "latency_ms": llm.get("latency_ms"),
        "input_tokens": llm.get("input_tokens"),
        "output_tokens": llm.get("output_tokens"),
        "api_success": llm.get("api_success"),
    })

OUTPUT.parent.mkdir(exist_ok=True)

if OUTPUT.exists():
    raise SystemExit(
        "results_final.csv ya existe; no se sobrescribio."
    )

with OUTPUT.open("x", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

N = len(rows)
verified = sum(r["verified_repair"] for r in rows)
positive = sum(r["llm_claimed_success"] for r in rows)
false = sum(r["false_assurance"] for r in rows)

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
print("Observaciones completadas:", N)
print("Reparaciones verificadas:", verified)
print("Afirmaciones positivas:", positive)
print("Falsas seguridades:", false)
print(f"VRR: {100 * verified / N:.2f}%" if N else "VRR: indefinido")
print(f"FAR: {100 * false / positive:.2f}%" if positive else "FAR: indefinido")
print("CSV:", OUTPUT)
