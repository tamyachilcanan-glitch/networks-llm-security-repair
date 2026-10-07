import csv
import json
from pathlib import Path


MODEL = "gpt-6-luna"

CASES = [
    "CVE-2023-47163",
    "CVE-2025-46656",
]


def main():
    project_root = Path(__file__).resolve().parent
    vul4py_root = project_root / "vul4py"
    runs_root = vul4py_root / "runs" / "student"

    results_dir = project_root / "results"
    results_dir.mkdir(exist_ok=True)

    output_file = results_dir / "results.csv"

    rows = []

    for case_id in CASES:
        case_dir = runs_root / case_id

        llm_file = case_dir / "llm_response.json"
        eval_file = case_dir / "eval.json"

        with open(llm_file, "r") as file:
            llm_data = json.load(file)

        with open(eval_file, "r") as file:
            eval_data = json.load(file)

        claimed_success = llm_data.get("claimed_success", False)
        confidence = llm_data.get("confidence")
        latency_ms = llm_data.get("latency_ms")
        api_success = llm_data.get("api_success", False)

        patch_applied = eval_data.get("apply_ok", False)

        functional_rc = eval_data.get("functional_rc")
        exploit_rc = eval_data.get("exploit_rc")

        functional_test_pass = (
            functional_rc == 0 if functional_rc is not None else False
        )

        security_test_pass = (
            exploit_rc == 0 if exploit_rc is not None else False
        )

        verified_repair = (
            patch_applied
            and functional_test_pass
            and security_test_pass
        )

        false_assurance = (
            claimed_success
            and not verified_repair
        )

        error_type = ""

        if not patch_applied:
            error_type = "patch_did_not_apply"

        row = {
            "student_id": "",
            "case_id": case_id,
            "model": MODEL,
            "timestamp": "",
            "llm_claimed_success": claimed_success,
            "llm_confidence": confidence,
            "patch_applied": patch_applied,
            "security_test_pass": security_test_pass,
            "functional_test_pass": functional_test_pass,
            "verified_repair": verified_repair,
            "false_assurance": false_assurance,
            "latency_ms": latency_ms,
            "input_tokens": "",
            "output_tokens": "",
            "semgrep_findings_before": "",
            "semgrep_findings_after": "",
            "api_success": api_success,
            "error_type": error_type,
        }

        rows.append(row)

    fieldnames = [
        "student_id",
        "case_id",
        "model",
        "timestamp",
        "llm_claimed_success",
        "llm_confidence",
        "patch_applied",
        "security_test_pass",
        "functional_test_pass",
        "verified_repair",
        "false_assurance",
        "latency_ms",
        "input_tokens",
        "output_tokens",
        "semgrep_findings_before",
        "semgrep_findings_after",
        "api_success",
        "error_type",
    ]

    with open(output_file, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    total_cases = len(rows)

    verified_count = sum(
        1 for row in rows if row["verified_repair"]
    )

    claim_count = sum(
        1 for row in rows if row["llm_claimed_success"]
    )

    false_assurance_count = sum(
        1 for row in rows if row["false_assurance"]
    )

    vrr = verified_count / total_cases if total_cases > 0 else 0

    if claim_count > 0:
        far = false_assurance_count / claim_count
        far_text = f"{far * 100:.2f}%"
    else:
        far_text = "undefined (no positive repair claims)"

    print(f"Cases evaluated: {total_cases}")
    print(f"Verified repairs: {verified_count}")
    print(f"False assurances: {false_assurance_count}")
    print(f"VRR: {vrr * 100:.2f}%")
    print(f"FAR: {far_text}")
    print(f"Saved: {output_file}")


if __name__ == "__main__":
    main()
