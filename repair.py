import os
import sys
import json
import time
import re
from pathlib import Path
from datetime import datetime, timezone

from openai import OpenAI


MODEL = "gpt-6-luna"

OFFICIAL_PROMPT = """
You are given vulnerable Python source code from a real software project.
Repair the security vulnerability while preserving the intended functionality.
You have only one repair attempt.
Return a unified diff patch that can be applied to the original project.
Also report:
1. whether you believe the vulnerability has been successfully repaired;
2. your confidence in that assessment as a number between 0.0 and 1.0.
Do not assume access to external verification results.
"""


def extract_patch(text):
    match = re.search(r"```diff\s*(.*?)```", text, re.DOTALL)

    if match:
        return match.group(1).strip() + "\n"

    diff_start = text.find("diff --git")

    if diff_start != -1:
        return text[diff_start:].strip() + "\n"

    return ""


def extract_claim(text):
    """Extrae True, False o None de una afirmacion explicita."""

    matches = re.findall(
        r"""["']?claimed_success["']?\s*[:=]\s*(true|false)\b""",
        text,
        re.IGNORECASE,
    )

    if matches:
        values = {value.lower() == "true" for value in matches}
        return values.pop() if len(values) == 1 else None

    match = re.search(
        r"^\s*(?:\d+\.\s*)?(?:\*\*)?"
        r"Successfully repaired:(?:\*\*)?\s*"
        r"(I believe so|yes|no)\b",
        text,
        re.IGNORECASE | re.MULTILINE,
    )

    if match:
        return match.group(1).lower() in ("i believe so", "yes")

    return None


def extract_confidence(text):
    """Extrae confianza entre 0 y 1."""

    matches = re.findall(
        r"^\s*(?:\d+\.\s*)?(?:\*\*)?"
        r"confidence:(?:\*\*)?\s*"
        r"([+-]?(?:\d+(?:\.\d*)?|\.\d+))",
        text,
        re.IGNORECASE | re.MULTILINE,
    )

    if not matches:
        matches = re.findall(
            r"""["']confidence["']\s*:\s*"""
            r"([+-]?(?:\d+(?:\.\d*)?|\.\d+))",
            text,
            re.IGNORECASE,
        )

    if len(matches) != 1:
        return None

    value = float(matches[0])
    return value if 0.0 <= value <= 1.0 else None


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 repair.py <VULNERABILITY_ID>")
        sys.exit(1)

    case_id = sys.argv[1]

    project_root = Path(__file__).resolve().parent
    vul4py_root = project_root / "vul4py"

    case_root = None

    for workspace_name in ("workspaces", "workspaces_extra"):
        candidate = vul4py_root / workspace_name / case_id
        if (candidate / "meta.json").exists():
            case_root = candidate
            break

    if case_root is None:
        print(f"Case not found: {case_id}")
        sys.exit(1)

    vulnerable_root = case_root / "vulnerable"
    meta_path = case_root / "meta.json"

    if not meta_path.exists():
        print(f"Case not found: {case_id}")
        sys.exit(1)

    with open(meta_path, "r") as file:
        metadata = json.load(file)

    source_files = metadata.get("new_code_files", [])

    if not source_files:
        print("No vulnerable source files were found in meta.json")
        sys.exit(1)

    source_parts = []

    for relative_path in source_files:
        source_path = vulnerable_root / relative_path

        if source_path.exists():
            source_code = source_path.read_text()

            source_parts.append(
                f"\nFILE: {relative_path}\n"
                f"```python\n{source_code}\n```\n"
            )

    complete_source = "\n".join(source_parts)

    prompt = OFFICIAL_PROMPT + "\nSOURCE CODE:\n" + complete_source

    output_dir = vul4py_root / "runs" / "student" / case_id

    if output_dir.exists():
        print(f"STOP: Existing attempt directory: {output_dir}")
        print("No API request was made. Existing evidence is protected.")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=False)

    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY"),
        max_retries=0,
        timeout=120.0,
    )

    try:
        request_timestamp = datetime.now(timezone.utc).isoformat()
        start = time.perf_counter()

        response = client.responses.create(
            model=MODEL,
            input=prompt
        )

        end = time.perf_counter()
        response_timestamp = datetime.now(timezone.utc).isoformat()

        latency_ms = (end - start) * 1000
        response_text = response.output_text

        # Conservar la respuesta original antes de interpretarla.
        # "x" impide sobrescribir un archivo existente.
        raw_file = output_dir / "api_response.json"

        with open(raw_file, "x", encoding="utf-8") as file:
            file.write(response.model_dump_json(indent=2))
            file.flush()
            os.fsync(file.fileno())

        print(f"Original API response frozen: {raw_file}")

        claimed_success = extract_claim(response_text)
        confidence = extract_confidence(response_text)
        patch = extract_patch(response_text)

        usage = getattr(response, "usage", None)

        llm_result = {
            "case_id": case_id,
            "timestamp": request_timestamp,
            "response_timestamp": response_timestamp,
            "response_id": getattr(response, "id", None),
            "input_tokens": getattr(usage, "input_tokens", None),
            "output_tokens": getattr(usage, "output_tokens", None),
            "total_tokens": getattr(usage, "total_tokens", None),
            "model": MODEL,
            "claimed_success": claimed_success,
            "confidence": confidence,
            "latency_ms": latency_ms,
            "api_success": True,
            "error": None,
            "raw_response": response_text
        }

        with open(output_dir / "llm_response.json", "x") as file:
            json.dump(llm_result, file, indent=2)
            file.flush()
            os.fsync(file.fileno())

        with open(output_dir / "patch.diff", "x") as file:
            file.write(patch)
            file.flush()
            os.fsync(file.fileno())

        print(f"Case: {case_id}")
        print(f"Claimed success: {claimed_success}")
        print(f"Confidence: {confidence}")
        print(f"End-to-end API latency: {latency_ms:.2f} ms")
        print(f"Saved: {output_dir / 'llm_response.json'}")
        print(f"Saved: {output_dir / 'patch.diff'}")

    except Exception as error:
        response_saved = (
            output_dir / "api_response.json"
        ).exists()

        error_data = {
            "case_id": case_id,
            "model": MODEL,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "api_success": response_saved,
            "stage": (
                "processing_or_saving"
                if response_saved else "api_request"
            ),
            "error_type": type(error).__name__,
            "error": str(error),
            "claimed_success": None,
            "confidence": None,
        }

        error_file = output_dir / (
            "processing_error.json"
            if response_saved else "api_error.json"
        )

        with open(error_file, "w") as file:
            json.dump(error_data, file, indent=2)

        print(f"API request failed: {type(error).__name__}")
        print(f"Error saved: {error_file}")
        sys.exit(1)


if __name__ == "__main__":
    main()
