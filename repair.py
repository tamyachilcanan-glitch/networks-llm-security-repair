import os
import sys
import json
import time
import re
from pathlib import Path

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
    lower = text.lower()

    if "claimed_success" in lower:
        match = re.search(
            r"claimed_success[\"']?\s*[:=]\s*(true|false)",
            lower
        )
        if match:
            return match.group(1) == "true"

    if "successfully repaired" in lower:
        return True

    return False


def extract_confidence(text):
    match = re.search(
        r"confidence[\"']?\s*[:=]?\s*(0(?:\.\d+)?|1(?:\.0+)?)",
        text.lower()
    )

    if match:
        return float(match.group(1))

    return None


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 repair.py <VULNERABILITY_ID>")
        sys.exit(1)

    case_id = sys.argv[1]

    project_root = Path(__file__).resolve().parent
    vul4py_root = project_root / "vul4py"

    case_root = vul4py_root / "workspaces" / case_id
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
    output_dir.mkdir(parents=True, exist_ok=True)

    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY")
    )

    try:
        start = time.perf_counter()

        response = client.responses.create(
            model=MODEL,
            input=prompt
        )

        end = time.perf_counter()

        latency_ms = (end - start) * 1000
        response_text = response.output_text

        claimed_success = extract_claim(response_text)
        confidence = extract_confidence(response_text)
        patch = extract_patch(response_text)

        llm_result = {
            "case_id": case_id,
            "model": MODEL,
            "claimed_success": claimed_success,
            "confidence": confidence,
            "latency_ms": latency_ms,
            "api_success": True,
            "error": None,
            "raw_response": response_text
        }

        with open(output_dir / "llm_response.json", "w") as file:
            json.dump(llm_result, file, indent=2)

        (output_dir / "patch.diff").write_text(patch)

        print(f"Case: {case_id}")
        print(f"Claimed success: {claimed_success}")
        print(f"Confidence: {confidence}")
        print(f"End-to-end API latency: {latency_ms:.2f} ms")
        print(f"Saved: {output_dir / 'llm_response.json'}")
        print(f"Saved: {output_dir / 'patch.diff'}")

    except Exception as error:
        print(f"API request failed: {error}")


if __name__ == "__main__":
    main()
