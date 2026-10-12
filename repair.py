import os
# Lets the program read the OpenAI API key from an environment variable

import sys
# Lets the program read the CVE ID that we write in the terminal command

import json
# Lets the program read meta.json and save the model result as JSON

import time
# Lets the program measure how long the OpenAI API request takes

import re
# Lets the program search specific patterns inside the model response

from pathlib import Path
# Makes it easier to create and work with file and folder paths

from openai import OpenAI
# Imports the OpenAI client used to send the request to the model


# Defines the OpenAI model used for this experiment
MODEL = "gpt-6-luna"


# Defines the instructions that will be sent to the model
# The model must repair the vulnerability, return a patch,
# report if it believes the repair worked, and give a confidence value
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


# Receives the complete model response and extracts only the patch
def extract_patch(text):

    # Searches for code written inside a ```diff ... ``` block
    match = re.search(r"```diff\s*(.*?)```", text, re.DOTALL)

    # If a diff block is found, return only the content of that block
    if match:
        return match.group(1).strip() + "\n"

    # If there is no ```diff``` block, search for the normal Git diff header
    diff_start = text.find("diff --git")

    # If "diff --git" is found, return the response starting from that point
    if diff_start != -1:
        return text[diff_start:].strip() + "\n"

    # If no patch format is found, return an empty string
    return ""


# Receives the model response and extracts its success claim
def extract_claim(text):

    # Converts the response to lowercase so uppercase/lowercase do not affect the search
    lower = text.lower()

    # Checks if the model used the field "claimed_success"
    if "claimed_success" in lower:

        # Searches for claimed_success followed by true or false
        match = re.search(
            r"claimed_success[\"']?\s*[:=]\s*(true|false)",
            lower
        )

        # If the value was found, return True when it says "true"
        # and False when it says "false"
        if match:
            return match.group(1) == "true"

    # If the model did not use claimed_success,
    # this checks another possible success phrase
    if "successfully repaired" in lower:
        return True

    # If no success statement is found, the function returns False
    return False


# Receives the model response and extracts the confidence value
def extract_confidence(text):

    # Searches for the word "confidence" followed by a number from 0 to 1
    # It also accepts simple Markdown formatting such as **Confidence:** 0.83
    match = re.search(
        r'confidence["\']?\s*[*_]*\s*[:=]\s*[*_]*\s*(0(?:\.\d+)?|1(?:\.0+)?)',
        text.lower()
    )

    # If a confidence value is found, convert the text value into a decimal number
    if match:
        return float(match.group(1))

    # If the response does not contain a readable confidence value, return None
    return None


# Main function that controls the complete repair process
def main():

    # The command must contain exactly one CVE ID after repair.py
    # Example: python3 repair.py CVE-2023-47163
    if len(sys.argv) != 2:
        print("Usage: python3 repair.py <VULNERABILITY_ID>")
        sys.exit(1)

    # Gets the CVE ID from the terminal command and stores it in case_id
    case_id = sys.argv[1]


    # Gets the folder where this repair.py file is located
    project_root = Path(__file__).resolve().parent

    # Creates the path to the Vul4Py folder inside our project
    vul4py_root = project_root / "vul4py"


    # Creates the path to the workspace of the selected CVE
    case_root = vul4py_root / "workspaces" / case_id

    # Creates the path to the vulnerable version of that CVE project
    vulnerable_root = case_root / "vulnerable"

    # Creates the path to the meta.json file of the selected CVE
    meta_path = case_root / "meta.json"


    # Verifies that meta.json exists
    # If it does not exist, the selected CVE is not available in this workspace
    if not meta_path.exists():
        print(f"Case not found: {case_id}")
        sys.exit(1)


    # Opens meta.json in read mode
    with open(meta_path, "r") as file:

        # Converts the JSON content into a Python dictionary
        metadata = json.load(file)


    # Reads the "new_code_files" list from meta.json
    # This tells the script which source files must be collected for this case
    source_files = metadata.get("new_code_files", [])


    # Stops the program if meta.json does not provide any source files
    if not source_files:
        print("No vulnerable source files were found in meta.json")
        sys.exit(1)


    # Creates an empty list where the source code will be stored
    source_parts = []


    # Goes through every source file listed in meta.json
    for relative_path in source_files:

        # Combines the vulnerable project path with the file's relative path
        # to obtain the complete location of that source file
        source_path = vulnerable_root / relative_path


        # Continues only if that source file really exists
        if source_path.exists():

            # Reads all the Python code from that source file as text
            source_code = source_path.read_text()


            # Adds the file name and its source code to source_parts
            # The code is formatted as a Python code block for the model
            source_parts.append(
                f"\nFILE: {relative_path}\n"
                f"```python\n{source_code}\n```\n"
            )


    # Joins all collected source files into one single text
    complete_source = "\n".join(source_parts)


    # Builds the final message sent to OpenAI:
    # official repair instructions + source code from the vulnerable case
    prompt = OFFICIAL_PROMPT + "\nSOURCE CODE:\n" + complete_source


    # Defines where this CVE's model results will be saved
    output_dir = vul4py_root / "runs" / "student" / case_id

    # Creates the result folder if it does not already exist
    output_dir.mkdir(parents=True, exist_ok=True)


    # Creates the OpenAI client
    client = OpenAI(

        # Reads the API key from the OPENAI_API_KEY environment variable
        # The key is not written directly inside the Python code
        api_key=os.environ.get("OPENAI_API_KEY")
    )


    try:

        # Records the time immediately before sending the API request
        start = time.perf_counter()


        # Sends the final prompt to the selected OpenAI model
        # and waits for the model response
        response = client.responses.create(

            # Specifies which OpenAI model will process the request
            model=MODEL,

            # Sends the instructions and vulnerable source code
            input=prompt
        )


        # Records the time immediately after the API response is received
        end = time.perf_counter()


        # Calculates the API request duration in milliseconds
        latency_ms = (end - start) * 1000


        # Extracts the text generated by the model from the API response
        response_text = response.output_text


        # Reads from the model response whether it claims the repair succeeded
        claimed_success = extract_claim(response_text)

        # Reads the confidence value reported by the model
        confidence = extract_confidence(response_text)

        # Extracts only the proposed code patch from the complete response
        patch = extract_patch(response_text)


        # Creates a Python dictionary with the information we want to save
        llm_result = {

            # Stores the CVE that was tested
            "case_id": case_id,

            # Stores the model used for the experiment
            "model": MODEL,

            # Stores whether the model says its repair was successful
            "claimed_success": claimed_success,

            # Stores how confident the model says it is
            "confidence": confidence,

            # Stores how long the API request and response took
            "latency_ms": latency_ms,

            # Records that the API call completed successfully
            "api_success": True,

            # There was no API error in this successful result
            "error": None,

            # Stores the complete original text returned by the model
            "raw_response": response_text
        }


        # Opens or creates llm_response.json inside this CVE's result folder
        with open(output_dir / "llm_response.json", "w") as file:

            # Saves llm_result in JSON format with indentation for readability
            json.dump(llm_result, file, indent=2)


        # Saves only the extracted patch in a separate patch.diff file
        (output_dir / "patch.diff").write_text(patch)


        # Prints the CVE that was processed
        print(f"Case: {case_id}")

        # Prints whether the model claims the repair succeeded
        print(f"Claimed success: {claimed_success}")

        # Prints the confidence reported by the model
        print(f"Confidence: {confidence}")

        # Prints the API request duration
        print(f"End-to-end API latency: {latency_ms:.2f} ms")

        # Prints the location of the saved JSON result
        print(f"Saved: {output_dir / 'llm_response.json'}")

        # Prints the location of the saved patch
        print(f"Saved: {output_dir / 'patch.diff'}")


    # If the OpenAI API request produces an error, execution comes here
    except Exception as error:

        # Prints the API error instead of stopping with an unhandled exception
        print(f"API request failed: {error}")


# Checks if this Python file was executed directly
# If yes, it starts the main function
if __name__ == "__main__":
    main()
