# LLM-Based Vulnerability Repair

## Project Overview

This project uses AWS EC2, the OpenAI API, Vul4Py, and GitHub to evaluate whether an LLM can repair vulnerable Python code.

The workflow is:

1. Prepare vulnerable cases with Vul4Py.
2. Validate the cases using the Vul4Py scan.
3. Send vulnerable Python source code to the OpenAI API.
4. Save the LLM response, confidence, and generated patch.
5. Freeze the response before verification.
6. Use Vul4Py to evaluate whether the patch can be applied and whether the vulnerability is repaired.
7. Store the experimental results in results.csv.
8. Calculate the Verified Repair Rate (VRR) and False Assurance Rate (FAR).

## Installation

Create and activate a Python virtual environment:

python3 -m venv venv
source venv/bin/activate

Install the required packages:

pip install openai semgrep pytest

Clone Vul4Py:

git clone https://github.com/tabudz/vul4py.git

## OpenAI API Configuration

The OpenAI API key is configured as an environment variable:

export OPENAI_API_KEY="YOUR_KEY"

The API key is not stored inside the Python source code and must not be uploaded to GitHub.

The repair.py program reads the vulnerable source code, sends it to the OpenAI API using GPT-6 Luna, measures end-to-end API latency, and saves:

- claimed_success
- confidence
- llm_response.json
- patch.diff

## Vul4Py Verification

Five prepared Vul4Py cases were initially selected for the MVP.

After running the Vul4Py scan, only two cases were reported as valid (OK):

- CVE-2023-47163
- CVE-2025-46656

The remaining cases were not used because Vul4Py reported:

- CVE-2017-16615: NON_ORACLE
- CVE-2019-10800: UNEXPECTED
- CVE-2024-34078: UNEXPECTED

For the two valid cases, the LLM generated a patch and claimed that the vulnerability had been successfully repaired.

However, Vul4Py reported that the generated patches could not be applied.

For both cases:

patch_applied = False
verified_repair = False
false_assurance = True

## Preliminary Results

Cases evaluated: 2

Verified repairs: 0

False assurances: 2

VRR: 0.00%

FAR: 100.00%

None of the evaluated repairs were independently verified.

In both cases, the LLM claimed that the vulnerability had been repaired, but Vul4Py showed that the generated patch could not be applied. Therefore, both cases were classified as false assurance.

## Network Communication

The Python application runs on AWS EC2 and communicates with the OpenAI API through HTTPS.

First, DNS resolves the API hostname to an IP address. TCP then establishes the connection, and TLS creates an encrypted communication channel. The application sends an HTTPS request to the OpenAI API and receives the LLM response.

The latency recorded in the experiment is end-to-end API latency. It may include DNS resolution, TCP connection establishment, TLS processing, Internet transmission, API processing, LLM inference, and response transmission.

## How to Run

Activate the virtual environment:

source venv/bin/activate

Configure the API key:

export OPENAI_API_KEY="YOUR_KEY"

Run the valid cases:

python3 repair.py CVE-2023-47163
python3 repair.py CVE-2025-46656

Generate the results and metrics:

python3 metrics.py

The experimental results are stored in:

results/results.csv
