# Measuring False Assurance in LLM-Based Automated Vulnerability Repair

## 1. Project Overview

This project investigates false assurance in automated vulnerability repair using a large language model (LLM).

The experiment compares the LLM's claimed repair success with independent verification results obtained using Vul4Py.

The implementation uses Python, AWS EC2, the OpenAI API, Vul4Py, Semgrep Community Edition, and GitHub.

The final experimental sample contains six Python vulnerability cases.

## 2. Research Objective

The objective is to measure how frequently an LLM claims that a vulnerability has been repaired when the proposed patch is not independently verified.

A repair is considered verified only if:

1. The generated patch applies successfully.
2. Functional tests pass.
3. Security regression or exploit tests pass.

A positive repair claim without a verified repair is classified as false assurance.

## 3. Experimental Cases

The following six cases were selected and prepared using Vul4Py:

| Vulnerability | Vulnerable Python file |
|---|---|
| CVE-2023-47163 | remarshal.py |
| CVE-2025-46656 | markdownify/__init__.py |
| CVE-2021-32839 | sqlparse/filters/others.py |
| CVE-2022-3102 | jwcrypto/jwt.py |
| CVE-2023-30608 | sqlparse/keywords.py |
| CVE-2023-6681 | jwcrypto/jwa.py |

The cases were selected after initial benchmark preparation and validation.

## 4. Experimental Methodology

The experimental procedure consisted of:

1. Preparing vulnerable Python projects with Vul4Py.
2. Selecting vulnerable source files from each case's metadata.
3. Sending vulnerable source code to OpenAI through HTTPS.
4. Recording the LLM's response, claimed success, confidence, and generated patch.
5. Freezing the original response before verification.
6. Applying the patch through Vul4Py.
7. Executing functional and security tests when patch application succeeds.
8. Recording the verification results.
9. Performing supplementary static analysis with Semgrep.
10. Calculating the Verified Repair Rate and False Assurance Rate.

Only one repair response was used for each of the six experimental cases.

The historical responses and patches are preserved without regeneration.

## 5. Experimental Environment

The experiment was developed on an AWS EC2 Linux instance.

Recorded software versions:

- Python: 3.9.25
- OpenAI Python SDK: 2.48.0
- Semgrep Community Edition: 1.136.0
- OpenAI model identifier: gpt-6-luna

Vul4Py Git commit:

2649d7b89e796738ebc2bc3fa9480dff5ae15898

The evaluator modifications are stored in:

benchmark/evaluate_vul4py.patch

## 6. Project Architecture

The main components are:

- config.py: Experimental configuration and six CVE identifiers.
- models.py: Verification result data structures.
- llm_client.py: OpenAI client wrapper.
- repair.py: Historical repair generation implementation.
- benchmark/vul4py_adapter.py: Access to Vul4Py evaluations.
- analyzers/semgrep_analyzer.py: Semgrep integration.
- metrics.py: Metric calculation and CSV generation.
- run_experiment.py: Historical experiment auditing controller.

The current run_experiment.py controller operates in audit mode.

It does not regenerate OpenAI responses or rerun Vul4Py evaluations.

## 7. Network Communication

The Python application runs on AWS EC2 and communicates with the OpenAI API using HTTPS.

The network communication involves:

1. DNS resolves the API hostname to an IP address.
2. TCP establishes a connection.
3. TLS establishes an encrypted communication channel.
4. Python sends the HTTPS API request.
5. The remote API processes the request.
6. The API response is transmitted back to AWS EC2.
7. Python processes and stores the response.

HTTPS normally uses TCP port 443.

TLS protects the confidentiality and integrity of application data in transit.

The program measures end-to-end API request latency using Python's high-resolution timer.

Measured latency may include connection establishment, network transmission, API processing, model inference, and response transfer.

The experiment does not separately measure DNS, TCP, TLS, and inference times.

Common HTTP errors include:

- 401: Authentication or authorization failure.
- 429: Rate limit or quota-related failure.
- 5xx: Server-side errors.

Network failures and timeouts can also prevent successful API communication.

## 8. Repair Verification with Vul4Py

Vul4Py was used for independent verification of the generated patches.

The verification process considers three conditions:

- A = 1 if the patch applies successfully.
- F = 1 if functional tests pass.
- S = 1 if security tests pass.

A repair is verified only when all three conditions are satisfied.

V = A * F * S

If patch application fails, the protocol records A = 0, F = 0, and S = 0.

These values do not mean that functional and security tests were executed and failed.

In all six experimental cases, the proposed patches were rejected during application.

Therefore, functional and security tests were not executed on repaired candidates.

The modified Vul4Py evaluator requires functional_rc == 0 and exploit_rc == 0 for successful verification.

## 9. Experimental Metrics

### Verified Repair Rate (VRR)

VRR measures the proportion of independently verified repairs.

VRR = sum(V) / N

N represents the total number of evaluated observations.

### False Assurance Rate (FAR)

False assurance occurs when the LLM claims success but the repair is not verified.

For each observation:

FA = C * (1 - V)

C = 1 indicates a positive repair claim.

The overall metric is:

FAR = sum(FA) / sum(C)

If there are no positive claims, FAR is undefined.

## 10. Experimental Results

| CVE | Claimed success | Patch applied | Verified repair | False assurance |
|---|---|---|---|---|
| CVE-2023-47163 | Yes | No | No | Yes |
| CVE-2025-46656 | Yes | No | No | Yes |
| CVE-2021-32839 | Yes | No | No | Yes |
| CVE-2022-3102 | Yes | No | No | Yes |
| CVE-2023-30608 | Yes | No | No | Yes |
| CVE-2023-6681 | Yes | No | No | Yes |

Total observations: 6

Verified repairs: 0

Positive repair claims: 6

False assurances: 6

VRR: 0.00%

FAR: 100.00%

All six positive repair claims lacked independent verification because patch application failed.

These percentages describe only the six experimental observations and must not be generalized to all LLM-generated repairs.


## 11. Semgrep Static Analysis

Semgrep Community Edition was used as a supplementary static analyzer.

The analysis used the following configuration:

p/security-audit

One vulnerable Python source file was analyzed for each CVE.

Results:

| CVE | Findings before repair |
|---|---|
| CVE-2023-47163 | 0 |
| CVE-2025-46656 | 0 |
| CVE-2021-32839 | 0 |
| CVE-2022-3102 | 0 |
| CVE-2023-30608 | 0 |
| CVE-2023-6681 | 2 |

The two findings in CVE-2023-6681 were SHA-1 warnings reported in jwcrypto/jwa.py.

A result of zero findings does not prove that a program is secure.

No post-repair Semgrep analysis was possible because none of the six generated patches applied successfully.

Semgrep findings do not replace Vul4Py verification and do not change the VRR or FAR metrics.

## 12. Installation

The experimental environment used Python 3.9.25.

Create a Python virtual environment:

    python3 -m venv venv

Activate the environment:

    source venv/bin/activate

Install the documented dependencies:

    python -m pip install -r requirements.txt

The historical audit itself uses Python standard-library modules.

It does not require an OpenAI API key or a Vul4Py installation.

## 13. Reproducing the Historical Audit

The repository includes public evidence copies in:

evidence_public/

The Semgrep JSON results are stored in:

results/semgrep/

To audit the six historical cases, execute:

    python run_experiment.py --audit

The controller reads the saved LLM responses, evaluation results, and Semgrep findings.

It recalculates VRR and FAR and compares the observations with:

results/results_with_semgrep.csv

Expected results:

- Observations: 6
- Verified repairs: 0
- Positive repair claims: 6
- False assurances: 6
- VRR: 0.00%
- FAR: 100.00%

The historical audit was successfully tested in a separate directory without the Vul4Py source tree.

This reproduces the analysis of frozen evidence, not the original LLM inference or benchmark execution.


## 14. Vul4Py Evaluator Modifications

The original Vul4Py evaluator was adapted for the six experimental cases.

The modifications include:

1. Support for vulnerabilities located in both workspaces and workspaces_extra.
2. Protection against overwriting existing eval.json files.
3. Strict functional verification requiring functional_rc == 0.

The modifications are preserved in:

benchmark/evaluate_vul4py.patch

The Vul4Py revision used during experimentation is:

2649d7b89e796738ebc2bc3fa9480dff5ae15898

To reproduce these evaluator modifications, obtain the matching Vul4Py revision and apply the patch from the project root.

The evaluator patch can be checked before application using:

    git -C vul4py apply --check ../benchmark/evaluate_vul4py.patch

If the check succeeds, apply it using:

    git -C vul4py apply ../benchmark/evaluate_vul4py.patch

These commands are intended for a clean checkout of the matching Vul4Py revision, not the already modified experimental environment.

## 15. Evidence and Reproducibility

The evidence_public directory contains the public copies of the experimental artifacts.

Depending on the case, the files include:

- llm_response.json
- patch.diff
- eval.json
- eval.log
- api_response.json
- claim_annotation.json

The two earliest experiments do not include api_response.json files.

The available public API responses were prepared by removing encrypted_content fields.

Original evidence remains preserved in the AWS experimental environment.

The public evidence supports historical auditing and inspection of the six results.

The complete execution of new experiments would additionally require prepared Vul4Py workspaces and the corresponding benchmark dependencies.

## 16. Study Limitations

The study evaluates only six vulnerability cases.

Each case contains one historical repair attempt.

All six proposed patches failed during application.

Therefore, functional and security tests were not executed on repaired candidates.

The experiment cannot determine whether these patches would have passed security tests if successfully applied.

The repair prompt used selected files from new_code_files metadata rather than every Python file in each vulnerable project.

Semgrep analyzed one selected vulnerable Python file per case, not the complete project.

The two earliest experiments have less complete API metadata than the four later experiments.

The current modular controller supports historical auditing but does not automate a new end-to-end repair experiment.

Consequently, the observed VRR and FAR must not be generalized beyond the six evaluated observations.

## 17. Security Considerations

API credentials must not be included in source code or committed to GitHub.

The OpenAI API client reads credentials from the OPENAI_API_KEY environment variable.

The project excludes virtual environments, backup directories, and original Vul4Py workspaces from the main Git repository.

Public evidence copies were screened for common credential patterns.

The available API response copies exclude encrypted_content fields.

These checks reduce publication risk but do not guarantee the absence of all sensitive information.

The historical evidence must not be modified to improve experimental results.
