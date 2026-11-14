"""
Configuracion central del proyecto REDES.

Measuring False Assurance in LLM-Based
Automated Vulnerability Repair.

Muestra experimental: seis CVE.
"""

from pathlib import Path

# Directorios principales
PROJECT_ROOT = Path(__file__).resolve().parent
VUL4PY_ROOT = PROJECT_ROOT / "vul4py"

RUNS_ROOT = VUL4PY_ROOT / "runs" / "student"
RESULTS_ROOT = PROJECT_ROOT / "results"
SEMGREP_RESULTS = RESULTS_ROOT / "semgrep"

# Configuracion historica del experimento
MODEL = "gpt-6-luna"

CASES = (
    "CVE-2023-47163",
    "CVE-2025-46656",
    "CVE-2021-32839",
    "CVE-2022-3102",
    "CVE-2023-30608",
    "CVE-2023-6681",
)

# Configuracion de API utilizada
API_TIMEOUT_SECONDS = 120.0
API_MAX_RETRIES = 0

# Configuracion de Semgrep
SEMGREP_CONFIG = "p/security-audit"

# Archivos de resultados
FINAL_RESULTS = RESULTS_ROOT / "results_final.csv"
SEMGREP_RESULTS_CSV = RESULTS_ROOT / "results_with_semgrep.csv"

# No regenerar respuestas de los casos historicos.
PROTECT_EXISTING_ATTEMPTS = True


def validate_case(case_id):
    """Acepta solamente los seis casos seleccionados."""
    if case_id not in CASES:
        raise ValueError(
            f"CVE no autorizado en este experimento: {case_id}"
        )
    return case_id
