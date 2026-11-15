import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VUL4PY_ROOT = ROOT / "vul4py"
RUNS_ROOT = VUL4PY_ROOT / "runs" / "student"


class Vul4PyAdapter:
    def __init__(self):
        self.root = VUL4PY_ROOT
        self.runs = RUNS_ROOT

    def find_case(self, case_id):
        for workspace in ("workspaces", "workspaces_extra"):
            folder = self.root / workspace / case_id

            if (folder / "meta.json").is_file():
                return folder

        raise FileNotFoundError(
            f"No se encontro el caso: {case_id}"
        )

    def load_evaluation(self, case_id):
        path = self.runs / case_id / "eval.json"

        if not path.is_file():
            raise FileNotFoundError(
                f"No existe evaluacion: {case_id}"
            )

        with path.open(encoding="utf-8") as file:
            data = json.load(file)

        if type(data.get("apply_ok")) is not bool:
            raise ValueError(
                f"{case_id}: apply_ok invalido"
            )

        return data

    def get_verification(self, case_id):
        evaluation = self.load_evaluation(case_id)

        applied = evaluation["apply_ok"]
        functional_rc = evaluation.get("functional_rc")
        exploit_rc = evaluation.get("exploit_rc")

        if not applied and (
            functional_rc is not None
            or exploit_rc is not None
        ):
            raise ValueError(
                f"{case_id}: pruebas registradas sin aplicar parche"
            )

        A = int(applied)
        F = int(applied and functional_rc == 0)
        S = int(applied and exploit_rc == 0)

        return {
            "case_id": case_id,
            "patch_applied": A,
            "functional_test_pass": F,
            "security_test_pass": S,
            "functional_test_executed": (
                functional_rc is not None
            ),
            "security_test_executed": (
                exploit_rc is not None
            ),
            "verified_repair": A * F * S,
        }

def prepare_evaluation(case_id, runs_root, workspaces_root, agent="student"):
    """Prepara una evaluacion sobre directorios aislados."""
    import config

    config.validate_case(case_id)

    if agent != "student":
        raise ValueError("Agente no autorizado")

    runs_root = Path(runs_root).resolve()
    workspaces_root = Path(workspaces_root).resolve()
    protected_root = config.VUL4PY_ROOT.resolve()
    project_root = config.PROJECT_ROOT.resolve()

    def inside(path, parent):
        return path == parent or parent in path.parents

    for directory in (runs_root, workspaces_root):
        if inside(directory, project_root):
            raise PermissionError(
                "Los directorios de prueba deben estar fuera del proyecto"
            )

    if runs_root == workspaces_root:
        raise ValueError("Los directorios deben ser diferentes")

    case_workspace = workspaces_root / case_id
    case_run = runs_root / agent / case_id

    if not (case_workspace / "meta.json").is_file():
        raise FileNotFoundError(case_workspace / "meta.json")

    if not (case_workspace / "vulnerable").is_dir():
        raise FileNotFoundError(case_workspace / "vulnerable")

    if not (case_run / "patch.diff").is_file():
        raise FileNotFoundError(case_run / "patch.diff")

    if (case_run / "eval.json").exists():
        raise FileExistsError(case_run / "eval.json")

    evaluator = protected_root / "scripts" / "evaluate.py"

    if not evaluator.is_file():
        raise FileNotFoundError(evaluator)

    return [
        "python3",
        str(evaluator),
        "--agent",
        agent,
        "--vuln-id",
        case_id,
        "--workspaces",
        str(workspaces_root),
        "--strict-workspaces",
        "--runs",
        str(runs_root),
    ]


def execute_evaluation(case_id, runs_root, workspaces_root, keep_candidate=False):
    """Ejecuta Vul4Py sobre espacios aislados."""
    import subprocess
    import sys

    command = prepare_evaluation(
        case_id,
        runs_root,
        workspaces_root
    )

    command[0] = sys.executable

    if type(keep_candidate) is not bool:
        raise ValueError("keep_candidate debe ser booleano")

    if keep_candidate:
        command.append("--keep-candidate")

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=1800,
        check=False
    )

    if completed.returncode != 0:
        raise RuntimeError(
            "Vul4Py fallo durante la ejecucion: "
            + completed.stderr[-2000:]
        )

    eval_path = (
        Path(runs_root).resolve()
        / "student"
        / case_id
        / "eval.json"
    )

    if not eval_path.is_file():
        raise RuntimeError(
            "Vul4Py termino sin generar eval.json"
        )

    with eval_path.open(encoding="utf-8") as file:
        evaluation = json.load(file)

    if evaluation.get("vuln_id") != case_id:
        raise ValueError("Identificador de evaluacion incorrecto")

    if type(evaluation.get("apply_ok")) is not bool:
        raise ValueError("Estado de aplicacion invalido")

    return evaluation
