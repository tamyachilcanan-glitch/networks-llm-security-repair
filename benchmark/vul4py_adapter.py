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
