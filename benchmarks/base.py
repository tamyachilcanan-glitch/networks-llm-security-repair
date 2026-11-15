from pathlib import Path
from typing import Protocol, List, runtime_checkable
from models import EvaluationResult


@runtime_checkable
class BenchmarkAdapter(Protocol):
    def valid_cases(self) -> List[str]:
        ...

    def vulnerable_dir(self, case_id: str) -> Path:
        ...

    def apply_patch(
        self, case_id: str, patch: str
    ) -> EvaluationResult:
        ...

    def evaluate(
        self, case_id: str, candidate_dir: Path
    ) -> EvaluationResult:
        ...
