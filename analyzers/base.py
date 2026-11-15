from pathlib import Path
from typing import Protocol, Optional, runtime_checkable
from models import AnalyzerResult


@runtime_checkable
class Analyzer(Protocol):
    name: str

    def run(
        self,
        original_dir: Path,
        candidate_dir: Optional[Path]
    ) -> AnalyzerResult:
        ...
