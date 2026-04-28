from dataclasses import dataclass
from typing import Any, Protocol

from smart_unpacker.analysis.view import SharedBinaryView


@dataclass(frozen=True)
class FuzzyAnalysisModuleSpec:
    name: str
    provides: tuple[str, ...] = ()
    io_profile: str = "sampled"
    parallel_safe: bool = True


class FuzzyAnalysisModule(Protocol):
    spec: FuzzyAnalysisModuleSpec

    def analyze(self, view: SharedBinaryView, prepass: dict, config: dict) -> dict[str, Any]:
        ...
