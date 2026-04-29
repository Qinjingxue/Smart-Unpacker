from dataclasses import dataclass
from typing import Protocol

from packrelic.repair.diagnosis import RepairDiagnosis
from packrelic.repair.job import RepairJob
from packrelic.repair.result import RepairResult


@dataclass(frozen=True)
class RepairRoute:
    require_any_categories: tuple[str, ...] = ()
    require_any_flags: tuple[str, ...] = ()
    require_any_fuzzy_hints: tuple[str, ...] = ()
    require_any_failure_stages: tuple[str, ...] = ()
    require_any_failure_kinds: tuple[str, ...] = ()
    formats: tuple[str, ...] = ()
    reject_any_flags: tuple[str, ...] = ("wrong_password",)
    reject_any_failure_stages: tuple[str, ...] = ()
    reject_any_failure_kinds: tuple[str, ...] = (
        "process_start",
        "process_timeout",
        "process_stall",
        "process_exit",
        "process_signal",
        "process_io",
        "output_filesystem",
    )
    base_score: float = 0.5


@dataclass(frozen=True)
class RepairModuleSpec:
    name: str
    formats: tuple[str, ...]
    categories: tuple[str, ...] = ()
    stage: str = "targeted"
    safe: bool = True
    parallel_safe: bool = True
    partial: bool = False
    lossy: bool = False
    routes: tuple[RepairRoute, ...] = ()


class RepairModule(Protocol):
    spec: RepairModuleSpec

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        ...

    def repair(
        self,
        job: RepairJob,
        diagnosis: RepairDiagnosis,
        workspace: str,
        config: dict,
    ) -> RepairResult:
        ...
