from dataclasses import dataclass
from typing import Protocol

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.result import RepairResult


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
