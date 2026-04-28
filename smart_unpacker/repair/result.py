from dataclasses import dataclass, field
from typing import Any, Literal

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor


RepairStatus = Literal[
    "repaired",
    "partial",
    "unrepairable",
    "unsupported",
    "needs_password",
    "skipped",
    "error",
]


@dataclass(frozen=True)
class RepairResult:
    status: RepairStatus
    confidence: float = 0.0
    format: str = ""
    repaired_input: dict[str, Any] | None = None
    actions: list[str] = field(default_factory=list)
    damage_flags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    workspace_paths: list[str] = field(default_factory=list)
    partial: bool = False
    module_name: str = ""
    diagnosis: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    repaired_descriptor: ArchiveInputDescriptor | None = None

    @property
    def ok(self) -> bool:
        return self.status in {"repaired", "partial"} and self.repaired_input is not None

    def archive_input(self, *, archive_path: str = "", part_paths: list[str] | None = None) -> ArchiveInputDescriptor | None:
        if self.repaired_descriptor is not None:
            return self.repaired_descriptor
        if not isinstance(self.repaired_input, dict):
            return None
        return ArchiveInputDescriptor.from_any(
            self.repaired_input,
            archive_path=archive_path,
            part_paths=part_paths,
            format_hint=self.format,
        )
