from dataclasses import dataclass, field
from typing import Any

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor
from smart_unpacker.contracts.archive_state import ArchiveState


@dataclass(frozen=True)
class RepairJob:
    source_input: dict[str, Any]
    format: str = ""
    confidence: float = 0.0
    analysis_evidence: Any = None
    analysis_prepass: dict[str, Any] = field(default_factory=dict)
    fuzzy_profile: dict[str, Any] = field(default_factory=dict)
    extraction_failure: dict[str, Any] | None = None
    extraction_diagnostics: dict[str, Any] = field(default_factory=dict)
    damage_flags: list[str] = field(default_factory=list)
    password: str | None = None
    archive_key: str = ""
    workspace: str = ""
    attempts: int = 0
    source_descriptor: ArchiveInputDescriptor | None = None
    archive_state: ArchiveState | None = None

    @property
    def has_extraction_failure(self) -> bool:
        return bool(self.extraction_failure)

    def archive_input(self) -> ArchiveInputDescriptor:
        if self.archive_state is not None:
            return self.archive_state.to_archive_input_descriptor()
        if self.source_descriptor is not None:
            return self.source_descriptor
        return ArchiveInputDescriptor.from_any(
            self.source_input,
            archive_path=str(self.source_input.get("path") or self.source_input.get("archive_path") or ""),
            part_paths=[
                str(item.get("path") or "")
                for item in self.source_input.get("ranges", [])
                if isinstance(item, dict) and item.get("path")
            ] or None,
            format_hint=str(self.source_input.get("format_hint") or self.source_input.get("format") or self.format or ""),
        )
