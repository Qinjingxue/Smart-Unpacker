from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from packrelic.repair.job import RepairJob


@dataclass(frozen=True)
class CoverageFile:
    archive_path: str = ""
    output_path: str = ""
    state: str = "unverified"
    bytes_written: int = 0
    expected_size: int | None = None
    progress: float | None = None
    crc_ok: bool | None = None
    method: str = ""
    message: str = ""

    @property
    def effective_name(self) -> str:
        return self.archive_path or self.output_path


@dataclass(frozen=True)
class ArchiveCoverageView:
    completeness: float = 1.0
    file_coverage: float = 1.0
    byte_coverage: float = 1.0
    expected_files: int = 0
    matched_files: int = 0
    complete_files: int = 0
    partial_files: int = 0
    failed_files: int = 0
    missing_files: int = 0
    unverified_files: int = 0
    expected_bytes: int = 0
    matched_bytes: int = 0
    complete_bytes: int = 0
    confidence: float = 0.0
    files: tuple[CoverageFile, ...] = field(default_factory=tuple)

    @property
    def known(self) -> bool:
        return bool(self.expected_files or self.matched_files or self.files or self.confidence > 0.0)

    @property
    def has_missing_entries(self) -> bool:
        return self.missing_files > 0 or any(item.state == "missing" for item in self.files)

    @property
    def has_payload_damage(self) -> bool:
        return self.failed_files > 0 or self.partial_files > 0 or any(item.state in {"failed", "partial"} for item in self.files)

    @property
    def has_recovered_output(self) -> bool:
        return self.matched_files > 0 or any(item.state in {"complete", "partial", "unverified"} for item in self.files)

    @property
    def directory_only_suspected(self) -> bool:
        return self.has_missing_entries and not self.has_payload_damage

    @property
    def payload_only_suspected(self) -> bool:
        return self.has_payload_damage and not self.has_missing_entries

    @property
    def mixed_damage_suspected(self) -> bool:
        return self.has_missing_entries and self.has_payload_damage

    @property
    def low_yield_partial(self) -> bool:
        return self.known and self.completeness < 0.35

    @property
    def failed_names(self) -> tuple[str, ...]:
        return tuple(item.effective_name for item in self.files if item.state == "failed" and item.effective_name)

    @property
    def partial_names(self) -> tuple[str, ...]:
        return tuple(item.effective_name for item in self.files if item.state == "partial" and item.effective_name)

    @property
    def missing_names(self) -> tuple[str, ...]:
        return tuple(item.effective_name for item in self.files if item.state == "missing" and item.effective_name)

    def score_hint(self, *, directory: float = 0.0, payload: float = 0.0, mixed: float = 0.0, partial: float = 0.0) -> float:
        if not self.known:
            return 0.0
        score = 0.0
        if self.directory_only_suspected:
            score += directory
        if self.payload_only_suspected:
            score += payload
        if self.mixed_damage_suspected:
            score += mixed
        if self.has_recovered_output:
            score += partial
        return max(-1.0, min(1.0, score))

    def as_dict(self) -> dict[str, Any]:
        return {
            "completeness": self.completeness,
            "file_coverage": self.file_coverage,
            "byte_coverage": self.byte_coverage,
            "expected_files": self.expected_files,
            "matched_files": self.matched_files,
            "complete_files": self.complete_files,
            "partial_files": self.partial_files,
            "failed_files": self.failed_files,
            "missing_files": self.missing_files,
            "unverified_files": self.unverified_files,
            "expected_bytes": self.expected_bytes,
            "matched_bytes": self.matched_bytes,
            "complete_bytes": self.complete_bytes,
            "confidence": self.confidence,
            "files": [item.__dict__ for item in self.files],
        }


def coverage_view_from_job(job: RepairJob) -> ArchiveCoverageView:
    failure = job.extraction_failure if isinstance(job.extraction_failure, dict) else {}
    coverage = failure.get("archive_coverage") if isinstance(failure.get("archive_coverage"), dict) else {}
    observations = failure.get("file_observations") if isinstance(failure.get("file_observations"), list) else []
    return coverage_view_from_payload(coverage, observations)


def coverage_view_from_payload(coverage: dict[str, Any] | None, observations: list[Any] | None = None) -> ArchiveCoverageView:
    raw = coverage if isinstance(coverage, dict) else {}
    files = tuple(_coverage_file(item) for item in observations or [] if isinstance(item, dict))
    return ArchiveCoverageView(
        completeness=_float(raw.get("completeness"), 1.0),
        file_coverage=_float(raw.get("file_coverage"), 1.0),
        byte_coverage=_float(raw.get("byte_coverage"), 1.0),
        expected_files=_int(raw.get("expected_files")),
        matched_files=_int(raw.get("matched_files")),
        complete_files=_int(raw.get("complete_files")),
        partial_files=_int(raw.get("partial_files")),
        failed_files=_int(raw.get("failed_files")),
        missing_files=_int(raw.get("missing_files")),
        unverified_files=_int(raw.get("unverified_files")),
        expected_bytes=_int(raw.get("expected_bytes")),
        matched_bytes=_int(raw.get("matched_bytes")),
        complete_bytes=_int(raw.get("complete_bytes")),
        confidence=_float(raw.get("confidence"), 0.0),
        files=files,
    )


def _coverage_file(raw: dict[str, Any]) -> CoverageFile:
    return CoverageFile(
        archive_path=str(raw.get("archive_path") or ""),
        output_path=str(raw.get("path") or raw.get("output_path") or ""),
        state=str(raw.get("state") or raw.get("status") or "unverified"),
        bytes_written=_int(raw.get("bytes_written")),
        expected_size=_optional_int(raw.get("expected_size")),
        progress=_optional_float(raw.get("progress")),
        crc_ok=raw.get("crc_ok") if isinstance(raw.get("crc_ok"), bool) else None,
        method=str(raw.get("method") or ""),
        message=str(raw.get("message") or ""),
    )


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
