from __future__ import annotations

from pathlib import Path
from typing import Any
import zlib

from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.verification.evidence import VerificationEvidence
from sunpack.verification.methods._archive_output_match import (
    coverage_details,
    coverage_from_archive_and_output,
)
from sunpack.verification.registry import register_verification_method
from sunpack.verification.result import (
    DECISION_ACCEPT,
    DECISION_ACCEPT_PARTIAL,
    DECISION_REPAIR,
    SOURCE_INTEGRITY_COMPLETE,
    SOURCE_INTEGRITY_DAMAGED,
    VerificationIssue,
    VerificationStepResult,
)


@register_verification_method("oracle_expected_output_match")
class OracleExpectedOutputMatchMethod:
    name = "oracle_expected_output_match"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        expected = _expected_files(evidence)
        if not expected:
            return VerificationStepResult(method=self.name, status="skipped")
        output_files = _output_files(evidence.output_dir)
        coverage = coverage_from_archive_and_output(expected, output_files, method=self.name)
        details = coverage_details(coverage)
        status = "passed" if coverage.failed_files == 0 and coverage.missing_files == 0 and coverage.partial_files == 0 else "warning"
        decision = DECISION_ACCEPT if coverage.completeness >= 0.999 else DECISION_ACCEPT_PARTIAL if coverage.completeness > 0 else DECISION_REPAIR
        issue = VerificationIssue(
            method=self.name,
            code="info.oracle_expected_output_coverage",
            message="Training oracle expected files were matched against extraction output",
            path=evidence.output_dir,
            expected=len(expected),
            actual={"coverage": details, "oracle_strength": knowledge_view.get(evidence.task, "verification.oracle.oracle_strength", "")},
        )
        return VerificationStepResult(
            method=self.name,
            status=status,
            issues=[issue],
            completeness_hint=coverage.completeness,
            source_integrity_hint=SOURCE_INTEGRITY_COMPLETE if coverage.completeness >= 0.999 else SOURCE_INTEGRITY_DAMAGED,
            decision_hint=decision,
            file_observations=coverage.observations,
        )


def _expected_files(evidence: VerificationEvidence) -> list[dict[str, Any]]:
    payload = knowledge_view.get(evidence.task, "verification.oracle.expected_files", {})
    if isinstance(payload, dict):
        return [_expected_item(item, name) for name, item in payload.items() if isinstance(item, dict)]
    if isinstance(payload, list):
        return [_expected_item(item, "") for item in payload if isinstance(item, dict)]
    return []


def _expected_item(item: dict[str, Any], fallback_name: str) -> dict[str, Any]:
    name = str(item.get("name") or item.get("path") or fallback_name or "")
    return {
        "name": name,
        "path": name,
        "size": item.get("size", item.get("unpacked_size")),
        "crc32": item.get("crc32", item.get("crc")),
        "has_crc": item.get("crc32", item.get("crc")) is not None,
    }


def _output_files(output_dir: str) -> list[dict[str, Any]]:
    root = Path(output_dir)
    if not root.is_dir():
        return []
    output: list[dict[str, Any]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root).as_posix()
            if rel.startswith(".sunpack/"):
                continue
            output.append({"path": rel, "size": int(path.stat().st_size), "crc32": _crc32(path)})
        except OSError:
            continue
    return output


def _crc32(path: Path, *, chunk_size: int = 1024 * 1024) -> int:
    checksum = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            checksum = zlib.crc32(chunk, checksum)
    return checksum & 0xFFFFFFFF
