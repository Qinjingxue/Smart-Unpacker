from typing import Any

from packrelic.support.sevenzip_native import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_DAMAGED,
    STATUS_OK,
    STATUS_UNSUPPORTED,
    STATUS_WRONG_PASSWORD,
)
from packrelic.verification.archive_state_manifest import archive_state_manifest_for_evidence
from packrelic.verification.evidence import VerificationEvidence
from packrelic.verification.registry import register_verification_method
from packrelic.verification.result import (
    DECISION_REPAIR,
    FileVerificationObservation,
    SOURCE_INTEGRITY_COMPLETE,
    SOURCE_INTEGRITY_DAMAGED,
    SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
    VerificationIssue,
    VerificationStepResult,
)

from packrelic_native import match_archive_output_crc_coverage as _match_archive_output_crc_coverage


@register_verification_method("archive_test_crc")
class ArchiveTestCrcMethod:
    name = "archive_test_crc"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        max_items = max(0, int(config.get("max_items", 200000) or 0))
        archive_manifest = archive_state_manifest_for_evidence(evidence, max_items=max_items)

        archive_status_result = self._archive_status_result(archive_manifest, evidence)
        if archive_status_result is not None:
            return archive_status_result

        archive_files = [item for item in archive_manifest.files if isinstance(item, dict) and item.get("path")]
        if not archive_files:
            return VerificationStepResult(method=self.name, status="skipped")
        match_result = dict(_match_archive_output_crc_coverage(archive_files, evidence.output_dir, max_items))

        status = str(match_result.get("status") or "")
        if status != "ok":
            return VerificationStepResult(method=self.name, status="skipped")

        source_integrity = _manifest_source_integrity(archive_manifest)
        mismatches = list(match_result.get("mismatches") or [])
        missing = list(match_result.get("missing") or [])
        coverage = dict(match_result.get("coverage") or {})
        issue_by_path: dict[str, list[VerificationIssue]] = {}

        issues: list[VerificationIssue] = []
        if mismatches:
            issue = VerificationIssue(
                method=self.name,
                code="fail.archive_crc_mismatch",
                message="Output file CRC does not match archive manifest CRC",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=mismatches[: int(config.get("max_reported_items", 20) or 20)],
            )
            issues.append(issue)
            for item in mismatches:
                issue_by_path.setdefault(str(item.get("path") or ""), []).append(issue)
        if missing:
            issue = VerificationIssue(
                method=self.name,
                code="fail.archive_crc_file_missing",
                message="Some archive CRC entries were not found in extraction output",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=missing[: int(config.get("max_reported_items", 20) or 20)],
            )
            issues.append(issue)
            for path in missing:
                issue_by_path.setdefault(str(path), []).append(issue)

        observations = _native_observations(match_result.get("observations") or [], issue_by_path, self.name)
        completeness = _coverage_float(coverage, "completeness", 1.0)

        if not issues:
            return VerificationStepResult(
                method=self.name,
                status="passed",
                completeness_hint=completeness,
                source_integrity_hint=source_integrity,
                file_observations=observations,
                issues=[VerificationIssue(
                    method=self.name,
                    code="info.archive_output_coverage",
                    message="Archive-state files were matched against extraction output",
                    path=evidence.output_dir,
                    expected=int(coverage.get("expected_files", len(archive_files)) or 0),
                    actual=_coverage_actual(coverage, archive_manifest, evidence),
                )],
            )
        issues.append(VerificationIssue(
            method=self.name,
            code="info.archive_output_coverage",
            message="Archive-state files were matched against extraction output",
            path=evidence.output_dir,
            expected=int(coverage.get("expected_files", len(archive_files)) or 0),
            actual=_coverage_actual(coverage, archive_manifest, evidence),
        ))
        return VerificationStepResult(
            method=self.name,
            status="failed",
            issues=issues,
            completeness_hint=completeness,
            source_integrity_hint=source_integrity,
            recoverable_upper_bound_hint=completeness if source_integrity != SOURCE_INTEGRITY_COMPLETE else None,
            decision_hint=DECISION_REPAIR if source_integrity == SOURCE_INTEGRITY_COMPLETE else "none",
            file_observations=observations,
        )

    def _archive_status_result(self, archive_manifest, evidence: VerificationEvidence) -> VerificationStepResult | None:
        if archive_manifest.status == STATUS_OK and archive_manifest.ok:
            return None
        if archive_manifest.status in {STATUS_BACKEND_UNAVAILABLE, STATUS_UNSUPPORTED}:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.archive_crc_state_unsupported",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                    actual={
                        "state_aware": True,
                        "patch_digest": evidence.patch_digest,
                        "archive_type": getattr(archive_manifest, "archive_type", ""),
                    },
                )],
            )
        if archive_manifest.status == STATUS_WRONG_PASSWORD:
            return VerificationStepResult(
                method=self.name,
                status="failed",
                issues=[VerificationIssue(
                    method=self.name,
                    code="fail.archive_crc_wrong_password",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                )],
            )
        if (archive_manifest.status == STATUS_DAMAGED or archive_manifest.checksum_error or archive_manifest.damaged) and archive_manifest.files:
            return None
        if archive_manifest.status == STATUS_DAMAGED or archive_manifest.checksum_error or archive_manifest.damaged:
            return VerificationStepResult(
                method=self.name,
                status="failed",
                completeness_hint=None,
                source_integrity_hint=SOURCE_INTEGRITY_PAYLOAD_DAMAGED if archive_manifest.checksum_error else SOURCE_INTEGRITY_DAMAGED,
                decision_hint=DECISION_REPAIR,
                issues=[VerificationIssue(
                    method=self.name,
                    code="fail.archive_crc_test_failed",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                )],
            )
        return VerificationStepResult(
            method=self.name,
            status="skipped",
            issues=[VerificationIssue(
                method=self.name,
                code="warning.archive_crc_unknown_status",
                message=archive_manifest.message,
                path=evidence.archive_path,
                actual=archive_manifest.status,
            )],
        )


def _coverage_actual(coverage: dict[str, Any], archive_manifest, evidence: VerificationEvidence) -> dict[str, Any]:
    actual = {
        "completeness": round(_coverage_float(coverage, "completeness", 1.0), 6),
        "file_coverage": round(_coverage_float(coverage, "file_coverage", 1.0), 6),
        "byte_coverage": round(_coverage_float(coverage, "byte_coverage", 1.0), 6),
        "expected_files": int(coverage.get("expected_files", 0) or 0),
        "matched_files": int(coverage.get("matched_files", 0) or 0),
        "complete_files": int(coverage.get("complete_files", 0) or 0),
        "partial_files": int(coverage.get("partial_files", 0) or 0),
        "failed_files": int(coverage.get("failed_files", 0) or 0),
        "missing_files": int(coverage.get("missing_files", 0) or 0),
        "expected_bytes": int(coverage.get("expected_bytes", 0) or 0),
        "matched_bytes": int(coverage.get("matched_bytes", 0) or 0),
        "complete_bytes": int(coverage.get("complete_bytes", 0) or 0),
    }
    actual.update({
        "state_aware": True,
        "patch_digest": evidence.patch_digest,
        "archive_type": getattr(archive_manifest, "archive_type", ""),
        "source_integrity": _manifest_source_integrity(archive_manifest),
    })
    return actual


def _native_observations(
    raw_observations: list[Any],
    issues_by_path: dict[str, list[VerificationIssue]],
    method: str,
) -> list[FileVerificationObservation]:
    observations: list[FileVerificationObservation] = []
    for raw in raw_observations:
        if not isinstance(raw, dict):
            continue
        archive_path = str(raw.get("archive_path") or raw.get("path") or "")
        observations.append(FileVerificationObservation(
            path=str(raw.get("path") or archive_path),
            archive_path=archive_path,
            state=str(raw.get("state") or "unverified"),
            method=method,
            bytes_written=int(raw.get("bytes_written", 0) or 0),
            expected_size=_optional_int(raw.get("expected_size")),
            progress=_optional_float(raw.get("progress")),
            crc_expected=_optional_crc(raw.get("crc_expected")),
            crc_actual=_optional_crc(raw.get("crc_actual")),
            issues=list(issues_by_path.get(archive_path) or []),
            details=dict(raw.get("details") or {}),
        ))
    return observations


def _manifest_source_integrity(archive_manifest) -> str:
    if getattr(archive_manifest, "checksum_error", False):
        return SOURCE_INTEGRITY_PAYLOAD_DAMAGED
    if getattr(archive_manifest, "damaged", False) or getattr(archive_manifest, "status", STATUS_OK) == STATUS_DAMAGED:
        return SOURCE_INTEGRITY_DAMAGED
    return SOURCE_INTEGRITY_COMPLETE


def _coverage_float(coverage: dict[str, Any], key: str, default: float) -> float:
    try:
        return float(coverage.get(key, default))
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


def _optional_crc(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value or 0) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None
