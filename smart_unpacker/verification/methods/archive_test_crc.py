import os
import unicodedata
from typing import Any

from smart_unpacker.support.sevenzip_native import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_DAMAGED,
    STATUS_OK,
    STATUS_UNSUPPORTED,
    STATUS_WRONG_PASSWORD,
    cached_read_archive_crc_manifest,
)
from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.registry import register_verification_method
from smart_unpacker.verification.result import VerificationIssue, VerificationStepResult

try:
    from smart_unpacker_native import compute_directory_crc_manifest as _compute_directory_crc_manifest
except Exception:  # pragma: no cover - depends on optional native build availability
    _compute_directory_crc_manifest = None


@register_verification_method("archive_test_crc")
class ArchiveTestCrcMethod:
    name = "archive_test_crc"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        max_items = max(0, int(config.get("max_items", 200000) or 0))
        try:
            archive_manifest = cached_read_archive_crc_manifest(
                evidence.archive_path,
                password=evidence.password or "",
                part_paths=evidence.archive_parts or [evidence.archive_path],
                max_items=max_items,
            )
        except Exception as exc:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.archive_crc_backend_unavailable",
                    message=f"Archive CRC backend is unavailable: {exc}",
                    path=evidence.archive_path,
                )],
            )

        archive_status_result = self._archive_status_result(archive_manifest, evidence)
        if archive_status_result is not None:
            return archive_status_result

        archive_files = [
            item for item in archive_manifest.files
            if isinstance(item, dict) and bool(item.get("has_crc", False))
        ]
        if not archive_files:
            return VerificationStepResult(method=self.name, status="skipped")
        if _compute_directory_crc_manifest is None:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.output_crc_backend_unavailable",
                    message="Rust output CRC backend is unavailable",
                    path=evidence.output_dir,
                )],
            )

        try:
            output_manifest = _compute_directory_crc_manifest(evidence.output_dir, max_items)
        except Exception as exc:
            return VerificationStepResult(
                method=self.name,
                status="skipped",
                issues=[VerificationIssue(
                    method=self.name,
                    code="warning.output_crc_backend_error",
                    message=f"Output CRC backend failed: {exc}",
                    path=evidence.output_dir,
                )],
            )

        status = str(output_manifest.get("status") or "")
        if status != "ok":
            return VerificationStepResult(method=self.name, status="skipped")

        output_by_path, output_by_name = _index_output_files(output_manifest.get("files") or [])
        mismatches = []
        missing = []
        checked = 0
        for item in archive_files:
            expected_path = _clean_path(item.get("path"))
            output_item = output_by_path.get(_normalize_path(expected_path))
            if output_item is None:
                output_item = output_by_name.get(_normalize_name(os.path.basename(expected_path)))
            if output_item is None:
                missing.append(expected_path)
                continue
            checked += 1
            expected_crc = _as_u32(item.get("crc32"))
            actual_crc = _as_u32(output_item.get("crc32"))
            if expected_crc != actual_crc:
                mismatches.append({
                    "path": expected_path,
                    "expected_crc32": expected_crc,
                    "actual_crc32": actual_crc,
                })

        issues: list[VerificationIssue] = []
        score_delta = 0
        if mismatches:
            score_delta -= abs(int(config.get("crc_mismatch_penalty", 100) or 100))
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.archive_crc_mismatch",
                message="Output file CRC does not match archive manifest CRC",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=mismatches[: int(config.get("max_reported_items", 20) or 20)],
            ))
        if missing:
            score_delta -= abs(int(config.get("missing_crc_file_penalty", 60) or 60))
            issues.append(VerificationIssue(
                method=self.name,
                code="fail.archive_crc_file_missing",
                message="Some archive CRC entries were not found in extraction output",
                path=evidence.output_dir,
                expected=len(archive_files),
                actual=missing[: int(config.get("max_reported_items", 20) or 20)],
            ))

        if not issues:
            return VerificationStepResult(method=self.name, status="passed")
        return VerificationStepResult(
            method=self.name,
            status="failed",
            score_delta=score_delta,
            issues=issues,
            hard_fail=bool(config.get("hard_fail_on_crc_mismatch", True) and mismatches),
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
                    code="warning.archive_crc_unsupported",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                )],
            )
        if archive_manifest.status == STATUS_WRONG_PASSWORD:
            return VerificationStepResult(
                method=self.name,
                status="failed",
                score_delta=-100,
                hard_fail=True,
                issues=[VerificationIssue(
                    method=self.name,
                    code="fail.archive_crc_wrong_password",
                    message=archive_manifest.message,
                    path=evidence.archive_path,
                )],
            )
        if archive_manifest.status == STATUS_DAMAGED or archive_manifest.checksum_error or archive_manifest.damaged:
            return VerificationStepResult(
                method=self.name,
                status="failed",
                score_delta=-100,
                hard_fail=True,
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


def _index_output_files(files: list[dict]) -> tuple[dict[str, dict], dict[str, dict]]:
    by_path = {}
    by_name = {}
    duplicate_names = set()
    for item in files:
        if not isinstance(item, dict):
            continue
        path = _clean_path(item.get("path"))
        by_path[_normalize_path(path)] = item
        name = _normalize_name(os.path.basename(path))
        if name in by_name:
            duplicate_names.add(name)
        else:
            by_name[name] = item
    for name in duplicate_names:
        by_name.pop(name, None)
    return by_path, by_name


def _clean_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip().strip("/")
    parts = [part for part in text.split("/") if part not in {"", ".", ".."}]
    return "/".join(parts)


def _normalize_path(value: str) -> str:
    return "/".join(
        _normalize_name(part)
        for part in _clean_path(value).split("/")
        if part
    )


def _normalize_name(value: str) -> str:
    return unicodedata.normalize("NFC", str(value or "")).casefold()


def _as_u32(value: Any) -> int:
    try:
        return int(value or 0) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return 0
