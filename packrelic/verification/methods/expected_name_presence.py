import os
from typing import Any

from packrelic.support.sevenzip_native import STATUS_DAMAGED, STATUS_OK
from packrelic.verification.archive_state_manifest import ArchiveStateManifest, archive_state_manifest_for_evidence
from packrelic.verification.evidence import VerificationEvidence
from packrelic.verification.methods._archive_output_match import (
    archive_files_from_names,
    coverage_details,
    coverage_from_archive_and_output,
    output_files_from_directory,
)
from packrelic.verification.methods._output_stats import output_stats_for_evidence
from packrelic.verification.registry import register_verification_method
from packrelic.verification.result import (
    DECISION_NONE,
    DECISION_REPAIR,
    SOURCE_INTEGRITY_COMPLETE,
    SOURCE_INTEGRITY_DAMAGED,
    VerificationIssue,
    VerificationStepResult,
)
from packrelic.support.path_names import clean_relative_archive_path, normalize_match_name, normalize_match_path


NAME_FIELDS = (
    "expected_names",
    "manifest_names",
    "item_names",
    "file_names",
    "path_samples",
    "paths",
)


@register_verification_method("expected_name_presence")
class ExpectedNamePresenceMethod:
    name = "expected_name_presence"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        state_manifest = archive_state_manifest_for_evidence(
            evidence,
            max_items=max(1, int(config.get("max_expected_names", 50) or 50)),
        )
        expected_names = self._expected_names(evidence, config, state_manifest)
        if not expected_names:
            return VerificationStepResult(method=self.name, status="skipped")

        stats = output_stats_for_evidence(evidence)
        if not stats.exists or not stats.is_dir or not stats.relative_paths:
            return VerificationStepResult(method=self.name, status="skipped")

        output_paths = {normalize_match_path(path) for path in stats.relative_paths}
        output_basenames = {normalize_match_name(os.path.basename(path)) for path in stats.relative_paths}
        output_files = _output_files_for_coverage(evidence)
        coverage = coverage_from_archive_and_output(
            archive_files_from_names(expected_names),
            output_files,
            method=self.name,
        )
        missing = []
        for expected in expected_names:
            normalized_path = normalize_match_path(expected)
            basename = normalize_match_name(os.path.basename(normalized_path))
            if normalized_path in output_paths or basename in output_basenames:
                continue
            missing.append(expected)

        if not missing:
            return VerificationStepResult(
                method=self.name,
                status="passed",
                completeness_hint=coverage.completeness,
                source_integrity_hint=_source_integrity_hint(evidence, state_manifest),
                file_observations=coverage.observations,
                issues=[VerificationIssue(
                    method=self.name,
                    code="info.expected_name_coverage",
                    message="Expected archive names were matched against extraction output",
                    path=evidence.output_dir,
                    expected=len(expected_names),
                    actual=_coverage_actual(coverage, state_manifest, evidence),
                )],
            )

        total = len(expected_names)
        matched = total - len(missing)
        missing_ratio = len(missing) / max(1, total)
        required_match_ratio = float(config.get("required_match_ratio", 0.8) or 0.0)
        actual_match_ratio = matched / max(1, total)
        if actual_match_ratio >= required_match_ratio:
            penalty = int(config.get("minor_missing_penalty", 10) or 10)
            code = "warning.expected_names_partially_missing"
        elif matched == 0:
            penalty = int(config.get("all_missing_penalty", 60) or 60)
            code = "fail.expected_names_all_missing"
        else:
            penalty = int(config.get("missing_penalty", 35) or 35)
            code = "fail.expected_names_missing"

        issue = VerificationIssue(
            method=self.name,
            code=code,
            message="Expected archive item names were not found in extraction output",
            path=evidence.output_dir,
            expected=expected_names,
            actual={
                "matched": matched,
                "missing": missing,
                "missing_ratio": round(missing_ratio, 3),
                "coverage": _coverage_actual(coverage, state_manifest, evidence),
            },
        )
        source_integrity = _source_integrity_hint(evidence, state_manifest)
        return VerificationStepResult(
            method=self.name,
            status="warning",
            issues=[issue],
            completeness_hint=coverage.completeness,
            recoverable_upper_bound_hint=coverage.completeness if source_integrity != SOURCE_INTEGRITY_COMPLETE else None,
            source_integrity_hint=source_integrity,
            decision_hint=DECISION_REPAIR if _expected_names_are_strong(evidence, config, source_integrity, state_manifest) else DECISION_NONE,
            file_observations=coverage.observations,
        )

    def _expected_names(
        self,
        evidence: VerificationEvidence,
        config: dict,
        state_manifest: ArchiveStateManifest | None = None,
    ) -> list[str]:
        configured = config.get("expected_names")
        candidates = list(_iter_name_values(configured))
        if not candidates and state_manifest is not None and state_manifest.ok:
            candidates.extend(state_manifest.expected_names)
        if not candidates:
            for field in NAME_FIELDS:
                candidates.extend(_iter_name_values(evidence.analysis.get(field)))
        if not candidates:
            candidates.extend(_iter_name_values(_fact_value(evidence.fact_bag, "verification.expected_names")))

        max_names = max(1, int(config.get("max_expected_names", 50) or 50))
        names = []
        seen = set()
        for candidate in candidates:
            cleaned = clean_relative_archive_path(candidate)
            if not cleaned:
                continue
            key = normalize_match_path(cleaned)
            if key in seen:
                continue
            seen.add(key)
            names.append(cleaned)
            if len(names) >= max_names:
                break
        return names


def _fact_value(fact_bag: Any, key: str) -> Any:
    if fact_bag is not None and hasattr(fact_bag, "get"):
        return fact_bag.get(key)
    return None


def _output_files_for_coverage(evidence: VerificationEvidence) -> list[dict[str, Any]]:
    manifest = evidence.progress_manifest or {}
    manifest_files = []
    for item in manifest.get("files") or []:
        if not isinstance(item, dict):
            continue
        path = item.get("archive_path") or item.get("path")
        if not path:
            continue
        manifest_files.append({
            "path": path,
            "archive_path": item.get("archive_path"),
            "size": item.get("bytes_written"),
            "bytes_written": item.get("bytes_written"),
            "status": item.get("status"),
        })
    return manifest_files or output_files_from_directory(evidence.output_dir)


def _iter_name_values(value: Any):
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, bytes):
        try:
            yield value.decode("utf-8", errors="replace")
        except Exception:
            return
        return
    if isinstance(value, dict):
        for key in ("name", "path", "file", "filename"):
            if key in value:
                yield from _iter_name_values(value.get(key))
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _iter_name_values(item)


def _source_integrity_hint(evidence: VerificationEvidence, state_manifest: ArchiveStateManifest | None = None) -> str:
    if state_manifest is not None:
        if state_manifest.status == STATUS_OK and state_manifest.ok:
            return SOURCE_INTEGRITY_COMPLETE
        if state_manifest.status == STATUS_DAMAGED or state_manifest.damaged:
            return SOURCE_INTEGRITY_DAMAGED
    analysis = evidence.analysis or {}
    status = str(analysis.get("status") or "")
    if status in {"damaged", "weak"}:
        return SOURCE_INTEGRITY_DAMAGED
    return SOURCE_INTEGRITY_COMPLETE


def _expected_names_are_strong(
    evidence: VerificationEvidence,
    config: dict,
    source_integrity: str,
    state_manifest: ArchiveStateManifest | None = None,
) -> bool:
    if config.get("expected_names"):
        return True
    if state_manifest is not None and state_manifest.ok and state_manifest.expected_names:
        return True
    source = str(config.get("expected_names_source") or evidence.analysis.get("expected_names_source") or "")
    if source in {"user", "central_directory", "manifest"}:
        return True
    return source_integrity == SOURCE_INTEGRITY_COMPLETE


def _coverage_actual(coverage, state_manifest: ArchiveStateManifest | None, evidence: VerificationEvidence) -> dict[str, Any]:
    actual = coverage_details(coverage)
    actual.update({
        "state_aware": True,
        "patch_digest": evidence.patch_digest,
        "archive_type": state_manifest.archive_type if state_manifest is not None else "",
        "manifest_source": state_manifest.source if state_manifest is not None and state_manifest.ok else "analysis_or_config",
    })
    return actual
