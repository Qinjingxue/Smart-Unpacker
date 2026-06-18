from contextlib import nullcontext
from dataclasses import replace
from typing import Any, Callable

from sunpack.verification.evidence import VerificationEvidence
from sunpack.verification.archive_state_manifest import configure_archive_state_manifest_cache
from sunpack.verification.output_quality import compute_output_quality
from sunpack.verification.registry import get_verification_method
from sunpack.verification.result import (
    ASSESSMENT_COMPLETE,
    ASSESSMENT_INCONSISTENT,
    ASSESSMENT_PARTIAL,
    ASSESSMENT_UNKNOWN,
    ASSESSMENT_UNUSABLE,
    DECISION_ACCEPT,
    DECISION_ACCEPT_PARTIAL,
    DECISION_FAIL,
    DECISION_NONE,
    DECISION_REPAIR,
    DECISION_RETRY_EXTRACT,
    SOURCE_INTEGRITY_COMPLETE,
    SOURCE_INTEGRITY_DAMAGED,
    SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
    SOURCE_INTEGRITY_TRUNCATED,
    SOURCE_INTEGRITY_UNKNOWN,
    ArchiveCoverageSummary,
    FileVerificationObservation,
    VerificationIssue,
    VerificationResult,
    VerificationStepRecord,
)


class VerificationPipeline:
    def __init__(self, config: dict):
        self.config = dict(config or {})
        self.methods = list(self.config.get("methods") or [])
        self.complete_accept_threshold = _clamp01(float(self.config.get("complete_accept_threshold", 0.999) or 0.999))
        self.partial_accept_threshold = _clamp01(float(self.config.get("partial_accept_threshold", 0.2) or 0.2))

    def run(
        self,
        evidence: VerificationEvidence,
        *,
        phase_timer: Callable[..., Any] | None = None,
        phase_prefix: str = "verify_pipeline",
    ) -> VerificationResult:
        issues: list[VerificationIssue] = []
        methods_run: list[str] = []
        steps: list[VerificationStepRecord] = []
        file_observations: list[FileVerificationObservation] = []
        completeness_hints: list[float] = []
        upper_bound_hints: list[float] = []
        source_hints: list[str] = []
        decision_hints: list[str] = []

        observation_owner = _configured_observation_owner(self.methods, evidence)
        if observation_owner:
            object.__setattr__(evidence, "_file_observation_owner", observation_owner)

        manifest_limit = _configured_archive_manifest_limit(self.methods)
        if manifest_limit is not None:
            configure_archive_state_manifest_cache(evidence, max_items=manifest_limit)

        if not self.methods:
            return VerificationResult(
                completeness=1.0,
                recoverable_upper_bound=1.0,
                assessment_status=ASSESSMENT_UNKNOWN,
                source_integrity=SOURCE_INTEGRITY_UNKNOWN,
                decision_hint=DECISION_ACCEPT,
            )

        for method_config in self.methods:
            if not isinstance(method_config, dict) or not method_config.get("enabled", True):
                continue
            method_name = str(method_config.get("name") or "").strip()
            if not method_name:
                continue
            method = get_verification_method(method_name)
            if method is None:
                issues.append(VerificationIssue(
                    method=method_name,
                    code="warning.unknown_method",
                    message=f"Unknown verification method: {method_name}",
                ))
                continue

            with _phase(phase_timer, f"{phase_prefix}_method_{method_name}"):
                step = method.verify(evidence, method_config)
            methods_run.append(step.method or method_name)
            issues.extend(step.issues)
            file_observations.extend(step.file_observations)
            if step.completeness_hint is not None:
                completeness_hints.append(_clamp01(float(step.completeness_hint)))
            if step.recoverable_upper_bound_hint is not None:
                upper_bound_hints.append(_clamp01(float(step.recoverable_upper_bound_hint)))
            if step.source_integrity_hint != SOURCE_INTEGRITY_UNKNOWN:
                source_hints.append(step.source_integrity_hint)
            if step.decision_hint != DECISION_NONE:
                decision_hints.append(step.decision_hint)
            steps.append(VerificationStepRecord(
                method=step.method or method_name,
                status=step.status,
                issues=list(step.issues),
                completeness_hint=step.completeness_hint,
                recoverable_upper_bound_hint=step.recoverable_upper_bound_hint,
                source_integrity_hint=step.source_integrity_hint,
                decision_hint=step.decision_hint,
                file_observations=list(step.file_observations),
            ))

        with _phase(phase_timer, f"{phase_prefix}_build_result"):
            return self._build_result(
                methods_run=methods_run,
                issues=issues,
                steps=steps,
                file_observations=file_observations,
                completeness_hints=completeness_hints,
                upper_bound_hints=upper_bound_hints,
                source_hints=source_hints,
                decision_hints=decision_hints,
                repair_hints=evidence.repair_hints,
                evidence=evidence,
            )
    def _build_result(
        self,
        *,
        methods_run: list[str],
        issues: list[VerificationIssue],
        steps: list[VerificationStepRecord],
        file_observations: list[FileVerificationObservation],
        completeness_hints: list[float],
        upper_bound_hints: list[float],
        source_hints: list[str],
        decision_hints: list[str],
        repair_hints: dict | None = None,
        evidence: VerificationEvidence,
    ) -> VerificationResult:
        file_observations = _dedupe_observations(file_observations)
        archive_coverage = _archive_coverage_summary(issues, file_observations)
        output_quality = compute_output_quality(
            evidence,
            file_observations,
            archive_coverage=archive_coverage,
        )
        direct_verification_signal = _has_direct_verification_signal(
            file_observations=file_observations,
            completeness_hints=completeness_hints,
            source_hints=source_hints,
            decision_hints=decision_hints,
            archive_coverage=archive_coverage,
        )
        evidence_sufficient = direct_verification_signal or not output_quality.empty
        completeness = _aggregate_completeness(file_observations, completeness_hints)
        if archive_coverage.confidence > 0:
            completeness = archive_coverage.completeness
        source_integrity = _aggregate_source_integrity(source_hints)
        extraction_failed = not bool(getattr(evidence.extraction_result, "success", False))
        if not evidence_sufficient:
            completeness = 0.0
            if extraction_failed and source_integrity == SOURCE_INTEGRITY_UNKNOWN:
                source_integrity = SOURCE_INTEGRITY_DAMAGED
        recoverable_upper_bound = _aggregate_upper_bound(source_integrity, upper_bound_hints)
        counts = _file_counts(file_observations)
        assessment_status = _assessment_status(
            completeness=completeness,
            source_integrity=source_integrity,
            counts=counts,
            issues=issues,
            evidence_sufficient=evidence_sufficient,
        )
        decision_hint = _decision_hint(
            assessment_status=assessment_status,
            source_integrity=source_integrity,
            completeness=completeness,
            recoverable_upper_bound=recoverable_upper_bound,
            decision_hints=decision_hints,
            complete_accept_threshold=self.complete_accept_threshold,
            partial_accept_threshold=self.partial_accept_threshold,
            output_quality_score=output_quality.score,
            output_confidence=output_quality.confidence,
            evidence_sufficient=evidence_sufficient,
        )
        return VerificationResult(
            methods_run=methods_run,
            issues=issues,
            steps=steps,
            completeness=completeness,
            recoverable_upper_bound=recoverable_upper_bound,
            assessment_status=assessment_status,
            source_integrity=source_integrity,
            decision_hint=decision_hint,
            complete_files=counts["complete"],
            partial_files=counts["partial"],
            failed_files=counts["failed"],
            missing_files=counts["missing"],
            unverified_files=counts["unverified"],
            output_quality_score=output_quality.score,
            output_file_count=output_quality.file_count,
            output_total_bytes=output_quality.total_bytes,
            output_complete_ratio=output_quality.complete_ratio,
            output_failed_ratio=output_quality.failed_ratio,
            output_empty=output_quality.empty,
            output_confidence=output_quality.confidence,
            archive_coverage=archive_coverage,
            file_observations=file_observations,
            repair_hints=dict(repair_hints or {}),
        )


def _configured_archive_manifest_limit(methods: list[Any]) -> int | None:
    limits = []
    for config in methods:
        if not isinstance(config, dict) or not config.get("enabled", True):
            continue
        name = str(config.get("name") or "").strip()
        if name == "expected_name_presence":
            limits.append(max(1, int(config.get("max_expected_names", 50) or 50)))
        elif name == "manifest_size_match":
            limits.append(max(1, int(config.get("max_expected_names", 2000) or 2000)))
        elif name == "archive_test_crc":
            limits.append(max(0, int(config.get("max_items", 200000) or 0)))
    return max(limits) if limits else None


def _configured_observation_owner(methods: list[Any], evidence: VerificationEvidence) -> str:
    worker = evidence.worker_result if isinstance(evidence.worker_result, dict) else {}
    manifest = worker.get("verified_manifest") if isinstance(worker.get("verified_manifest"), dict) else {}
    if worker.get("status") != "ok" or not manifest.get("validated"):
        return ""
    enabled = {
        str(item.get("name") or "")
        for item in methods
        if isinstance(item, dict) and item.get("enabled", True)
    }
    for name in (
        "archive_test_crc",
        "manifest_size_match",
        "expected_name_presence",
        "output_presence",
        "extraction_exit_signal",
    ):
        if name in enabled:
            return name
    return ""


def _aggregate_completeness(file_observations: list[FileVerificationObservation], hints: list[float]) -> float:
    file_completeness = _file_completeness(file_observations)
    if hints and file_completeness is not None:
        return _clamp01(min(file_completeness, min(hints)))
    if hints:
        return _clamp01(min(hints))
    if file_completeness is not None:
        return _clamp01(file_completeness)
    return 1.0


def _has_direct_verification_signal(
    *,
    file_observations: list[FileVerificationObservation],
    completeness_hints: list[float],
    source_hints: list[str],
    decision_hints: list[str],
    archive_coverage: ArchiveCoverageSummary,
) -> bool:
    if file_observations or completeness_hints or source_hints or decision_hints:
        return True
    return bool(archive_coverage.confidence > 0)


def _file_completeness(file_observations: list[FileVerificationObservation]) -> float | None:
    if not file_observations:
        return None
    total = 0.0
    for item in file_observations:
        if item.progress is not None:
            total += _clamp01(float(item.progress))
            continue
        if item.state == "complete":
            total += 1.0
        elif item.state == "partial":
            total += 0.5
        elif item.state == "unverified":
            total += 0.75
    return total / max(1, len(file_observations))


def _aggregate_upper_bound(source_integrity: str, hints: list[float]) -> float:
    if hints:
        return _clamp01(min(hints))
    if source_integrity in {SOURCE_INTEGRITY_TRUNCATED, SOURCE_INTEGRITY_PAYLOAD_DAMAGED, SOURCE_INTEGRITY_DAMAGED}:
        return 0.99
    return 1.0


def _aggregate_source_integrity(hints: list[str]) -> str:
    priority = [
        SOURCE_INTEGRITY_TRUNCATED,
        SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
        SOURCE_INTEGRITY_DAMAGED,
        SOURCE_INTEGRITY_COMPLETE,
    ]
    for item in priority:
        if item in hints:
            return item
    return SOURCE_INTEGRITY_UNKNOWN


def _file_counts(file_observations: list[FileVerificationObservation]) -> dict[str, int]:
    counts = {"complete": 0, "partial": 0, "failed": 0, "missing": 0, "unverified": 0}
    for item in file_observations:
        state = item.state if item.state in counts else "unverified"
        counts[state] += 1
    return counts


def _archive_coverage_summary(
    issues: list[VerificationIssue],
    file_observations: list[FileVerificationObservation],
) -> ArchiveCoverageSummary:
    sources = _coverage_sources_from_issues(issues)
    if sources:
        return _merge_coverage_sources(sources)
    return _coverage_from_observations(file_observations)


def _coverage_sources_from_issues(issues: list[VerificationIssue]) -> list[dict]:
    sources = []
    for issue in issues:
        actual = issue.actual if isinstance(issue.actual, dict) else {}
        coverage = actual.get("coverage") if isinstance(actual.get("coverage"), dict) else actual
        if not _looks_like_coverage(coverage):
            continue
        source = dict(coverage)
        source["method"] = issue.method
        source["code"] = issue.code
        sources.append(source)
    return sources


def _looks_like_coverage(value: dict) -> bool:
    return any(
        key in value
        for key in (
            "completeness",
            "file_coverage",
            "byte_coverage",
            "expected_files",
            "matched_files",
            "expected_bytes",
            "matched_bytes",
        )
    )


def _merge_coverage_sources(sources: list[dict]) -> ArchiveCoverageSummary:
    strongest = _strongest_coverage_source(sources)
    expected_files = max(_as_int(item.get("expected_files")) for item in sources)
    expected_bytes = max(_as_int(item.get("expected_bytes")) for item in sources)
    matched_files = _as_int(strongest.get("matched_files"))
    complete_files = _as_int(strongest.get("complete_files"))
    partial_files = _as_int(strongest.get("partial_files"))
    failed_files = _as_int(strongest.get("failed_files"))
    missing_files = _as_int(strongest.get("missing_files"))
    strongest_expected_files = _as_int(strongest.get("expected_files"))
    if expected_files > strongest_expected_files:
        missing_files = max(
            missing_files,
            max(
                (_as_int(item.get("missing_files")) for item in sources if _as_int(item.get("expected_files")) > strongest_expected_files),
                default=0,
            ),
        )
    matched_bytes = _as_int(strongest.get("matched_bytes"))
    complete_bytes = _as_int(strongest.get("complete_bytes"))
    completeness = _as_float(strongest.get("completeness"), None)
    if completeness is None:
        completeness = _coverage_value(strongest, "file_coverage", matched_files, expected_files)
    file_coverage = _coverage_value(strongest, "file_coverage", matched_files, expected_files)
    if expected_files > strongest_expected_files:
        file_coverage = _clamp01(matched_files / max(1, expected_files))
        completeness = min(completeness, file_coverage)
    byte_coverage = _coverage_value(strongest, "byte_coverage", matched_bytes, expected_bytes)
    confidence = _coverage_confidence(strongest)
    return ArchiveCoverageSummary(
        completeness=_clamp01(completeness),
        file_coverage=file_coverage,
        byte_coverage=byte_coverage,
        expected_files=expected_files,
        matched_files=matched_files,
        complete_files=complete_files,
        partial_files=partial_files,
        failed_files=failed_files,
        missing_files=missing_files,
        unverified_files=max(0, matched_files - complete_files - partial_files - failed_files),
        expected_bytes=expected_bytes,
        matched_bytes=matched_bytes,
        complete_bytes=complete_bytes,
        confidence=confidence,
        sources=[dict(item) for item in sources],
    )


def _strongest_coverage_source(sources: list[dict]) -> dict:
    return max(sources, key=lambda item: (
        _coverage_confidence(item),
        _as_int(item.get("expected_files")),
        _as_int(item.get("expected_bytes")),
    ))


def _coverage_from_observations(file_observations: list[FileVerificationObservation]) -> ArchiveCoverageSummary:
    if not file_observations:
        return ArchiveCoverageSummary(confidence=0.0)
    expected_files = len(file_observations)
    matched_files = sum(1 for item in file_observations if item.state != "missing")
    complete_files = sum(1 for item in file_observations if item.state == "complete")
    partial_files = sum(1 for item in file_observations if item.state == "partial")
    failed_files = sum(1 for item in file_observations if item.state == "failed")
    missing_files = sum(1 for item in file_observations if item.state == "missing")
    unverified_files = sum(1 for item in file_observations if item.state == "unverified")
    expected_bytes = sum(max(0, int(item.expected_size or 0)) for item in file_observations)
    matched_bytes = 0
    complete_bytes = 0
    for item in file_observations:
        if item.state == "missing":
            continue
        written = max(0, int(item.bytes_written or 0))
        expected = max(0, int(item.expected_size or 0))
        matched_bytes += min(written, expected) if expected else written
        if item.state == "complete":
            complete_bytes += expected or written
    file_coverage = matched_files / max(1, expected_files)
    byte_coverage = matched_bytes / expected_bytes if expected_bytes > 0 else file_coverage
    return ArchiveCoverageSummary(
        completeness=_aggregate_completeness(file_observations, []),
        file_coverage=_clamp01(file_coverage),
        byte_coverage=_clamp01(byte_coverage),
        expected_files=expected_files,
        matched_files=matched_files,
        complete_files=complete_files,
        partial_files=partial_files,
        failed_files=failed_files,
        missing_files=missing_files,
        unverified_files=unverified_files,
        expected_bytes=expected_bytes,
        matched_bytes=matched_bytes,
        complete_bytes=complete_bytes,
        confidence=0.5,
        sources=[{
            "method": "file_observations",
            "completeness": _aggregate_completeness(file_observations, []),
            "file_coverage": _clamp01(file_coverage),
            "byte_coverage": _clamp01(byte_coverage),
            "expected_files": expected_files,
            "matched_files": matched_files,
            "expected_bytes": expected_bytes,
            "matched_bytes": matched_bytes,
        }],
    )


def _dedupe_observations(file_observations: list[FileVerificationObservation]) -> list[FileVerificationObservation]:
    by_path: dict[str, FileVerificationObservation] = {}
    for item in file_observations:
        key = (item.archive_path or item.path).replace("\\", "/")
        if not key:
            key = f"{item.method}:{len(by_path)}"
        existing = by_path.get(key)
        if existing is None:
            by_path[key] = item
            continue
        chosen, other = (item, existing) if _state_rank(item.state) < _state_rank(existing.state) else (existing, item)
        methods = list(chosen.details.get("verification_methods") or [])
        for method in (existing.method, item.method):
            if method and method not in methods:
                methods.append(method)
        issues = list(chosen.issues)
        issue_keys = {(issue.method, issue.code, issue.path) for issue in issues}
        for issue in other.issues:
            issue_key = (issue.method, issue.code, issue.path)
            if issue_key not in issue_keys:
                issue_keys.add(issue_key)
                issues.append(issue)
        by_path[key] = replace(
            chosen,
            archive_path=chosen.archive_path or other.archive_path,
            bytes_written=max(chosen.bytes_written, other.bytes_written),
            expected_size=chosen.expected_size if chosen.expected_size is not None else other.expected_size,
            progress=chosen.progress if chosen.progress is not None else other.progress,
            crc_expected=chosen.crc_expected if chosen.crc_expected is not None else other.crc_expected,
            crc_actual=chosen.crc_actual if chosen.crc_actual is not None else other.crc_actual,
            issues=issues,
            details={**other.details, **chosen.details, "verification_methods": methods},
        )
    return list(by_path.values())


def _state_rank(state: str) -> int:
    return {
        "failed": 0,
        "missing": 1,
        "partial": 2,
        "complete": 3,
        "unverified": 4,
    }.get(state, 3)


def _coverage_value(source: dict, key: str, numerator: int, denominator: int) -> float:
    if key in source:
        return _clamp01(_as_float(source.get(key), 1.0))
    if denominator <= 0:
        return 1.0
    return _clamp01(numerator / denominator)


def _coverage_confidence(source: dict) -> float:
    if source.get("confidence") is not None:
        return _clamp01(_as_float(source.get("confidence"), 0.5))
    if source.get("code") == "info.archive_output_coverage":
        return 0.95
    if source.get("code") == "info.expected_name_coverage":
        manifest_source = str(source.get("manifest_source") or source.get("expected_names_source") or "")
        if manifest_source in {"analysis_or_config", "damaged_scan"}:
            return 0.6
        return 0.8
    if source.get("code") == "info.output_progress_coverage":
        return 0.7
    if source.get("code") == "info.sample_readability_coverage":
        return 0.35
    return _as_float(source.get("confidence"), 0.5)


def _min_float(values, *, default: float) -> float:
    parsed = [_as_float(value, None) for value in values]
    parsed = [value for value in parsed if value is not None]
    if not parsed:
        return default
    return min(parsed)


def _as_int(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _as_float(value, default: float | None = 0.0) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _assessment_status(
    *,
    completeness: float,
    source_integrity: str,
    counts: dict[str, int],
    issues: list[VerificationIssue],
    evidence_sufficient: bool = True,
) -> str:
    if counts["failed"] or counts["missing"]:
        return ASSESSMENT_INCONSISTENT if source_integrity == SOURCE_INTEGRITY_COMPLETE else ASSESSMENT_PARTIAL
    if counts["partial"]:
        return ASSESSMENT_PARTIAL
    if not evidence_sufficient:
        if any(issue.code.startswith("fail") for issue in issues):
            return ASSESSMENT_UNUSABLE
        return ASSESSMENT_UNKNOWN
    if completeness >= 0.999:
        return ASSESSMENT_COMPLETE
    if completeness > 0.0:
        return ASSESSMENT_PARTIAL
    if any(issue.code.startswith("fail") for issue in issues):
        return ASSESSMENT_UNUSABLE
    return ASSESSMENT_UNKNOWN


def _decision_hint(
    *,
    assessment_status: str,
    source_integrity: str,
    completeness: float,
    recoverable_upper_bound: float,
    decision_hints: list[str],
    complete_accept_threshold: float,
    partial_accept_threshold: float,
    output_quality_score: float = 0.0,
    output_confidence: float = 0.0,
    evidence_sufficient: bool = True,
) -> str:
    if DECISION_FAIL in decision_hints:
        return DECISION_FAIL
    if not evidence_sufficient:
        if source_integrity in {
            SOURCE_INTEGRITY_TRUNCATED,
            SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
            SOURCE_INTEGRITY_DAMAGED,
        }:
            return DECISION_REPAIR
        return DECISION_FAIL
    high_output_quality = (
        output_quality_score >= complete_accept_threshold
        and output_confidence >= 0.5
        and completeness >= complete_accept_threshold
    )
    output_partial_acceptable = output_quality_score >= partial_accept_threshold and output_confidence >= 0.35
    if DECISION_ACCEPT_PARTIAL in decision_hints and source_integrity in {
        SOURCE_INTEGRITY_TRUNCATED,
        SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
        SOURCE_INTEGRITY_DAMAGED,
    } and (
        (completeness >= partial_accept_threshold and completeness >= min(0.999, recoverable_upper_bound))
        or output_partial_acceptable
    ):
        return DECISION_ACCEPT_PARTIAL
    if (
        assessment_status == ASSESSMENT_COMPLETE
        and completeness >= complete_accept_threshold
        and source_integrity in {SOURCE_INTEGRITY_COMPLETE, SOURCE_INTEGRITY_UNKNOWN}
    ):
        return DECISION_ACCEPT
    if assessment_status == ASSESSMENT_COMPLETE and source_integrity in {
        SOURCE_INTEGRITY_TRUNCATED,
        SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
        SOURCE_INTEGRITY_DAMAGED,
    }:
        if high_output_quality or output_partial_acceptable:
            return DECISION_ACCEPT_PARTIAL
        return DECISION_REPAIR
    for decision in (DECISION_REPAIR, DECISION_RETRY_EXTRACT, DECISION_ACCEPT_PARTIAL, DECISION_ACCEPT):
        if decision in decision_hints:
            return decision
    if assessment_status == ASSESSMENT_PARTIAL and source_integrity in {
        SOURCE_INTEGRITY_TRUNCATED,
        SOURCE_INTEGRITY_PAYLOAD_DAMAGED,
        SOURCE_INTEGRITY_DAMAGED,
    } and (
        (completeness >= partial_accept_threshold and completeness >= min(0.999, recoverable_upper_bound))
        or output_partial_acceptable
    ):
        return DECISION_ACCEPT_PARTIAL
    if assessment_status in {ASSESSMENT_PARTIAL, ASSESSMENT_INCONSISTENT}:
        return DECISION_REPAIR
    return DECISION_FAIL


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def _phase(timer: Callable[..., Any] | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
