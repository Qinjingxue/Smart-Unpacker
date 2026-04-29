from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from sunpack.verification.result import (
    ASSESSMENT_COMPLETE,
    ASSESSMENT_INCONSISTENT,
    ASSESSMENT_PARTIAL,
    ASSESSMENT_UNKNOWN,
    ASSESSMENT_UNUSABLE,
    DECISION_ACCEPT,
    DECISION_ACCEPT_PARTIAL,
    DECISION_FAIL,
    DECISION_REPAIR,
    DECISION_RETRY_EXTRACT,
    VerificationResult,
)


@dataclass(frozen=True)
class RecoveryAttempt:
    attempt_id: str
    verification: VerificationResult
    extraction_result: Any = None
    archive_state: dict[str, Any] = field(default_factory=dict)
    patch_digest: str = ""
    patch_lineage: list[dict[str, Any]] = field(default_factory=list)
    round_index: int = 0
    source: str = "unknown"
    repair_module: str = ""
    patch_cost: float = 0.0
    risk_flags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RecoveryRank:
    attempt_id: str
    rank_score: float
    rank_vector: dict[str, Any]
    decision: str
    reasons: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class RecoveryComparisonResult:
    selected: list[RecoveryAttempt]
    rejected: list[RecoveryAttempt]
    ranks: dict[str, RecoveryRank]
    best: RecoveryAttempt | None
    should_continue_repair: bool
    stop_reason: str = ""


def rank_attempt(attempt: RecoveryAttempt) -> RecoveryRank:
    verification = attempt.verification
    coverage = verification.archive_coverage
    terminal = _terminal_blocker(attempt)
    status_rank = _status_rank(verification.assessment_status)
    decision_rank = _decision_rank(verification.decision_hint)
    source_quality = _coverage_source_quality(coverage.sources)
    source_integrity_rank = _source_integrity_rank(verification.source_integrity)
    complete_files = int(coverage.complete_files or verification.complete_files or 0)
    failed_missing = int(coverage.failed_files or verification.failed_files or 0) + int(
        coverage.missing_files or verification.missing_files or 0
    )
    partial_files = int(coverage.partial_files or verification.partial_files or 0)
    completeness = _clamp01(float(coverage.completeness if coverage.confidence > 0 else verification.completeness))
    file_coverage = _clamp01(float(coverage.file_coverage or completeness))
    byte_coverage = _clamp01(float(coverage.byte_coverage or completeness))
    complete_bonus = 1.0 if verification.assessment_status == ASSESSMENT_COMPLETE else 0.0
    terminal_penalty = 1.0 if terminal else 0.0
    patch_cost = max(0.0, float(attempt.patch_cost or 0.0))
    risk_penalty = min(0.25, len(attempt.risk_flags) * 0.03)
    rank_score = (
        complete_bonus * 2.0
        + status_rank * 0.35
        + decision_rank * 0.2
        + completeness * 1.5
        + file_coverage * 0.55
        + byte_coverage * 0.35
        + source_integrity_rank * 0.08
        + source_quality * 0.3
        + min(1.0, complete_files / max(1, int(coverage.expected_files or complete_files or 1))) * 0.25
        + partial_files * 0.01
        - failed_missing * 0.04
        - min(1.0, patch_cost) * 0.05
        - risk_penalty
        - terminal_penalty * 3.0
    )
    vector = {
        "terminal_blocker": terminal,
        "assessment_status": verification.assessment_status,
        "decision_hint": verification.decision_hint,
        "status_rank": status_rank,
        "decision_rank": decision_rank,
        "completeness": completeness,
        "file_coverage": file_coverage,
        "byte_coverage": byte_coverage,
        "source_integrity": verification.source_integrity,
        "source_integrity_rank": source_integrity_rank,
        "complete_files": complete_files,
        "partial_files": partial_files,
        "failed_missing_files": failed_missing,
        "source_quality": source_quality,
        "patch_cost": patch_cost,
        "patch_digest": attempt.patch_digest,
        "source": attempt.source,
    }
    return RecoveryRank(
        attempt_id=attempt.attempt_id,
        rank_score=rank_score,
        rank_vector=vector,
        decision=_rank_decision(attempt, terminal=terminal),
        reasons=_rank_reasons(vector),
    )


def rank_attempts(attempts: list[RecoveryAttempt]) -> list[tuple[RecoveryAttempt, RecoveryRank]]:
    ranked = [(attempt, rank_attempt(attempt)) for attempt in attempts]
    return sorted(ranked, key=lambda item: _sort_key(item[0], item[1]), reverse=True)


def compare_attempts(
    attempts: list[RecoveryAttempt],
    *,
    keep_limit: int = 1,
    incumbent: RecoveryAttempt | None = None,
    min_improvement: float = 0.0,
) -> RecoveryComparisonResult:
    candidates = list(attempts)
    if incumbent is not None and not any(item.attempt_id == incumbent.attempt_id for item in candidates):
        candidates.append(incumbent)
    if not candidates:
        return RecoveryComparisonResult(
            selected=[],
            rejected=[],
            ranks={},
            best=None,
            should_continue_repair=False,
            stop_reason="no_attempts",
        )
    ranked = rank_attempts(candidates)
    best, best_rank = ranked[0]
    ranks = {rank.attempt_id: rank for _attempt, rank in ranked}
    selected = [attempt for attempt, _rank in ranked[: max(1, int(keep_limit or 1))]]
    rejected = [attempt for attempt, _rank in ranked[max(1, int(keep_limit or 1)):]]
    stop_reason = ""
    should_continue = best_rank.decision in {"continue_repair", "keep_partial"}
    if incumbent is not None:
        incumbent_rank = ranks.get(incumbent.attempt_id)
        non_incumbent_attempted = any(item.attempt_id != incumbent.attempt_id for item in candidates)
        if best.attempt_id == incumbent.attempt_id and non_incumbent_attempted:
            should_continue = False
            stop_reason = "no_improvement"
        elif best.attempt_id != incumbent.attempt_id:
            if incumbent_rank is not None and best_rank.rank_score <= incumbent_rank.rank_score + max(0.0, min_improvement):
                best = incumbent
                selected = [incumbent, *[item for item in selected if item.attempt_id != incumbent.attempt_id]][: max(1, int(keep_limit or 1))]
                rejected = [item for item in candidates if item.attempt_id not in {selected_item.attempt_id for selected_item in selected}]
                should_continue = False
                stop_reason = "no_improvement"
    if not stop_reason:
        stop_reason = _stop_reason_for_rank(ranks[best.attempt_id])
    return RecoveryComparisonResult(
        selected=selected,
        rejected=rejected,
        ranks=ranks,
        best=best,
        should_continue_repair=should_continue,
        stop_reason=stop_reason,
    )


def score_verification_payload(payload: dict[str, Any]) -> float:
    verification = _verification_from_payload(payload)
    attempt = RecoveryAttempt(
        attempt_id=_stable_digest(payload),
        verification=verification,
        patch_cost=float(payload.get("patch_cost", 0.0) or 0.0),
        source=str(payload.get("source") or "assessment"),
        patch_digest=str(payload.get("patch_digest") or ""),
    )
    return rank_attempt(attempt).rank_score


def _verification_from_payload(payload: dict[str, Any]) -> VerificationResult:
    from sunpack.verification.result import ArchiveCoverageSummary

    coverage_payload = payload.get("archive_coverage") if isinstance(payload.get("archive_coverage"), dict) else {}
    coverage = ArchiveCoverageSummary(
        completeness=_clamp01(float(coverage_payload.get("completeness", payload.get("completeness", 1.0)) or 0.0)),
        file_coverage=_clamp01(float(coverage_payload.get("file_coverage", payload.get("file_coverage", payload.get("completeness", 1.0))) or 0.0)),
        byte_coverage=_clamp01(float(coverage_payload.get("byte_coverage", payload.get("byte_coverage", payload.get("completeness", 1.0))) or 0.0)),
        expected_files=_as_int(coverage_payload.get("expected_files")),
        matched_files=_as_int(coverage_payload.get("matched_files")),
        complete_files=_as_int(coverage_payload.get("complete_files", payload.get("complete_files"))),
        partial_files=_as_int(coverage_payload.get("partial_files", payload.get("partial_files"))),
        failed_files=_as_int(coverage_payload.get("failed_files", payload.get("failed_files"))),
        missing_files=_as_int(coverage_payload.get("missing_files", payload.get("missing_files"))),
        unverified_files=_as_int(coverage_payload.get("unverified_files", payload.get("unverified_files"))),
        expected_bytes=_as_int(coverage_payload.get("expected_bytes")),
        matched_bytes=_as_int(coverage_payload.get("matched_bytes")),
        complete_bytes=_as_int(coverage_payload.get("complete_bytes")),
        confidence=float(coverage_payload.get("confidence", 0.0) or 0.0),
        sources=list(coverage_payload.get("sources") or []),
    )
    return VerificationResult(
        completeness=_clamp01(float(payload.get("completeness", coverage.completeness) or 0.0)),
        recoverable_upper_bound=_clamp01(float(payload.get("recoverable_upper_bound", 1.0) or 1.0)),
        assessment_status=str(payload.get("assessment_status") or payload.get("status") or ASSESSMENT_UNKNOWN),
        source_integrity=str(payload.get("source_integrity") or "unknown"),
        decision_hint=str(payload.get("decision_hint") or "none"),
        complete_files=_as_int(payload.get("complete_files", coverage.complete_files)),
        partial_files=_as_int(payload.get("partial_files", coverage.partial_files)),
        failed_files=_as_int(payload.get("failed_files", coverage.failed_files)),
        missing_files=_as_int(payload.get("missing_files", coverage.missing_files)),
        unverified_files=_as_int(payload.get("unverified_files", coverage.unverified_files)),
        archive_coverage=coverage,
    )


def _sort_key(attempt: RecoveryAttempt, rank: RecoveryRank) -> tuple:
    vector = rank.rank_vector
    return (
        0 if vector["terminal_blocker"] else 1,
        1 if vector["assessment_status"] == ASSESSMENT_COMPLETE else 0,
        vector["status_rank"],
        vector["decision_rank"],
        round(vector["completeness"], 6),
        int(vector["complete_files"]),
        -int(vector["failed_missing_files"]),
        round(vector["file_coverage"], 6),
        round(vector["byte_coverage"], 6),
        round(vector["source_integrity_rank"], 6),
        round(vector["source_quality"], 6),
        -float(vector["patch_cost"]),
        -int(attempt.round_index),
        rank.rank_score,
        _stable_digest({"attempt_id": attempt.attempt_id, "patch_digest": attempt.patch_digest}),
    )


def _rank_decision(attempt: RecoveryAttempt, *, terminal: bool) -> str:
    if terminal:
        return "drop"
    decision = attempt.verification.decision_hint
    status = attempt.verification.assessment_status
    if decision == DECISION_ACCEPT or status == ASSESSMENT_COMPLETE:
        return "accept"
    if decision == DECISION_ACCEPT_PARTIAL:
        return "keep_partial"
    if decision in {DECISION_REPAIR, DECISION_RETRY_EXTRACT}:
        return "continue_repair"
    return "drop"


def _stop_reason_for_rank(rank: RecoveryRank) -> str:
    if rank.decision == "accept":
        return "complete_found"
    if rank.decision == "keep_partial":
        return "partial_incumbent"
    if rank.decision == "continue_repair":
        return "repair_recommended"
    return "no_recoverable_attempt"


def _rank_reasons(vector: dict[str, Any]) -> list[dict[str, Any]]:
    reasons = [
        {"code": "coverage.completeness", "value": vector["completeness"]},
        {"code": "coverage.file_coverage", "value": vector["file_coverage"]},
        {"code": "coverage.byte_coverage", "value": vector["byte_coverage"]},
        {"code": "files.complete", "value": vector["complete_files"]},
    ]
    if vector["failed_missing_files"]:
        reasons.append({"code": "files.failed_or_missing", "value": vector["failed_missing_files"]})
    if vector["terminal_blocker"]:
        reasons.append({"code": "terminal.blocker", "value": True})
    if vector["patch_cost"]:
        reasons.append({"code": "patch.cost", "value": vector["patch_cost"]})
    return reasons


def _terminal_blocker(attempt: RecoveryAttempt) -> bool:
    diagnostics = getattr(attempt.extraction_result, "diagnostics", {}) or {}
    result = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else diagnostics
    failure_kind = str(result.get("failure_kind") or result.get("native_status") or "").lower() if isinstance(result, dict) else ""
    if any(token in failure_kind for token in ("missing_volume", "wrong_password", "resource_guard")):
        return True
    for issue in attempt.verification.issues:
        code = issue.code.lower()
        if any(token in code for token in ("missing_volume", "wrong_password", "resource_guard")):
            return True
    return False


def _status_rank(status: str) -> int:
    return {
        ASSESSMENT_COMPLETE: 5,
        ASSESSMENT_PARTIAL: 4,
        ASSESSMENT_INCONSISTENT: 2,
        ASSESSMENT_UNKNOWN: 1,
        ASSESSMENT_UNUSABLE: 0,
    }.get(status, 1)


def _decision_rank(decision: str) -> int:
    return {
        DECISION_ACCEPT: 5,
        DECISION_ACCEPT_PARTIAL: 4,
        DECISION_REPAIR: 2,
        DECISION_RETRY_EXTRACT: 1,
        DECISION_FAIL: 0,
    }.get(decision, 1)


def _coverage_source_quality(sources: list[dict[str, Any]]) -> float:
    if not sources:
        return 0.0
    qualities = [_single_source_quality(item) for item in sources if isinstance(item, dict)]
    return max(qualities) if qualities else 0.0


def _single_source_quality(source: dict[str, Any]) -> float:
    code = str(source.get("code") or "")
    method = str(source.get("method") or "")
    if code == "info.archive_output_coverage" or method == "archive_test_crc":
        return 1.0
    if code == "info.expected_name_coverage":
        return 0.75
    if code == "info.output_progress_coverage" or method == "output_presence":
        return 0.65
    if code == "info.sample_readability_coverage":
        return 0.3
    return _clamp01(float(source.get("confidence", 0.5) or 0.5))


def _source_integrity_rank(source_integrity: str) -> float:
    return {
        "complete": 1.0,
        "unknown": 0.5,
        "damaged": 0.3,
        "payload_damaged": 0.2,
        "truncated": 0.1,
    }.get(str(source_integrity or "unknown"), 0.5)


def _stable_digest(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))
