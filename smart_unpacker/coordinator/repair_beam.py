from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from smart_unpacker.contracts.archive_state import ArchiveState
from smart_unpacker.repair.candidate import CandidateSelector, RepairCandidate, materialize_candidate
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.scheduler import RepairScheduler
from smart_unpacker.verification.result import (
    ASSESSMENT_COMPLETE,
    ASSESSMENT_INCONSISTENT,
    ASSESSMENT_PARTIAL,
    ASSESSMENT_UNUSABLE,
    DECISION_ACCEPT,
    DECISION_ACCEPT_PARTIAL,
    DECISION_FAIL,
    DECISION_NONE,
    DECISION_REPAIR,
    DECISION_RETRY_EXTRACT,
    SOURCE_INTEGRITY_UNKNOWN,
    VerificationResult,
)


AnalyzeFn = Callable[[RepairCandidate], dict[str, Any]]
AssessFn = Callable[["RepairBeamCandidate"], VerificationResult | dict[str, Any] | None]


@dataclass(frozen=True)
class RepairBeamState:
    source_input: dict[str, Any]
    format: str
    archive_state: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    damage_flags: list[str] = field(default_factory=list)
    password: str | None = None
    archive_key: str = ""
    round_index: int = 0
    score: float = 0.0
    completeness: float = 0.0
    recoverable_upper_bound: float = 1.0
    assessment_status: str = ""
    source_integrity: str = SOURCE_INTEGRITY_UNKNOWN
    decision_hint: str = DECISION_NONE
    verification: dict[str, Any] = field(default_factory=dict)
    actions: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    job_template: RepairJob | None = field(default=None, compare=False, repr=False)

    @property
    def digest(self) -> str:
        payload = {
            "source_input": self.source_input,
            "archive_state": self.archive_state,
            "format": self.format,
            "password_present": self.password is not None,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def to_job(self) -> RepairJob:
        extraction_failure = None
        if self.verification:
            extraction_failure = {
                "failure_stage": "repair_beam",
                "assessment_status": self.assessment_status,
                "source_integrity": self.source_integrity,
                "decision_hint": self.decision_hint,
                "completeness": self.completeness,
                "recoverable_upper_bound": self.recoverable_upper_bound,
                "verification": dict(self.verification),
            }
        if self.job_template is not None:
            return replace(
                self.job_template,
                source_input=dict(self.source_input),
                format=self.format,
                archive_state=_state_from_dict(self.archive_state) or self.job_template.archive_state,
                confidence=self.confidence,
                extraction_failure=extraction_failure or self.job_template.extraction_failure,
                damage_flags=list(self.damage_flags),
                password=self.password if self.password is not None else self.job_template.password,
                archive_key=self.archive_key,
                attempts=self.round_index,
            )
        return RepairJob(
            source_input=dict(self.source_input),
            format=self.format,
            archive_state=_state_from_dict(self.archive_state),
            confidence=self.confidence,
            extraction_failure=extraction_failure,
            damage_flags=list(self.damage_flags),
            password=self.password,
            archive_key=self.archive_key,
            attempts=self.round_index,
        )


@dataclass(frozen=True)
class RepairBeamCandidate:
    state: RepairBeamState
    candidate: RepairCandidate
    analyze: dict[str, Any] = field(default_factory=dict)
    assessment: dict[str, Any] = field(default_factory=dict)
    score: float = 0.0


@dataclass(frozen=True)
class RepairBeamRound:
    round_index: int
    states_in: list[RepairBeamState]
    candidates: list[RepairBeamCandidate]
    states_out: list[RepairBeamState]
    accepted_states: list[RepairBeamState] = field(default_factory=list)


@dataclass(frozen=True)
class RepairBeamRunResult:
    rounds: list[RepairBeamRound]
    states: list[RepairBeamState]
    accepted_states: list[RepairBeamState]

    @property
    def best_state(self) -> RepairBeamState | None:
        candidates = self.accepted_states or self.states
        if not candidates:
            return None
        return max(candidates, key=lambda item: item.score)


class RepairBeamLoop:
    def __init__(
        self,
        scheduler: RepairScheduler,
        *,
        beam_width: int = 4,
        max_candidates_per_state: int | None = None,
        max_analyze_candidates: int = 8,
        max_assess_candidates: int | None = None,
        analyze: AnalyzeFn | None = None,
        assess: AssessFn | None = None,
        min_improvement: float = 0.0,
    ):
        self.scheduler = scheduler
        self.beam_width = max(1, int(beam_width or 1))
        self.max_candidates_per_state = max_candidates_per_state
        self.max_analyze_candidates = max(1, int(max_analyze_candidates or 1))
        self.max_assess_candidates = max(1, int(max_assess_candidates or self.max_analyze_candidates))
        self.analyze = analyze or (lambda _candidate: {})
        self.assess = assess or (lambda _candidate: None)
        self.min_improvement = max(0.0, float(min_improvement or 0.0))

    @classmethod
    def from_config(
        cls,
        scheduler: RepairScheduler,
        config: dict[str, Any],
        *,
        analyze: AnalyzeFn | None = None,
        assess: AssessFn | None = None,
    ) -> "RepairBeamLoop":
        beam = config.get("beam") if isinstance(config.get("beam"), dict) else {}
        return cls(
            scheduler,
            beam_width=int(beam.get("beam_width", 4) or 4),
            max_candidates_per_state=int(beam.get("max_candidates_per_state", 4) or 4),
            max_analyze_candidates=int(beam.get("max_analyze_candidates", 8) or 8),
            max_assess_candidates=int(beam.get("max_assess_candidates", 4) or 4),
            analyze=analyze,
            assess=assess,
            min_improvement=float(beam.get("min_improvement", 0.0) or 0.0),
        )

    def run(self, states: list[RepairBeamState], *, max_rounds: int = 3) -> RepairBeamRunResult:
        frontier = list(states)
        rounds: list[RepairBeamRound] = []
        accepted: list[RepairBeamState] = []
        best_completeness = max([float(state.completeness or 0.0) for state in frontier] or [0.0])
        for round_index in range(1, max(0, int(max_rounds or 0)) + 1):
            if not frontier:
                break
            round_result = self.expand_round(frontier, round_index=round_index)
            rounds.append(round_result)
            accepted.extend(round_result.accepted_states)
            if round_result.accepted_states:
                return RepairBeamRunResult(rounds=rounds, states=round_result.states_out, accepted_states=_top_states(accepted, self.beam_width))
            next_best = max([float(state.completeness or 0.0) for state in round_result.states_out] or [0.0])
            if round_index > 1 and next_best <= best_completeness + self.min_improvement:
                break
            best_completeness = max(best_completeness, next_best)
            frontier = round_result.states_out
        return RepairBeamRunResult(rounds=rounds, states=frontier, accepted_states=_top_states(accepted, self.beam_width))

    def expand_round(self, states: list[RepairBeamState], *, round_index: int) -> RepairBeamRound:
        raw_candidates: list[RepairBeamCandidate] = []
        for state in states:
            try:
                batch = self.scheduler.generate_repair_candidates(state.to_job(), lazy=True)
            except TypeError:
                batch = self.scheduler.generate_repair_candidates(state.to_job())
            candidates = list(batch.candidates)
            if self.max_candidates_per_state is not None:
                candidates = candidates[: max(0, int(self.max_candidates_per_state))]
            for candidate in candidates:
                raw_candidates.append(RepairBeamCandidate(
                    state=state,
                    candidate=candidate,
                    score=_candidate_pre_score(candidate, state),
                ))

        ranked = sorted(raw_candidates, key=lambda item: item.score, reverse=True)
        analyzed = [
            _with_analyze(item, self.analyze(item.candidate))
            for item in ranked[: self.max_analyze_candidates]
        ]
        analyzed = sorted(analyzed, key=lambda item: item.score, reverse=True)
        assessment_window = _materialize_beam_items(analyzed[: self.max_assess_candidates])
        assessment_window = sorted(assessment_window, key=lambda item: item.score, reverse=True)
        assessed = [
            _with_assessment(item, self.assess(item))
            for item in assessment_window
        ]
        assessed = sorted(assessed, key=lambda item: item.score, reverse=True)
        states_out = self._states_from_candidates(assessed, round_index=round_index)
        accepted_states = [state for state in states_out if _state_accepted(state)]
        return RepairBeamRound(
            round_index=round_index,
            states_in=list(states),
            candidates=assessed,
            states_out=states_out,
            accepted_states=accepted_states,
        )

    def _states_from_candidates(self, candidates: list[RepairBeamCandidate], *, round_index: int) -> list[RepairBeamState]:
        output: list[RepairBeamState] = []
        seen: set[str] = set()
        for item in candidates:
            password = _candidate_or_state_password(item)
            repaired_input = _source_input_with_password(item.candidate.repaired_input, password)
            candidate_state = _candidate_archive_state(item.candidate)
            state = RepairBeamState(
                source_input=dict(repaired_input),
                format=item.candidate.format or item.state.format,
                archive_state=candidate_state or dict(item.state.archive_state),
                confidence=max(
                    float(item.candidate.confidence or 0.0),
                    float(item.analyze.get("confidence", 0.0) or 0.0),
                    float(item.assessment.get("confidence", 0.0) or 0.0),
                ),
                damage_flags=list(item.candidate.damage_flags or item.state.damage_flags),
                password=password,
                archive_key=f"{item.state.archive_key or 'repair'}:{round_index}:{item.candidate.module_name}",
                round_index=round_index,
                score=item.score,
                completeness=float(item.assessment.get("completeness", item.state.completeness) or 0.0),
                recoverable_upper_bound=float(item.assessment.get("recoverable_upper_bound", item.state.recoverable_upper_bound) or 1.0),
                assessment_status=str(item.assessment.get("assessment_status") or item.state.assessment_status or ""),
                source_integrity=str(item.assessment.get("source_integrity") or item.state.source_integrity or SOURCE_INTEGRITY_UNKNOWN),
                decision_hint=str(item.assessment.get("decision_hint") or item.state.decision_hint or DECISION_NONE),
                verification=dict(item.assessment),
                job_template=item.state.job_template,
                actions=[*item.state.actions, *item.candidate.actions],
                history=[
                    *item.state.history,
                    {
                        "round": round_index,
                        "module": item.candidate.module_name,
                        "status": item.candidate.status,
                        "score": item.score,
                        "analyze": dict(item.analyze),
                        "assessment": dict(item.assessment),
                    },
                ],
            )
            if state.digest in seen:
                continue
            seen.add(state.digest)
            output.append(state)
            if len(output) >= self.beam_width:
                break
        return output


def _candidate_pre_score(candidate: RepairCandidate, state: RepairBeamState) -> float:
    selector_score = CandidateSelector._score(candidate)
    progress_score = _candidate_progress_score(candidate)
    prior_score = min(1.0, max(0.0, state.score)) * 0.03
    prior_completeness = min(1.0, max(0.0, state.completeness)) * 0.04
    return selector_score + progress_score * 0.08 + prior_score + prior_completeness


def _candidate_archive_state(candidate: RepairCandidate) -> dict[str, Any]:
    if not isinstance(candidate.plan, dict):
        return {}
    raw = candidate.plan.get("archive_state")
    return dict(raw) if isinstance(raw, dict) else {}


def _candidate_or_state_password(item: RepairBeamCandidate) -> str | None:
    repaired_input = item.candidate.repaired_input if isinstance(item.candidate.repaired_input, dict) else {}
    if "password" in repaired_input:
        return repaired_input.get("password")
    return item.state.password


def _source_input_with_password(source_input: dict[str, Any], password: str | None) -> dict[str, Any]:
    payload = dict(source_input or {})
    if password is not None and "password" not in payload:
        payload["password"] = password
    return payload


def _state_from_dict(raw: dict[str, Any]) -> ArchiveState | None:
    if not isinstance(raw, dict) or not raw:
        return None
    try:
        return ArchiveState.from_dict(raw)
    except (TypeError, ValueError):
        return None


def _materialize_beam_items(items: list[RepairBeamCandidate]) -> list[RepairBeamCandidate]:
    output: list[RepairBeamCandidate] = []
    for item in items:
        materialized = materialize_candidate(item.candidate)
        for candidate in materialized:
            if candidate.is_lazy or not candidate.repaired_input:
                continue
            candidate = replace(
                candidate,
                repaired_input=_source_input_with_password(candidate.repaired_input, item.state.password),
            )
            rescored = _candidate_pre_score(candidate, item.state)
            output.append(RepairBeamCandidate(
                state=item.state,
                candidate=candidate,
                analyze=item.analyze,
                assessment=item.assessment,
                score=max(item.score, rescored),
            ))
    return output


def _with_analyze(item: RepairBeamCandidate, analyze: dict[str, Any]) -> RepairBeamCandidate:
    confidence = float(analyze.get("confidence", 0.0) or 0.0) if isinstance(analyze, dict) else 0.0
    status_bonus = 0.05 if str(analyze.get("status") or "") in {"damaged", "extractable", "repaired"} else 0.0
    score = item.score + min(1.0, max(0.0, confidence)) * 0.25 + status_bonus
    return RepairBeamCandidate(
        state=item.state,
        candidate=item.candidate,
        analyze=dict(analyze or {}),
        assessment=item.assessment,
        score=score,
    )


def _with_assessment(item: RepairBeamCandidate, assessment: VerificationResult | dict[str, Any] | None) -> RepairBeamCandidate:
    payload = _assessment_payload(assessment)
    if not payload:
        return item
    score = _score_with_assessment(item.score, payload)
    return RepairBeamCandidate(
        state=item.state,
        candidate=item.candidate,
        analyze=item.analyze,
        assessment=payload,
        score=score,
    )


def _assessment_payload(assessment: VerificationResult | dict[str, Any] | None) -> dict[str, Any]:
    if assessment is None:
        return {}
    if isinstance(assessment, VerificationResult):
        return {
            "confidence": assessment.completeness,
            "completeness": assessment.completeness,
            "recoverable_upper_bound": assessment.recoverable_upper_bound,
            "assessment_status": assessment.assessment_status,
            "source_integrity": assessment.source_integrity,
            "decision_hint": assessment.decision_hint,
            "complete_files": assessment.complete_files,
            "partial_files": assessment.partial_files,
            "failed_files": assessment.failed_files,
            "missing_files": assessment.missing_files,
            "unverified_files": assessment.unverified_files,
        }
    if not isinstance(assessment, dict):
        return {}
    payload = dict(assessment)
    if "assessment_status" not in payload and payload.get("status") in {
        ASSESSMENT_COMPLETE,
        ASSESSMENT_PARTIAL,
        ASSESSMENT_INCONSISTENT,
        ASSESSMENT_UNUSABLE,
    }:
        payload["assessment_status"] = payload.get("status")
    return payload


def _score_with_assessment(base_score: float, assessment: dict[str, Any]) -> float:
    completeness = _clamp01(float(assessment.get("completeness", 0.0) or 0.0))
    upper_bound = _clamp01(float(assessment.get("recoverable_upper_bound", 1.0) or 1.0))
    decision = str(assessment.get("decision_hint") or DECISION_NONE)
    status = str(assessment.get("assessment_status") or assessment.get("status") or "")
    score = min(1.0, max(0.0, base_score)) * 0.35
    score += completeness * 0.55
    score += min(completeness, upper_bound) * 0.1
    score += {
        DECISION_ACCEPT: 0.35,
        DECISION_ACCEPT_PARTIAL: 0.2,
        DECISION_REPAIR: 0.04,
        DECISION_RETRY_EXTRACT: -0.05,
        DECISION_FAIL: -0.45,
    }.get(decision, 0.0)
    score += {
        ASSESSMENT_COMPLETE: 0.18,
        ASSESSMENT_PARTIAL: 0.08,
        ASSESSMENT_INCONSISTENT: -0.12,
        ASSESSMENT_UNUSABLE: -0.35,
    }.get(status, 0.0)
    return score


def _candidate_progress_score(candidate: RepairCandidate) -> float:
    best = 0.0
    for validation in candidate.validations:
        details = validation.details if isinstance(validation.details, dict) else {}
        dry_run = details.get("dry_run") if isinstance(details.get("dry_run"), dict) else {}
        if dry_run.get("ok"):
            best = max(best, 1.0)
        elif int(dry_run.get("files_written", 0) or 0) > 0:
            best = max(best, 0.55)
        elif int(dry_run.get("bytes_written", 0) or 0) > 0:
            best = max(best, 0.35)
    return best


def _state_accepted(state: RepairBeamState) -> bool:
    if state.decision_hint in {DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL}:
        return True
    return state.assessment_status == ASSESSMENT_COMPLETE


def _top_states(states: list[RepairBeamState], limit: int) -> list[RepairBeamState]:
    seen: set[str] = set()
    output = []
    for state in sorted(states, key=lambda item: item.score, reverse=True):
        if state.digest in seen:
            continue
        seen.add(state.digest)
        output.append(state)
        if len(output) >= max(1, int(limit or 1)):
            break
    return output


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))
