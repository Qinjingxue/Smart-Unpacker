from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.candidate import (
    CandidateSelector,
    RepairCandidate,
    candidate_cost_penalty,
    candidate_predicted_completeness,
    candidate_progress_score,
    candidate_risk_penalty,
    materialize_candidate,
)
from sunpack.repair.job import RepairJob
from sunpack.repair.scheduler import RepairScheduler
from sunpack.verification.result import (
    ASSESSMENT_COMPLETE,
    ASSESSMENT_INCONSISTENT,
    ASSESSMENT_PARTIAL,
    ASSESSMENT_UNUSABLE,
    DECISION_ACCEPT,
    DECISION_NONE,
    DECISION_REPAIR,
    SOURCE_INTEGRITY_UNKNOWN,
    VerificationResult,
)
from sunpack.verification.comparison import score_verification_payload


AnalyzeFn = Callable[[RepairCandidate], dict[str, Any]]
AssessFn = Callable[["RepairBeamCandidate"], VerificationResult | dict[str, Any] | None]
ShouldAssessFn = Callable[["RepairBeamCandidate"], bool]


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
    terminal_results: list[Any] = field(default_factory=list)


@dataclass(frozen=True)
class RepairBeamRunResult:
    rounds: list[RepairBeamRound]
    states: list[RepairBeamState]
    accepted_states: list[RepairBeamState]
    terminal_results: list[Any] = field(default_factory=list)

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
        should_assess: ShouldAssessFn | None = None,
        min_improvement: float = 0.0,
    ):
        self.scheduler = scheduler
        self.beam_width = max(1, int(beam_width or 1))
        self.max_candidates_per_state = max_candidates_per_state
        self.max_analyze_candidates = max(1, int(max_analyze_candidates or 1))
        self.max_assess_candidates = max(1, int(max_assess_candidates or self.max_analyze_candidates))
        self.analyze = analyze or (lambda _candidate: {})
        self.assess = assess or (lambda _candidate: None)
        self.should_assess = should_assess or (lambda _item: True)
        self.min_improvement = max(0.0, float(min_improvement or 0.0))

    @classmethod
    def from_config(
        cls,
        scheduler: RepairScheduler,
        config: dict[str, Any],
        *,
        analyze: AnalyzeFn | None = None,
        assess: AssessFn | None = None,
        should_assess: ShouldAssessFn | None = None,
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
            should_assess=should_assess,
            min_improvement=float(beam.get("min_improvement", 0.0) or 0.0),
        )

    def run(self, states: list[RepairBeamState], *, max_rounds: int = 3) -> RepairBeamRunResult:
        frontier = list(states)
        rounds: list[RepairBeamRound] = []
        accepted: list[RepairBeamState] = []
        terminal_results: list[Any] = []
        best_completeness = max([float(state.completeness or 0.0) for state in frontier] or [0.0])
        for round_index in range(1, max(0, int(max_rounds or 0)) + 1):
            if not frontier:
                break
            round_result = self.expand_round(frontier, round_index=round_index)
            rounds.append(round_result)
            terminal_results.extend(round_result.terminal_results)
            accepted.extend(round_result.accepted_states)
            if round_result.accepted_states:
                return RepairBeamRunResult(
                    rounds=rounds,
                    states=round_result.states_out,
                    accepted_states=_top_states(accepted, self.beam_width),
                    terminal_results=terminal_results,
                )
            next_best = max([float(state.completeness or 0.0) for state in round_result.states_out] or [0.0])
            if round_index > 1 and next_best <= best_completeness + self.min_improvement:
                break
            best_completeness = max(best_completeness, next_best)
            frontier = round_result.states_out
        return RepairBeamRunResult(
            rounds=rounds,
            states=frontier,
            accepted_states=_top_states(accepted, self.beam_width),
            terminal_results=terminal_results,
        )

    def expand_round(self, states: list[RepairBeamState], *, round_index: int) -> RepairBeamRound:
        raw_candidates: list[RepairBeamCandidate] = []
        terminal_results: list[Any] = []
        for state in states:
            try:
                batch = self.scheduler.generate_repair_candidates(state.to_job(), lazy=True)
            except TypeError:
                batch = self.scheduler.generate_repair_candidates(state.to_job())
            if batch.terminal_result is not None:
                terminal_results.append(batch.terminal_result)
            candidates = list(batch.candidates)
            if self.max_candidates_per_state is not None:
                candidates = candidates[: max(0, int(self.max_candidates_per_state))]
            for candidate in candidates:
                raw_candidates.append(RepairBeamCandidate(
                    state=state,
                    candidate=candidate,
                    score=_candidate_pre_score(candidate, state),
                ))

        raw_candidates = _dedupe_generation_candidates(raw_candidates)
        ranked = sorted(raw_candidates, key=lambda item: item.score, reverse=True)
        analyzed = [
            _with_analyze(item, self.analyze(item.candidate))
            for item in ranked[: self.max_analyze_candidates]
        ]
        analyzed = sorted(analyzed, key=lambda item: item.score, reverse=True)
        analyzed = _dedupe_generation_candidates(analyzed)
        analyzed = [item for item in analyzed if self.should_assess(item)]
        assessment_window = _materialize_beam_items(analyzed[: self.max_assess_candidates])
        assessment_window = _dedupe_equivalent_candidates(assessment_window)
        assessment_window = sorted(assessment_window, key=lambda item: item.score, reverse=True)
        assessment_window = [item for item in assessment_window if self.should_assess(item)]
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
            terminal_results=terminal_results,
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
            state_key = _state_equivalence_key(state)
            if state_key in seen:
                continue
            seen.add(state_key)
            output.append(state)
            if len(output) >= self.beam_width:
                break
        return output


def _candidate_pre_score(candidate: RepairCandidate, state: RepairBeamState) -> float:
    selector_score = CandidateSelector.generation_priority(candidate)
    progress_score = candidate_progress_score(candidate)
    cost_penalty = candidate_cost_penalty(candidate)
    risk_penalty = candidate_risk_penalty(candidate)
    state_completeness = min(1.0, max(0.0, float(state.completeness or 0.0)))
    predicted_completeness = candidate_predicted_completeness(candidate)
    if predicted_completeness is None:
        predicted_gain = progress_score * max(0.1, 1.0 - state_completeness)
    else:
        predicted_gain = max(0.0, predicted_completeness - state_completeness)
    prior_score = min(1.0, max(0.0, state.score)) * 0.03
    prior_completeness = state_completeness * 0.04
    low_gain_penalty = 0.08 if state_completeness >= 0.2 and predicted_gain <= 0.01 and cost_penalty > 0.25 else 0.0
    return (
        selector_score
        + progress_score * 0.05
        + predicted_gain * 0.18
        + prior_score
        + prior_completeness
        - cost_penalty * 0.08
        - risk_penalty * 0.04
        - low_gain_penalty
    )


def _candidate_archive_state(candidate: RepairCandidate) -> dict[str, Any]:
    if not isinstance(candidate.plan, dict):
        return {}
    raw = candidate.plan.get("archive_state")
    return dict(raw) if isinstance(raw, dict) else {}


def _dedupe_equivalent_candidates(items: list[RepairBeamCandidate]) -> list[RepairBeamCandidate]:
    output: list[RepairBeamCandidate] = []
    seen: set[str] = set()
    for item in items:
        key = _candidate_equivalence_key(item)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _dedupe_generation_candidates(items: list[RepairBeamCandidate]) -> list[RepairBeamCandidate]:
    output: list[RepairBeamCandidate] = []
    seen: set[str] = set()
    for item in items:
        key = _candidate_generation_key(item)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _candidate_generation_key(item: RepairBeamCandidate) -> str:
    candidate_state = _candidate_archive_state(item.candidate)
    if candidate_state:
        digest = _stable_digest(_archive_state_equivalence_payload(candidate_state))
        return f"state:{digest}"
    repaired_input = item.candidate.repaired_input if isinstance(item.candidate.repaired_input, dict) else {}
    if repaired_input:
        digest = _stable_digest(_source_input_equivalence_payload(repaired_input))
        patch_digest = repaired_input.get("patch_digest") or ""
        return f"input:{digest}:{patch_digest}"
    if isinstance(item.candidate.plan, dict):
        patch_digest = item.candidate.plan.get("patch_digest") or ""
        return f"{item.candidate.module_name}:plan:{_stable_digest(item.candidate.plan)}:{patch_digest}"
    return f"{item.candidate.module_name}:{item.candidate.format}:{item.candidate.confidence}"


def _candidate_equivalence_key(item: RepairBeamCandidate) -> str:
    candidate_state = _candidate_archive_state(item.candidate)
    if candidate_state:
        return "state:" + _stable_digest(_archive_state_equivalence_payload(candidate_state))
    repaired_input = item.candidate.repaired_input if isinstance(item.candidate.repaired_input, dict) else {}
    if repaired_input:
        return "input:" + _stable_digest(_source_input_equivalence_payload(repaired_input))
    if isinstance(item.candidate.plan, dict):
        return "plan:" + _stable_digest(item.candidate.plan)
    return f"module:{item.candidate.module_name}:{item.candidate.format}:{item.candidate.confidence}"


def _state_equivalence_key(state: RepairBeamState) -> str:
    if state.archive_state:
        return "state:" + _stable_digest(_archive_state_equivalence_payload(state.archive_state))
    return "input:" + _stable_digest(_source_input_equivalence_payload(state.source_input))


def _archive_state_equivalence_payload(raw: dict[str, Any]) -> dict[str, Any]:
    source = raw.get("source") if isinstance(raw.get("source"), dict) else {}
    patches = []
    for patch in raw.get("patches") or raw.get("patch_stack") or []:
        if not isinstance(patch, dict):
            continue
        patches.append({
            "operations": [
                _patch_operation_equivalence_payload(operation)
                for operation in patch.get("operations") or []
                if isinstance(operation, dict)
            ],
        })
    return {
        "source": _source_input_equivalence_payload(source),
        "format_hint": raw.get("format_hint") or source.get("format_hint") or "",
        "logical_name": raw.get("logical_name") or source.get("logical_name") or "",
        "patches": patches,
    }


def _patch_operation_equivalence_payload(operation: dict[str, Any]) -> dict[str, Any]:
    return {
        "op": operation.get("op") or "replace_range",
        "target": operation.get("target") or "logical",
        "offset": int(operation.get("offset", 0) or 0),
        "size": operation.get("size"),
        "part_index": operation.get("part_index"),
        "data_b64": operation.get("data_b64") or "",
        "data_ref": operation.get("data_ref") or "",
    }


def _source_input_equivalence_payload(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": raw.get("kind") or raw.get("open_mode") or "",
        "entry_path": raw.get("entry_path") or raw.get("path") or raw.get("archive_path") or "",
        "open_mode": raw.get("open_mode") or "",
        "format_hint": raw.get("format_hint") or raw.get("format") or "",
        "parts": [
            _range_equivalence_payload(item)
            for item in raw.get("parts") or []
            if isinstance(item, dict)
        ],
        "ranges": [
            _range_equivalence_payload(item)
            for item in raw.get("ranges") or []
            if isinstance(item, dict)
        ],
        "segment": raw.get("segment") if isinstance(raw.get("segment"), dict) else None,
    }


def _range_equivalence_payload(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": item.get("path") or "",
        "role": item.get("role") or "",
        "volume_number": item.get("volume_number"),
        "start": item.get("start", item.get("start_offset")),
        "end": item.get("end", item.get("end_offset")),
    }


def _stable_digest(payload: Any) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


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
    score = _verification_score_with_assessment(item.score, payload)
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
            "archive_coverage": {
                "completeness": assessment.archive_coverage.completeness,
                "file_coverage": assessment.archive_coverage.file_coverage,
                "byte_coverage": assessment.archive_coverage.byte_coverage,
                "expected_files": assessment.archive_coverage.expected_files,
                "matched_files": assessment.archive_coverage.matched_files,
                "complete_files": assessment.archive_coverage.complete_files,
                "partial_files": assessment.archive_coverage.partial_files,
                "failed_files": assessment.archive_coverage.failed_files,
                "missing_files": assessment.archive_coverage.missing_files,
                "unverified_files": assessment.archive_coverage.unverified_files,
                "expected_bytes": assessment.archive_coverage.expected_bytes,
                "matched_bytes": assessment.archive_coverage.matched_bytes,
                "complete_bytes": assessment.archive_coverage.complete_bytes,
                "confidence": assessment.archive_coverage.confidence,
                "sources": list(assessment.archive_coverage.sources),
            },
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


def _verification_score_with_assessment(base_score: float, assessment: dict[str, Any]) -> float:
    verification_score = score_verification_payload(assessment)
    return verification_score + min(1.0, max(0.0, base_score)) * 0.01


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
    if state.decision_hint == DECISION_ACCEPT:
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
