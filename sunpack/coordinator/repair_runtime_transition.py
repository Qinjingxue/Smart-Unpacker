from __future__ import annotations

import shutil
from contextlib import nullcontext
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.analysis_stage import ArchiveAnalysisStage
from sunpack.extraction.result import ExtractionResult
from sunpack.extraction.knowledge import write_extraction_result
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.knowledge import write_repair_archive_status, write_repair_result
from sunpack.verification import VerificationResult, VerificationScheduler
from sunpack.verification.result import DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL, DECISION_REPAIR, SOURCE_INTEGRITY_DAMAGED


@dataclass
class RepairRuntimeTransition:
    candidate: RepairCandidate
    result: ExtractionResult
    verification: VerificationResult
    temp_dir: str
    source_digest: str = ""
    terminal_reason: str = ""
    can_continue_repair: bool = False
    accepted_complete: bool = False
    accepted_partial: bool = False
    task_snapshot: dict[str, Any] | None = None


class RepairRuntimeTransitionEvaluator:
    """Evaluate one repair candidate through the same runtime path as production.

    The evaluator intentionally owns only the candidate transition:
    apply the candidate to the task, run extraction, run verification, then restore
    the original task archive state. Coordinator beam, training collection, and
    runtime A/B tooling can all share this path without reimplementing state
    mutation or verification shortcuts.
    """

    def __init__(
        self,
        *,
        extractor: ExtractionScheduler,
        verifier: VerificationScheduler,
        repair_stage: Any,
        analysis_stage: ArchiveAnalysisStage | None = None,
        runtime_scheduler: Any = None,
        light_verify: Callable[[ArchiveTask, ExtractionResult], VerificationResult] | None = None,
        needs_full_verification: Callable[[RepairCandidate, VerificationResult], bool] | None = None,
        source_digest: Callable[[dict[str, Any]], str] | None = None,
    ):
        self.extractor = extractor
        self.verifier = verifier
        self.repair_stage = repair_stage
        self.analysis_stage = analysis_stage
        self.runtime_scheduler = runtime_scheduler
        self.light_verify = light_verify
        self.needs_full_verification = needs_full_verification
        self.source_digest = source_digest or _default_source_digest

    def evaluate(
        self,
        task: ArchiveTask,
        candidate: RepairCandidate,
        *,
        temp_dir: str | Path,
        restore: bool = True,
        refresh_analysis: bool = False,
        record_repair_history: bool = False,
        phase_timer: Callable[..., Any] | None = None,
        state_id: str = "",
        candidate_id: str = "",
    ) -> RepairRuntimeTransition:
        original_state = task.archive_state()
        original_knowledge = task.knowledge().to_dict()
        temp_dir = str(temp_dir)
        with _phase(phase_timer, "transition_cleanup", state_id=state_id, candidate_id=candidate_id):
            shutil.rmtree(temp_dir, ignore_errors=True)
        with _phase(phase_timer, "transition_source_digest", state_id=state_id, candidate_id=candidate_id):
            digest = self._candidate_source_digest(candidate)
        try:
            if record_repair_history:
                with _phase(phase_timer, "transition_record_history", state_id=state_id, candidate_id=candidate_id):
                    self.record_candidate_repair(task, candidate, phase_timer=phase_timer)
            with _phase(phase_timer, "transition_apply_candidate", state_id=state_id, candidate_id=candidate_id):
                self.apply_candidate_to_task(task, candidate)
            if refresh_analysis and self.analysis_stage is not None:
                with _phase(phase_timer, "transition_analysis_refresh", state_id=state_id, candidate_id=candidate_id):
                    self.analysis_stage.refresh_task_analysis(task, phase_timer=phase_timer, phase_prefix="transition_analysis_refresh")
            with _phase(phase_timer, "transition_extract", state_id=state_id, candidate_id=candidate_id):
                extracted = self.extractor.extract(
                    task,
                    temp_dir,
                    runtime_scheduler=self.runtime_scheduler,
                    phase_timer=phase_timer,
                    phase_prefix="transition_extract",
                )
            with _phase(phase_timer, "transition_write_extraction_knowledge", state_id=state_id, candidate_id=candidate_id):
                write_extraction_result(task, extracted, phase_timer=phase_timer, phase_prefix="transition_write_extraction")
            with _phase(phase_timer, "transition_verify", state_id=state_id, candidate_id=candidate_id):
                light = self.light_verify(task, extracted) if self.light_verify is not None else _verify_with_optional_timer(self.verifier, task, extracted, phase_timer=phase_timer, phase_prefix="transition_verify")
                if self.needs_full_verification is not None and not self.needs_full_verification(candidate, light):
                    assessed = light
                elif light is not None and self.light_verify is not None:
                    assessed = _verify_with_optional_timer(self.verifier, task, extracted, phase_timer=phase_timer, phase_prefix="transition_full_verify")
                else:
                    assessed = light
            with _phase(phase_timer, "transition_normalize_verification", state_id=state_id, candidate_id=candidate_id):
                assessed = self.normalize_transition_verification(extracted, assessed)
            with _phase(phase_timer, "transition_terminal_reason", state_id=state_id, candidate_id=candidate_id):
                terminal_reason = self.terminal_reason(extracted, assessed)
            return RepairRuntimeTransition(
                candidate=candidate,
                result=extracted,
                verification=assessed,
                temp_dir=temp_dir,
                source_digest=digest,
                terminal_reason=terminal_reason,
                can_continue_repair=self.can_continue_repair(extracted, assessed),
                accepted_complete=self.accepts_complete(extracted, assessed),
                accepted_partial=assessed.decision_hint == DECISION_ACCEPT_PARTIAL,
                task_snapshot=task.knowledge().to_dict(),
            )
        finally:
            if restore:
                with _phase(phase_timer, "transition_restore", state_id=state_id, candidate_id=candidate_id):
                    task.set_archive_state(original_state)
                    task.set_knowledge(original_knowledge)

    def apply_candidate_to_task(self, task: ArchiveTask, candidate: RepairCandidate) -> None:
        archive_state = candidate.plan.get("archive_state") if isinstance(candidate.plan, dict) else None
        if isinstance(archive_state, dict):
            task.set_archive_state(archive_state)
            return
        descriptor = self.repair_stage._descriptor_from_repaired_input(task, candidate.repaired_input)
        if descriptor is not None:
            task.set_archive_state(ArchiveState.from_archive_input(descriptor))
            return
        task.set_archive_input(candidate.repaired_input)

    def record_candidate_repair(self, task: ArchiveTask, candidate: RepairCandidate, *, phase_timer: Callable[..., Any] | None = None) -> None:
        result = candidate.to_result(selection={"selected_candidate_id": self._candidate_id(candidate)})
        append_history = getattr(self.repair_stage, "_append_repair_history", None)
        if callable(append_history):
            write_repair_result(task, result, phase="history", phase_timer=phase_timer, phase_prefix="transition_record_history_write_repair")
        else:
            write_repair_result(task, result, phase="runtime_transition", phase_timer=phase_timer, phase_prefix="transition_record_history_write_repair")
        if result.ok:
            with _phase(phase_timer, "transition_record_history_archive_status"):
                write_repair_archive_status(task, repaired=True)

    def _candidate_source_digest(self, candidate: RepairCandidate) -> str:
        if isinstance(candidate.plan, dict) and candidate.plan.get("archive_state"):
            return self.source_digest({"archive_state": candidate.plan.get("archive_state")})
        return self.source_digest(candidate.repaired_input)

    @staticmethod
    def _candidate_id(candidate: RepairCandidate) -> str:
        try:
            from sunpack.repair.candidate import candidate_feature_payload

            return str(candidate_feature_payload(candidate).get("candidate_id") or "")
        except Exception:
            return ""

    @staticmethod
    def terminal_reason(result: ExtractionResult, verification: VerificationResult) -> str:
        if RepairRuntimeTransitionEvaluator.accepts_complete(result, verification):
            return "complete"
        if verification.decision_hint == DECISION_ACCEPT_PARTIAL:
            return "verification_accept_partial"
        if not result.success and result.error:
            return str(result.error)
        return str(verification.decision_hint or verification.assessment_status or "repair_required")

    @staticmethod
    def accepts_complete(result: ExtractionResult, verification: VerificationResult) -> bool:
        return bool(result.success and verification.decision_hint == DECISION_ACCEPT)

    @staticmethod
    def can_continue_repair(result: ExtractionResult, verification: VerificationResult) -> bool:
        return bool(verification.decision_hint == DECISION_REPAIR)

    @staticmethod
    def normalize_transition_verification(result: ExtractionResult, verification: VerificationResult) -> VerificationResult:
        """Match the production loop's repair gate for failed extractions.

        The main ExtractionBatchRunner only accepts a complete verification as
        terminal when extraction itself succeeded. A damaged extraction can still
        produce a superficially complete verification when the oracle/coverage is
        empty, but production keeps repairing that state. Training transitions
        must expose the same decision so candidate graph expansion matches the
        real loop.
        """
        if result.success or verification.decision_hint != DECISION_ACCEPT:
            return verification
        if not (result.error or result.partial_outputs or result.files_written or result.bytes_written):
            return verification
        return replace(
            verification,
            decision_hint=DECISION_REPAIR,
            source_integrity=SOURCE_INTEGRITY_DAMAGED,
            recoverable_upper_bound=min(float(verification.recoverable_upper_bound or 1.0), 0.99),
        )


def _default_source_digest(source: dict[str, Any]) -> str:
    import hashlib
    import json

    try:
        payload = json.dumps(source or {}, sort_keys=True, ensure_ascii=False, default=str)
    except TypeError:
        payload = str(source)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def _phase(timer: Callable[..., Any] | None, name: str, *, state_id: str = "", candidate_id: str = ""):
    if timer is None:
        return nullcontext()
    return timer(name, state_id=state_id, candidate_id=candidate_id)


def _verify_with_optional_timer(verifier: Any, task: ArchiveTask, extracted: ExtractionResult, *, phase_timer: Callable[..., Any] | None, phase_prefix: str) -> VerificationResult:
    try:
        return verifier.verify(task, extracted, phase_timer=phase_timer, phase_prefix=phase_prefix)
    except TypeError as exc:
        if "phase_timer" not in str(exc) and "phase_prefix" not in str(exc):
            raise
        return verifier.verify(task, extracted)


def clone_archive_task(task: ArchiveTask, *, key_suffix: str = "") -> ArchiveTask:
    bag = FactBag()
    for key, value in task.fact_bag.to_dict().items():
        bag.set(key, value)
    cloned = ArchiveTask(
        fact_bag=bag,
        score=task.score,
        key=f"{task.key}{key_suffix}" if key_suffix else task.key,
        main_path=task.main_path,
        all_parts=list(task.all_parts or []),
        logical_name=task.logical_name,
        split_info=type(task.split_info)(
            is_split=task.split_info.is_split,
            is_sfx_stub=task.split_info.is_sfx_stub,
            parts=list(task.split_info.parts or []),
            preferred_entry=task.split_info.preferred_entry,
            source=task.split_info.source,
            volumes=list(task.split_info.volumes or []),
        ),
        decision=task.decision,
        stop_reason=task.stop_reason,
        matched_rules=list(task.matched_rules or []),
        detected_ext=task.detected_ext,
    )
    cloned.set_knowledge(task.knowledge().to_dict())
    cloned.set_archive_state(task.archive_state())
    return cloned
