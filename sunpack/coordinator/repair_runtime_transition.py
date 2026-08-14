from __future__ import annotations

from copy import deepcopy
from contextlib import nullcontext
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair_inspection import RepairInspectionService
from sunpack.coordinator.verification_stage import verify_and_project
from sunpack.contracts.extraction import ExtractionResult
from sunpack.extraction.knowledge import write_extraction_result
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.repair.candidate import RepairCandidate
from sunpack.repair.knowledge import write_repair_result
from sunpack.verification import VerificationResult, VerificationScheduler
from sunpack.contracts.verification import DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL, DECISION_REPAIR, CONTENT_INTEGRITY_UNKNOWN
from sunpack.support.output_cleanup import DEFAULT_OUTPUT_CLEANUP_MANAGER, OutputCleanupEvent, OutputRole


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
    inspection_feedback: dict[str, Any] | None = None


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
        repair_inspection_service: RepairInspectionService | None = None,
        light_verify: Callable[[ArchiveTask, ExtractionResult], VerificationResult] | None = None,
        needs_full_verification: Callable[[RepairCandidate, VerificationResult], bool] | None = None,
        source_digest: Callable[[dict[str, Any]], str] | None = None,
    ):
        self.extractor = extractor
        self.verifier = verifier
        self.repair_stage = repair_stage
        self.repair_inspection_service = repair_inspection_service
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
        inspect_candidate: bool = False,
        record_repair_history: bool = False,
        phase_timer: Callable[..., Any] | None = None,
        state_id: str = "",
        candidate_id: str = "",
    ) -> RepairRuntimeTransition:
        original_state = task.archive_state()
        original_knowledge = task.knowledge().to_dict()
        temp_dir = str(temp_dir)
        with _phase(phase_timer, "transition_cleanup", state_id=state_id, candidate_id=candidate_id):
            DEFAULT_OUTPUT_CLEANUP_MANAGER.cleanup_scoped_path(
                temp_dir,
                event=OutputCleanupEvent.BEAM_CANDIDATE_PREPARE,
                role=OutputRole.BEAM_CANDIDATE,
                workspace_root=str(Path(temp_dir).parent),
            )
        with _phase(phase_timer, "transition_source_digest", state_id=state_id, candidate_id=candidate_id):
            digest = self._candidate_source_digest(candidate)
        try:
            inspection_feedback = None
            if record_repair_history:
                with _phase(phase_timer, "transition_record_history", state_id=state_id, candidate_id=candidate_id):
                    self.record_candidate_repair(task, candidate, phase_timer=phase_timer)
            with _phase(phase_timer, "transition_apply_candidate", state_id=state_id, candidate_id=candidate_id):
                self.apply_candidate_to_task(task, candidate, phase_timer=phase_timer)
            if inspect_candidate and self.repair_inspection_service is not None:
                with _phase(phase_timer, "transition_inspect_candidate", state_id=state_id, candidate_id=candidate_id):
                    try:
                        inspection_feedback = self.repair_inspection_service.feedback_for_task(
                            task,
                            use_cache=True,
                        ).to_score_payload()
                    except Exception as exc:
                        inspection_feedback = {
                            "status": "error",
                            "error": str(exc),
                        }
            if refresh_analysis and self.repair_inspection_service is not None:
                with _phase(phase_timer, "transition_inspection_refresh", state_id=state_id, candidate_id=candidate_id):
                    self.repair_inspection_service.refresh_task(
                        task,
                        phase_timer=phase_timer,
                        phase_prefix="transition_inspection_refresh",
                    )
            with _phase(phase_timer, "transition_extract", state_id=state_id, candidate_id=candidate_id):
                extracted = _extract_with_timer(
                    self.extractor,
                    task,
                    temp_dir,
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
                inspection_feedback=inspection_feedback,
            )
        finally:
            if restore:
                with _phase(phase_timer, "transition_restore", state_id=state_id, candidate_id=candidate_id):
                    task.set_archive_state(original_state, phase_timer=phase_timer, phase_prefix="transition_restore_set_archive_state")
                    task.set_knowledge(original_knowledge)

    def apply_candidate_to_task(self, task: ArchiveTask, candidate: RepairCandidate, *, phase_timer: Callable[..., Any] | None = None) -> None:
        archive_state = candidate.plan.get("archive_state") if isinstance(candidate.plan, dict) else None
        if isinstance(archive_state, dict):
            task.set_archive_state(archive_state, phase_timer=phase_timer, phase_prefix="transition_apply_candidate_set_archive_state")
            return
        descriptor = self.repair_stage._descriptor_from_repaired_input(task, candidate.repaired_input)
        if descriptor is not None:
            task.set_archive_state(
                ArchiveState.from_archive_input(descriptor),
                phase_timer=phase_timer,
                phase_prefix="transition_apply_candidate_set_archive_state",
            )
            return
        task.set_archive_input(candidate.repaired_input)

    def record_candidate_repair(self, task: ArchiveTask, candidate: RepairCandidate, *, phase_timer: Callable[..., Any] | None = None) -> None:
        result = candidate.to_result(selection={"selected_candidate_id": self._candidate_id(candidate)})
        append_history = getattr(self.repair_stage, "_append_repair_history", None)
        if callable(append_history):
            write_repair_result(
                task,
                result,
                phase="history",
                archive_repaired=True if result.ok else None,
                phase_timer=phase_timer,
                phase_prefix="transition_record_history_write_repair",
            )
        else:
            write_repair_result(
                task,
                result,
                phase="runtime_transition",
                archive_repaired=True if result.ok else None,
                phase_timer=phase_timer,
                phase_prefix="transition_record_history_write_repair",
            )

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
            content_integrity=CONTENT_INTEGRITY_UNKNOWN,
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


def _extract_with_timer(
    extractor: Any,
    task: ArchiveTask,
    out_dir: str,
    *,
    phase_timer: Callable[..., Any] | None,
    phase_prefix: str,
) -> ExtractionResult:
    return extractor.extract(
        task,
        out_dir,
        phase_timer=phase_timer,
        phase_prefix=phase_prefix,
    )


def _verify_with_optional_timer(verifier: Any, task: ArchiveTask, extracted: ExtractionResult, *, phase_timer: Callable[..., Any] | None, phase_prefix: str) -> VerificationResult:
    try:
        return verify_and_project(verifier, task, extracted, phase_timer=phase_timer, phase_prefix=phase_prefix)
    except TypeError as exc:
        if "phase_timer" not in str(exc) and "phase_prefix" not in str(exc):
            raise
        return verify_and_project(verifier, task, extracted)


def clone_archive_task(task: ArchiveTask, *, key_suffix: str = "") -> ArchiveTask:
    bag = FactBag()
    knowledge_payload = task.fact_bag.get("archive.knowledge")
    if not isinstance(knowledge_payload, dict):
        knowledge_payload = task.knowledge().to_dict()
    state_payload = task.fact_bag.get("archive.state")
    if not isinstance(state_payload, dict):
        state_payload = task.archive_state().to_dict()
        state_payload.pop("knowledge", None)
    bag.set("archive.knowledge", deepcopy(knowledge_payload))
    bag.set("archive.state", deepcopy(state_payload))
    for key in (
        "archive.input",
        "archive.descriptor.source",
        "archive.source",
        "archive.patch_stack",
        "archive.patch_digest",
        "file.path",
        "file.detected_ext",
        "candidate.entry_path",
        "candidate.member_paths",
        "candidate.carrier_path",
        "candidate.companion_paths",
        "candidate.cleanup_paths",
        "candidate.logical_name",
        "relation.split_volumes",
    ):
        value = task.fact_bag.get(key)
        if value is not None:
            bag.set(key, deepcopy(value))
    cloned = ArchiveTask(
        fact_bag=bag,
        score=task.score,
        key=f"{task.key}{key_suffix}" if key_suffix else task.key,
        main_path=task.main_path,
        all_parts=list(task.all_parts or []),
        carrier_path=task.carrier_path,
        cleanup_parts=list(task.cleanup_parts or []),
        logical_name=task.logical_name,
        split_info=type(task.split_info)(
            is_split=task.split_info.is_split,
            is_sfx_stub=task.split_info.is_sfx_stub,
            archive_input=task.split_info.archive_input,
            source=task.split_info.source,
        ),
        decision=task.decision,
        stop_reason=task.stop_reason,
        matched_rules=list(task.matched_rules or []),
        detected_ext=task.detected_ext,
    )
    return cloned
