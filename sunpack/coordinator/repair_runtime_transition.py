from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.result import ExtractionResult
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.repair.candidate import RepairCandidate
from sunpack.verification import VerificationResult, VerificationScheduler
from sunpack.verification.result import DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL


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
        runtime_scheduler: Any = None,
        light_verify: Callable[[ArchiveTask, ExtractionResult], VerificationResult] | None = None,
        needs_full_verification: Callable[[RepairCandidate, VerificationResult], bool] | None = None,
        source_digest: Callable[[dict[str, Any]], str] | None = None,
    ):
        self.extractor = extractor
        self.verifier = verifier
        self.repair_stage = repair_stage
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
    ) -> RepairRuntimeTransition:
        original_state = task.archive_state()
        temp_dir = str(temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
        digest = self._candidate_source_digest(candidate)
        try:
            self.apply_candidate_to_task(task, candidate)
            extracted = self.extractor.extract(task, temp_dir, runtime_scheduler=self.runtime_scheduler)
            light = self.light_verify(task, extracted) if self.light_verify is not None else self.verifier.verify(task, extracted)
            if self.needs_full_verification is not None and not self.needs_full_verification(candidate, light):
                assessed = light
            elif light is not None and self.light_verify is not None:
                assessed = self.verifier.verify(task, extracted)
            else:
                assessed = light
            terminal_reason = self.terminal_reason(extracted, assessed)
            return RepairRuntimeTransition(
                candidate=candidate,
                result=extracted,
                verification=assessed,
                temp_dir=temp_dir,
                source_digest=digest,
                terminal_reason=terminal_reason,
                can_continue_repair=assessed.decision_hint not in {DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL},
                accepted_complete=assessed.decision_hint == DECISION_ACCEPT,
                accepted_partial=assessed.decision_hint == DECISION_ACCEPT_PARTIAL,
            )
        finally:
            task.set_archive_state(original_state)

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

    def _candidate_source_digest(self, candidate: RepairCandidate) -> str:
        if isinstance(candidate.plan, dict) and candidate.plan.get("archive_state"):
            return self.source_digest({"archive_state": candidate.plan.get("archive_state")})
        return self.source_digest(candidate.repaired_input)

    @staticmethod
    def terminal_reason(result: ExtractionResult, verification: VerificationResult) -> str:
        if verification.decision_hint == DECISION_ACCEPT:
            return "complete"
        if verification.decision_hint == DECISION_ACCEPT_PARTIAL:
            return "verification_accept_partial"
        if not result.success and result.error:
            return str(result.error)
        return str(verification.decision_hint or verification.assessment_status or "repair_required")


def _default_source_digest(source: dict[str, Any]) -> str:
    import hashlib
    import json

    try:
        payload = json.dumps(source or {}, sort_keys=True, ensure_ascii=False, default=str)
    except TypeError:
        payload = str(source)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
