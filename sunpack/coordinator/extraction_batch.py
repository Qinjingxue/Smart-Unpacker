import os
import shutil
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List

from sunpack.contracts.run_context import RunContext
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.analysis_stage import ArchiveAnalysisStage
from sunpack.coordinator.repair_beam import RepairBeamCandidate, RepairBeamLoop, RepairBeamState
from sunpack.coordinator.repair_loop import RepairLoopLimits, RepairLoopState, terminal_failure_reason
from sunpack.coordinator.repair_stage import ArchiveRepairStage
from sunpack.coordinator.resource_preflight import ResourcePreflightInspector
from sunpack.coordinator.scheduling import (
    ConcurrencyScheduler,
    TaskExecutor,
    build_scheduler_profile_config,
    resolve_max_workers,
)
from sunpack.detection import NestedOutputScanPolicy
from sunpack.extraction.result import ExtractionResult
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.extraction.progress import filter_extraction_manifest_payload, filter_extraction_outputs
from sunpack.rename.scheduler import RenameScheduler
from sunpack.repair.candidate import RepairCandidate
from sunpack.verification import RecoveryAttempt, VerificationResult, VerificationScheduler, compare_attempts, rank_attempt
from sunpack.verification.result import DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL, DECISION_REPAIR, DECISION_RETRY_EXTRACT
from sunpack.support.path_keys import absolute_path_key


@dataclass
class BatchExtractionOutcome:
    result: ExtractionResult
    verification: VerificationResult | None = None
    attempts: int = 1
    attempt_id: str = ""
    attempt_source: str = "original"
    repair_module: str = ""
    round_index: int = 0
    archive_state_payload: dict[str, Any] | None = None
    patch_digest: str = ""
    patch_lineage: list[dict[str, Any]] = field(default_factory=list)
    recovery_rank: dict[str, Any] = field(default_factory=dict)
    comparison: dict[str, Any] = field(default_factory=dict)
    rejected_attempts: list[dict[str, Any]] = field(default_factory=list)

    @property
    def success(self) -> bool:
        if not self.result.success:
            if terminal_failure_reason(self.result):
                return False
            return _verification_accepts_partial(self.verification)
        return self.verification is None or _verification_accepts(self.verification)


@dataclass
class _IndexedStageTask:
    index: int
    task: ArchiveTask
    resource_token_cost: int = 1

    @property
    def fact_bag(self):
        return self.task.fact_bag

    @property
    def main_path(self) -> str:
        return self.task.main_path

    @property
    def all_parts(self) -> list[str]:
        return self.task.all_parts


@dataclass
class _BeamRepairEvaluation:
    candidate: RepairCandidate
    result: ExtractionResult
    verification: VerificationResult
    temp_dir: str
    repair_result: Any
    outcome: BatchExtractionOutcome


@dataclass
class _BeamRepairTerminal:
    repair_result: Any


class ExtractionBatchRunner:
    def __init__(
        self,
        context: RunContext,
        extractor: ExtractionScheduler,
        output_scan_policy: NestedOutputScanPolicy,
        rename_scheduler: RenameScheduler | None = None,
        config: dict | None = None,
    ):
        self.context = context
        self.extractor = extractor
        self.output_scan_policy = output_scan_policy
        self.rename_scheduler = rename_scheduler or RenameScheduler()
        self.config = config or {}
        self.scheduler_config = self._build_scheduler_config(self.config)
        self.max_workers = resolve_max_workers()
        self.analysis_stage = ArchiveAnalysisStage(self.config)
        self.repair_stage = ArchiveRepairStage(self.config)
        self.repair_loop_limits = RepairLoopLimits.from_config(self.repair_stage.config)
        self.verifier = VerificationScheduler(self.config, password_session=self.extractor.password_session)
        performance = self.config.get("performance", {}) if isinstance(self.config.get("performance"), dict) else {}
        self.resource_inspector = ResourcePreflightInspector(
            password_session=self.extractor.password_session,
            rename_scheduler=self.rename_scheduler,
            precise_resource_min_size_mb=performance.get("precise_resource_min_size_mb", 256),
        )

    def prepare_tasks(self, tasks: List[ArchiveTask]):
        path_map = self.rename_scheduler.apply_renames(tasks)
        if path_map:
            for task in tasks:
                task.apply_path_mapping(path_map)

    def execute(self, tasks: List[ArchiveTask]) -> List[str]:
        if not tasks:
            return []

        self.prepare_tasks(tasks)
        tasks = self.analysis_stage.analyze_tasks(tasks)
        output_dir_resolver = self.rename_scheduler.build_output_dir_resolver(
            tasks,
            self.extractor.default_output_dir_for_task,
        )
        output_dir_resolver = self._cached_output_dir_resolver(output_dir_resolver)
        tasks = self._skip_tasks_inside_batch_outputs(tasks, output_dir_resolver)
        results = self._execute_ready_tasks(tasks, output_dir_resolver)

        output_dirs = []
        for task, outcome in results:
            output_dir = self.collect_result(task, outcome)
            if output_dir:
                output_dirs.append(output_dir)
        return self.output_scan_policy.scan_roots_from_outputs(output_dirs)

    def _execute_ready_tasks(self, tasks: List[ArchiveTask], output_dir_resolver) -> list[tuple[ArchiveTask, BatchExtractionOutcome]]:
        ready_tasks: list[ArchiveTask] = []
        skipped_results: list[tuple[ArchiveTask, BatchExtractionOutcome]] = []
        for _index, task, _out_dir, preflight in self._inspect_tasks_before_extract(tasks, output_dir_resolver):
            if preflight.skip_result is not None:
                skipped_results.append((task, BatchExtractionOutcome(preflight.skip_result)))
                continue
            ready_tasks.append(task)

        if not ready_tasks:
            return skipped_results
        if len(ready_tasks) == 1:
            guard_enabled = bool(self._resource_guard_config().get("enabled", False))
            if guard_enabled or isinstance(ready_tasks[0].fact_bag.get("resource.analysis"), dict):
                self.resource_inspector.inspect(ready_tasks[0])
            else:
                self.resource_inspector.record_estimated_single_task_profile(ready_tasks[0])
        else:
            self._inspect_resource_profiles(ready_tasks)
        guarded_results = self._resource_guard_results(ready_tasks, output_dir_resolver)
        if guarded_results:
            guarded = {id(task) for task, _outcome in guarded_results}
            ready_tasks = [task for task in ready_tasks if id(task) not in guarded]
            skipped_results.extend(guarded_results)
        if not ready_tasks:
            return skipped_results

        initial_limit = self.scheduler_config.get("initial_concurrency_limit", 4)
        scheduler = ConcurrencyScheduler(
            self.scheduler_config,
            current_limit=initial_limit,
            max_workers=self.max_workers,
        )
        executor = TaskExecutor(scheduler, max_workers=self.max_workers)
        return skipped_results + executor.execute_all(
            ready_tasks,
            lambda task, runtime_scheduler: (
                task,
                self._extract_verify_with_retries(task, output_dir_resolver(task), runtime_scheduler),
            ),
        )

    @staticmethod
    def _cached_output_dir_resolver(output_dir_resolver):
        cache: dict[int, str] = {}

        def resolve(task: ArchiveTask) -> str:
            key = id(task)
            if key not in cache:
                cache[key] = output_dir_resolver(task)
            return cache[key]

        return resolve

    def _resource_guard_results(self, tasks: list[ArchiveTask], output_dir_resolver) -> list[tuple[ArchiveTask, BatchExtractionOutcome]]:
        guard = self._resource_guard_config()
        if not guard or not bool(guard.get("enabled", False)):
            return []
        results: list[tuple[ArchiveTask, BatchExtractionOutcome]] = []
        for task in tasks:
            analysis = task.fact_bag.get("resource.analysis")
            if not isinstance(analysis, dict):
                continue
            violations = _resource_guard_violations(analysis, guard)
            if not violations:
                continue
            guard_payload = {
                "status": "guarded",
                "violations": violations,
                "policy": {
                    "max_file_count": guard.get("max_file_count"),
                    "max_total_unpacked_size": guard.get("max_total_unpacked_size"),
                    "max_largest_item_size": guard.get("max_largest_item_size"),
                    "max_compression_ratio": guard.get("max_compression_ratio"),
                },
            }
            task.fact_bag.set("resource.guard", guard_payload)
            out_dir = output_dir_resolver(task)
            result = ExtractionResult(
                success=False,
                archive=task.main_path,
                out_dir=out_dir,
                all_parts=task.all_parts,
                error="resource_guard",
                diagnostics={
                    "result": {
                        "status": "failed",
                        "native_status": "guarded",
                        "failure_stage": "preflight",
                        "failure_kind": "resource_guard",
                        "guard_status": "guarded",
                        "resource_guard": guard_payload,
                    }
                },
            )
            results.append((task, BatchExtractionOutcome(result=result)))
        return results

    def _resource_guard_config(self) -> dict:
        performance = self.config.get("performance") if isinstance(self.config.get("performance"), dict) else {}
        guard = performance.get("resource_guard") if isinstance(performance.get("resource_guard"), dict) else {}
        return dict(guard)

    def _build_scheduler_config(self, config: dict) -> dict:
        performance = config.get("performance", {}) if isinstance(config.get("performance"), dict) else {}
        scheduler_config = build_scheduler_profile_config(performance.get("scheduler_profile", "auto"))
        scheduler_config.update({
            key: value
            for key, value in performance.items()
            if key != "scheduler_profile" and value is not None
        })
        return scheduler_config

    def _inspect_tasks_before_extract(self, tasks: list[ArchiveTask], output_dir_resolver) -> list[tuple[int, ArchiveTask, str, Any]]:
        max_workers = self._stage_max_workers(
            enabled_key="parallel_preflight_inspect",
            workers_key="preflight_inspect_max_workers",
            task_count=len(tasks),
            default_workers=4,
        )
        if max_workers <= 1:
            results = []
            for index, task in enumerate(tasks):
                out_dir = output_dir_resolver(task)
                results.append((index, task, out_dir, self.extractor.inspect(task, out_dir)))
            return results

        indexed = [_IndexedStageTask(index, task) for index, task in enumerate(tasks)]

        def inspect_one(item: _IndexedStageTask):
            out_dir = output_dir_resolver(item.task)
            return item.index, item.task, out_dir, self.extractor.inspect(item.task, out_dir)

        results = self._execute_indexed_stage(indexed, max_workers=max_workers, worker=inspect_one)
        return sorted(results, key=lambda item: item[0])

    def _inspect_resource_profiles(self, tasks: list[ArchiveTask]) -> None:
        max_workers = self._stage_max_workers(
            enabled_key="parallel_resource_preflight",
            workers_key="resource_preflight_max_workers",
            task_count=len(tasks),
            default_workers=4,
        )
        if max_workers <= 1:
            for task in tasks:
                self.resource_inspector.inspect(task)
            return

        indexed = [_IndexedStageTask(index, task) for index, task in enumerate(tasks)]
        self._execute_indexed_stage(
            indexed,
            max_workers=max_workers,
            worker=lambda item: (item.index, self.resource_inspector.inspect(item.task)),
        )

    def _execute_indexed_stage(self, tasks: list[_IndexedStageTask], *, max_workers: int, worker) -> list[Any]:
        scheduler_config = dict(self.scheduler_config)
        scheduler_config["initial_concurrency_limit"] = max_workers
        scheduler = ConcurrencyScheduler(
            scheduler_config,
            current_limit=max_workers,
            max_workers=max_workers,
        )
        executor = TaskExecutor(scheduler, max_workers=max_workers)
        return executor.execute_all(tasks, worker)

    def _stage_max_workers(
        self,
        *,
        enabled_key: str,
        workers_key: str,
        task_count: int,
        default_workers: int,
    ) -> int:
        if task_count <= 1 or self.max_workers <= 1:
            return 1
        performance = self.config.get("performance", {}) if isinstance(self.config.get("performance"), dict) else {}
        profile = str(performance.get("scheduler_profile") or self.scheduler_config.get("scheduler_profile") or "").lower()
        resolved_profile = str(self.scheduler_config.get("resolved_scheduler_profile") or "").lower()
        if profile == "single" or resolved_profile == "single":
            return 1
        if not bool(performance.get(enabled_key, True)):
            return 1
        configured = performance.get(workers_key)
        try:
            worker_limit = int(configured) if configured is not None else int(default_workers)
        except (TypeError, ValueError):
            worker_limit = int(default_workers)
        return max(1, min(int(task_count), int(self.max_workers), max(1, worker_limit)))

    def _extract_verify_with_retries(
        self,
        task: ArchiveTask,
        out_dir: str,
        runtime_scheduler: ConcurrencyScheduler,
    ) -> BatchExtractionOutcome:
        verification_config = self.verifier.config
        max_verification_retries = max(0, int(verification_config.get("max_retries", 0) or 0))
        cleanup_failed_output = bool(verification_config.get("cleanup_failed_output", True))
        attempts = max_verification_retries + 1
        last_outcome: BatchExtractionOutcome | None = None
        incumbent_outcome: BatchExtractionOutcome | None = None

        attempt_index = 0
        attempt_sequence = 0
        while attempt_index < attempts:
            result = self.extractor.extract(task, out_dir, runtime_scheduler=runtime_scheduler)
            current_sequence = attempt_sequence
            attempt_sequence += 1
            if not result.success:
                verification = self.verifier.verify(task, result)
                current_outcome = BatchExtractionOutcome(
                    result=result,
                    verification=verification,
                    attempts=attempt_index + 1,
                )
                self._annotate_recovery_outcome(task, current_outcome, source="original", round_index=current_sequence)
                incumbent_outcome = self._select_better_recovery_outcome(
                    incumbent_outcome,
                    current_outcome,
                )
                if _verification_accepts(verification):
                    selected = self._selected_acceptable_outcome(incumbent_outcome, current_outcome, out_dir)
                    if selected is not None:
                        return selected
                if verification.decision_hint == DECISION_REPAIR:
                    state = RepairLoopState(task, self.repair_loop_limits)
                    if state.can_attempt(trigger="verification", failure=result):
                        handled = self._repair_after_verification_decision_with_beam(
                            task,
                            result,
                            verification,
                            out_dir,
                            runtime_scheduler,
                            state,
                            incumbent_outcome,
                            current_sequence,
                        )
                        if isinstance(handled, BatchExtractionOutcome):
                            self._cleanup_shelved_outcome(incumbent_outcome, keep=handled)
                            return handled
                        if handled:
                            continue
                selected = self._selected_acceptable_outcome(incumbent_outcome, current_outcome, out_dir)
                if selected is not None:
                    return selected
                return current_outcome

            verification = self.verifier.verify(task, result)
            outcome = BatchExtractionOutcome(result=result, verification=verification, attempts=attempt_index + 1)
            self._annotate_recovery_outcome(task, outcome, source="original", round_index=current_sequence)
            if _verification_accepts(verification):
                selected = self._selected_acceptable_outcome(incumbent_outcome, outcome, out_dir) or outcome
                self._cleanup_shelved_outcome(incumbent_outcome, keep=selected)
                return selected

            incumbent_outcome = self._select_better_recovery_outcome(incumbent_outcome, outcome)

            if verification.decision_hint == DECISION_REPAIR:
                state = RepairLoopState(task, self.repair_loop_limits)
                if state.can_attempt(trigger="verification"):
                    if self._beam_enabled():
                        self._shelve_outcome_if_needed(incumbent_outcome, out_dir)
                        beam_evaluation = self._repair_after_verification_with_beam(
                            task,
                            result,
                            verification,
                            out_dir,
                            runtime_scheduler,
                        )
                        if beam_evaluation is not None:
                            handled = self._handle_beam_evaluation(
                                task,
                                beam_evaluation,
                                incumbent_outcome,
                                out_dir,
                                state,
                                current_sequence,
                            )
                            if isinstance(handled, BatchExtractionOutcome):
                                self._cleanup_shelved_outcome(incumbent_outcome, keep=handled)
                                return handled
                            if handled:
                                continue
            selected = self._selected_acceptable_outcome(incumbent_outcome, outcome, out_dir)
            if selected is not None:
                return selected

            last_outcome = outcome
            if attempt_index >= max_verification_retries:
                break
            if verification.decision_hint not in {DECISION_RETRY_EXTRACT, DECISION_REPAIR} and not self._retry_on_verification_failure():
                break
            if cleanup_failed_output:
                shutil.rmtree(result.out_dir, ignore_errors=True)
            attempt_index += 1

        selected = self._selected_acceptable_outcome(incumbent_outcome, last_outcome, out_dir)
        if selected is not None:
            return selected
        return last_outcome or BatchExtractionOutcome(
            result=ExtractionResult(
                success=False,
                archive=task.main_path,
                out_dir=out_dir,
                all_parts=task.all_parts,
                error="校验失败",
            ),
            attempts=attempts,
        )

    def _accept_partial_output(self, result: ExtractionResult, verification: VerificationResult) -> bool:
        config = self.verifier.config
        if not bool(config.get("accept_partial_when_source_damaged", True)):
            return False
        if terminal_failure_reason(result):
            return False
        if verification.decision_hint != DECISION_ACCEPT_PARTIAL:
            return False
        min_completeness = float(config.get("partial_min_completeness", 0.2) or 0.0)
        if float(verification.completeness or 0.0) < min_completeness:
            return False
        return bool(result.partial_outputs or verification.partial_files or verification.complete_files or verification.unverified_files)

    def _filter_partial_outputs(self, result: ExtractionResult) -> None:
        try:
            if result.progress_manifest:
                result.progress_manifest_payload = filter_extraction_outputs(result.progress_manifest)
            elif isinstance(result.progress_manifest_payload, dict):
                result.progress_manifest_payload = filter_extraction_manifest_payload(result.progress_manifest_payload)
        except Exception:
            return

    def _annotate_recovery_outcome(
        self,
        task: ArchiveTask,
        outcome: BatchExtractionOutcome,
        *,
        source: str,
        round_index: int = 0,
        repair_module: str = "",
    ) -> None:
        if outcome.verification is None:
            return
        if outcome.archive_state_payload is None:
            try:
                state = task.archive_state()
                outcome.archive_state_payload = state.to_dict()
                outcome.patch_digest = state.effective_patch_digest()
                outcome.patch_lineage = [patch.to_dict() for patch in state.patches]
            except (TypeError, ValueError, AttributeError):
                outcome.archive_state_payload = {}
                outcome.patch_digest = ""
                outcome.patch_lineage = []
        outcome.attempt_source = source or outcome.attempt_source
        outcome.repair_module = repair_module or outcome.repair_module
        outcome.round_index = int(round_index or outcome.round_index or 0)
        if not outcome.attempt_id:
            outcome.attempt_id = _recovery_attempt_id(outcome)

    def _select_better_recovery_outcome(
        self,
        incumbent: BatchExtractionOutcome | None,
        challenger: BatchExtractionOutcome | None,
    ) -> BatchExtractionOutcome | None:
        if incumbent is None:
            return challenger
        if challenger is None or challenger.verification is None:
            return incumbent
        if incumbent.verification is None:
            return challenger
        incumbent_attempt = _recovery_attempt_from_outcome(incumbent)
        challenger_attempt = _recovery_attempt_from_outcome(challenger)
        comparison = compare_attempts(
            [challenger_attempt],
            incumbent=incumbent_attempt,
            min_improvement=self._recovery_min_improvement(),
        )
        _apply_recovery_comparison(comparison, [incumbent, challenger])
        if comparison.best is None:
            return incumbent
        return challenger if comparison.best.attempt_id == challenger_attempt.attempt_id else incumbent

    def _selected_acceptable_outcome(
        self,
        incumbent: BatchExtractionOutcome | None,
        challenger: BatchExtractionOutcome | None,
        out_dir: str,
    ) -> BatchExtractionOutcome | None:
        selected = self._select_better_recovery_outcome(incumbent, challenger)
        if selected is None or selected.verification is None:
            return None
        if not self._outcome_accepts(selected):
            return None
        _ensure_recovery_rank(selected)
        self._promote_recovery_outcome(selected, out_dir)
        if self._accept_partial_output(selected.result, selected.verification):
            self._filter_partial_outputs(selected.result)
        return selected

    def _outcome_accepts(self, outcome: BatchExtractionOutcome) -> bool:
        verification = outcome.verification
        if verification is None:
            return False
        if outcome.result.success and _verification_accepts(verification):
            return True
        return self._accept_partial_output(outcome.result, verification)

    def _recovery_min_improvement(self) -> float:
        verification_config = self.verifier.config
        try:
            return max(0.0, float(verification_config.get("recovery_min_improvement", 0.0) or 0.0))
        except (TypeError, ValueError):
            return 0.0

    def _shelve_outcome_if_needed(self, outcome: BatchExtractionOutcome | None, out_dir: str) -> None:
        if outcome is None:
            return
        current = Path(outcome.result.out_dir)
        target = Path(out_dir)
        if os.path.abspath(str(current)) != os.path.abspath(str(target)):
            return
        if not current.exists():
            return
        suffix = (outcome.attempt_id or _recovery_attempt_id(outcome))[:12]
        held = target.with_name(f"{target.name}.incumbent_{suffix}")
        shutil.rmtree(held, ignore_errors=True)
        shutil.move(str(current), str(held))
        _retarget_result_output(outcome.result, str(current), str(held))

    def _promote_recovery_outcome(self, outcome: BatchExtractionOutcome, out_dir: str) -> None:
        current = Path(outcome.result.out_dir)
        target = Path(out_dir)
        if os.path.abspath(str(current)) == os.path.abspath(str(target)):
            return
        shutil.rmtree(target, ignore_errors=True)
        if current.exists():
            shutil.move(str(current), str(target))
        _retarget_result_output(outcome.result, str(current), str(target))

    def _cleanup_shelved_outcome(
        self,
        outcome: BatchExtractionOutcome | None,
        *,
        keep: BatchExtractionOutcome | None = None,
    ) -> None:
        if outcome is None or keep is outcome:
            return
        path = Path(outcome.result.out_dir)
        if ".incumbent_" not in path.name:
            return
        shutil.rmtree(path, ignore_errors=True)

    def _retry_on_verification_failure(self) -> bool:
        return bool(self.verifier.config.get("retry_on_verification_failure", True))

    def _beam_enabled(self) -> bool:
        beam = self.repair_stage.config.get("beam") if isinstance(self.repair_stage.config.get("beam"), dict) else {}
        return bool(beam.get("enabled", False)) and self.repair_stage.scheduler is not None

    def _repair_after_verification_decision_with_beam(
        self,
        task: ArchiveTask,
        result: ExtractionResult,
        verification: VerificationResult,
        out_dir: str,
        runtime_scheduler: ConcurrencyScheduler,
        loop_state: RepairLoopState,
        incumbent_outcome: BatchExtractionOutcome | None,
        round_index: int,
    ) -> BatchExtractionOutcome | bool:
        if not self._beam_enabled():
            return False
        self._shelve_outcome_if_needed(incumbent_outcome, out_dir)
        beam_evaluation = self._repair_after_verification_with_beam(
            task,
            result,
            verification,
            out_dir,
            runtime_scheduler,
        )
        if isinstance(beam_evaluation, _BeamRepairTerminal):
            loop_state.record_result(beam_evaluation.repair_result, trigger="verification_beam")
            return False
        if beam_evaluation is None:
            loop_state.stop("repair_no_patch_plan_candidates", trigger="verification_beam")
            return False
        return self._handle_beam_evaluation(
            task,
            beam_evaluation,
            incumbent_outcome,
            out_dir,
            loop_state,
            round_index,
        )

    def _repair_after_verification_with_beam(
        self,
        task: ArchiveTask,
        result: ExtractionResult,
        verification: VerificationResult,
        out_dir: str,
        runtime_scheduler: ConcurrencyScheduler,
    ) -> _BeamRepairEvaluation | _BeamRepairTerminal | None:
        scheduler = self.repair_stage.scheduler
        if scheduler is None:
            return None
        job = self.repair_stage._job_from_verification_assessment(task, result, verification)
        if job is None:
            return None

        evaluated: dict[str, tuple[RepairCandidate, ExtractionResult, VerificationResult, str]] = {}
        beam = RepairBeamLoop.from_config(
            scheduler,
            self.repair_stage.config,
            analyze=lambda candidate: {"confidence": float(candidate.confidence or 0.0)},
            assess=lambda item: self._assess_beam_candidate(task, item, out_dir, runtime_scheduler, evaluated),
            should_assess=self._beam_candidate_should_assess,
        )
        initial = RepairBeamState(
            source_input=dict(job.source_input),
            format=job.format,
            archive_state=job.archive_state.to_dict() if job.archive_state is not None else {},
            confidence=job.confidence,
            damage_flags=list(job.damage_flags),
            password=job.password,
            archive_key=job.archive_key,
            completeness=verification.completeness,
            recoverable_upper_bound=verification.recoverable_upper_bound,
            assessment_status=verification.assessment_status,
            source_integrity=verification.source_integrity,
            decision_hint=verification.decision_hint,
            verification=_verification_payload(verification),
            job_template=job,
        )
        max_rounds = int((self.repair_stage.config.get("beam") or {}).get("max_rounds", 1) or 1)
        run = beam.run([initial], max_rounds=max_rounds)
        best = run.best_state
        if best is None:
            terminal_result = _first_terminal_repair_result(run.terminal_results)
            if terminal_result is not None:
                task.fact_bag.set("repair.last_result", self.repair_stage._result_payload(terminal_result))
                return _BeamRepairTerminal(repair_result=terminal_result)
            self._cleanup_beam_evaluations(evaluated)
            return None

        digest = _source_input_digest(best.source_input)
        selected = evaluated.get(digest)
        if selected is None and best.archive_state:
            digest = _source_input_digest({"archive_state": best.archive_state})
            selected = evaluated.get(digest)
        if selected is None:
            self._cleanup_beam_evaluations(evaluated)
            return None
        candidate, extracted, assessed, temp_dir = selected
        self._cleanup_beam_evaluations({
            key: value
            for key, value in evaluated.items()
            if key != digest
        })
        repair_result = candidate.to_result(selection={
            "strategy": "beam",
            "score": best.score,
            "completeness": assessed.completeness,
            "decision_hint": assessed.decision_hint,
            "archive_coverage": _coverage_payload(assessed),
        })
        outcome = BatchExtractionOutcome(
            result=extracted,
            verification=assessed,
            attempts=1,
            repair_module=candidate.module_name,
            archive_state_payload=self._archive_state_payload_for_candidate(task, candidate),
        )
        if outcome.archive_state_payload:
            outcome.patch_digest = str(outcome.archive_state_payload.get("patch_digest") or "")
            outcome.patch_lineage = list(outcome.archive_state_payload.get("patches") or outcome.archive_state_payload.get("patch_stack") or [])
        return _BeamRepairEvaluation(
            candidate=candidate,
            result=extracted,
            verification=assessed,
            temp_dir=temp_dir,
            repair_result=repair_result,
            outcome=outcome,
        )

    def _handle_beam_evaluation(
        self,
        task: ArchiveTask,
        evaluation: _BeamRepairEvaluation,
        incumbent_outcome: BatchExtractionOutcome | None,
        out_dir: str,
        loop_state: RepairLoopState,
        round_index: int,
    ) -> BatchExtractionOutcome | bool:
        beam_outcome = evaluation.outcome
        self._annotate_recovery_outcome(
            task,
            beam_outcome,
            source="beam",
            round_index=round_index,
            repair_module=evaluation.candidate.module_name,
        )
        selected = self._select_better_recovery_outcome(incumbent_outcome, beam_outcome)
        if selected is not beam_outcome:
            loop_state.stop("no_repair_improvement", trigger="verification_beam", result=evaluation.repair_result)
            self._cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
                evaluation.candidate,
                evaluation.result,
                evaluation.verification,
                evaluation.temp_dir,
            )})
            return False
        self._apply_beam_candidate_to_task(task, evaluation.candidate)
        if not loop_state.record_result(evaluation.repair_result, trigger="verification_beam"):
            self._cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
                evaluation.candidate,
                evaluation.result,
                evaluation.verification,
                evaluation.temp_dir,
            )})
            return False

        if _verification_accepts(evaluation.verification):
            if self._accept_partial_output(evaluation.result, evaluation.verification):
                self._filter_partial_outputs(evaluation.result)
            final_result = self._promote_beam_output(evaluation.result, evaluation.temp_dir, out_dir)
            beam_outcome.result = final_result
            self._promote_recovery_outcome(beam_outcome, out_dir)
            return beam_outcome

        self.analysis_stage.analyze_task(task)

        if not bool(beam_outcome.comparison.get("should_continue_repair", True)):
            loop_state.stop("no_repair_improvement", trigger="verification_beam", result=evaluation.repair_result)
            self._cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
                evaluation.candidate,
                evaluation.result,
                evaluation.verification,
                evaluation.temp_dir,
            )})
            return False

        self._cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
            evaluation.candidate,
            evaluation.result,
            evaluation.verification,
            evaluation.temp_dir,
        )})
        shutil.rmtree(out_dir, ignore_errors=True)
        return True

    def _apply_beam_candidate_to_task(self, task: ArchiveTask, candidate: RepairCandidate) -> None:
        state = self._archive_state_for_candidate(task, candidate)
        if state is not None:
            task.set_archive_state(state)
        else:
            task.set_archive_input(candidate.repaired_input)
        task.fact_bag.set("archive.repaired", True)
        task.fact_bag.set("repair.module", candidate.module_name)

    def _archive_state_payload_for_candidate(self, task: ArchiveTask, candidate: RepairCandidate) -> dict[str, Any]:
        state = self._archive_state_for_candidate(task, candidate)
        return state.to_dict() if state is not None else {}

    def _archive_state_for_candidate(self, task: ArchiveTask, candidate: RepairCandidate) -> ArchiveState | None:
        archive_state = candidate.plan.get("archive_state") if isinstance(candidate.plan, dict) else None
        if isinstance(archive_state, dict):
            try:
                return ArchiveState.from_any(
                    archive_state,
                    archive_path=task.main_path,
                    part_paths=list(task.all_parts or [task.main_path]),
                    format_hint=str(candidate.format or task.detected_ext or ""),
                    logical_name=str(task.logical_name or ""),
                    archive_input=task.fact_bag.get("archive.input"),
                )
            except (TypeError, ValueError):
                return None
        descriptor = self.repair_stage._descriptor_from_repaired_input(task, candidate.repaired_input)
        if descriptor is None:
            return None
        return ArchiveState.from_archive_input(descriptor)

    def _beam_candidate_should_assess(self, item: RepairBeamCandidate) -> bool:
        threshold = self._partial_accept_threshold()
        incumbent = max(0.0, float(item.state.completeness or 0.0))
        if item.state.decision_hint != DECISION_ACCEPT_PARTIAL or incumbent < threshold:
            return True
        predicted = self._candidate_validation_completeness(item.candidate)
        min_improvement = self._recovery_min_improvement()
        if predicted is not None and predicted <= incumbent + min_improvement and item.score < 0.55:
            return False
        patch_cost = self._candidate_patch_cost(item.candidate)
        if patch_cost > 0.85 and item.score < 0.55:
            return False
        if item.candidate.partial and item.score < 0.45:
            return False
        return item.score >= 0.25

    def _verify_beam_candidate_light(self, task: ArchiveTask, result: ExtractionResult) -> VerificationResult:
        verification_config = dict(self.verifier.config)
        verification_config["methods"] = [
            method
            for method in verification_config.get("methods", [])
            if isinstance(method, dict)
            and method.get("enabled", True)
            and str(method.get("name") or "") in {
                "extraction_exit_signal",
                "output_presence",
                "expected_name_presence",
                "manifest_size_match",
            }
        ]
        if not verification_config["methods"]:
            return self.verifier.verify(task, result)
        light_config = dict(self.config)
        light_config["verification"] = verification_config
        return VerificationScheduler(light_config, password_session=self.extractor.password_session).verify(task, result)

    def _beam_candidate_needs_full_verification(
        self,
        item: RepairBeamCandidate,
        light_assessment: VerificationResult,
    ) -> bool:
        threshold = self._partial_accept_threshold()
        incumbent = max(0.0, float(item.state.completeness or 0.0))
        if item.state.decision_hint != DECISION_ACCEPT_PARTIAL or incumbent < threshold:
            return True
        if light_assessment.decision_hint == DECISION_ACCEPT:
            return True
        if float(light_assessment.completeness or 0.0) + 0.02 >= incumbent:
            return True
        if float(light_assessment.recoverable_upper_bound or 0.0) > float(item.state.recoverable_upper_bound or 0.0) + 0.01:
            return True
        incumbent_complete = _coverage_complete_files(item.state.verification)
        if int(light_assessment.archive_coverage.complete_files or 0) > incumbent_complete:
            return True
        return False

    def _partial_accept_threshold(self) -> float:
        try:
            return max(0.0, min(1.0, float(self.verifier.config.get("partial_accept_threshold", 0.2) or 0.2)))
        except (TypeError, ValueError):
            return 0.2

    def _candidate_validation_completeness(self, candidate: RepairCandidate) -> float | None:
        values: list[float] = []
        for validation in candidate.validations:
            details = validation.details if isinstance(validation.details, dict) else {}
            coverage = details.get("archive_coverage") if isinstance(details.get("archive_coverage"), dict) else {}
            if "completeness" in coverage:
                try:
                    values.append(float(coverage.get("completeness") or 0.0))
                except (TypeError, ValueError):
                    pass
        return max(values) if values else None

    def _candidate_patch_cost(self, candidate: RepairCandidate) -> float:
        plan = candidate.plan if isinstance(candidate.plan, dict) else {}
        archive_state = plan.get("archive_state") if isinstance(plan.get("archive_state"), dict) else {}
        patches = archive_state.get("patches") or archive_state.get("patch_stack") or []
        operation_count = 0
        byte_cost = 0
        for patch in patches:
            if not isinstance(patch, dict):
                continue
            for operation in patch.get("operations") or []:
                if not isinstance(operation, dict):
                    continue
                operation_count += 1
                try:
                    byte_cost += max(0, int(operation.get("size") or 0))
                except (TypeError, ValueError):
                    pass
                byte_cost += len(str(operation.get("data_b64") or operation.get("data") or ""))
        return min(1.0, operation_count * 0.12 + byte_cost / (64 * 1024 * 1024))

    def _assess_beam_candidate(
        self,
        task: ArchiveTask,
        item: RepairBeamCandidate,
        out_dir: str,
        runtime_scheduler: ConcurrencyScheduler,
        evaluated: dict[str, tuple[RepairCandidate, ExtractionResult, VerificationResult, str]],
    ) -> VerificationResult:
        original_state = task.archive_state()
        digest = _source_input_digest(item.candidate.repaired_input)
        if isinstance(item.candidate.plan, dict) and item.candidate.plan.get("archive_state"):
            digest = _source_input_digest({"archive_state": item.candidate.plan.get("archive_state")})
        temp_dir = f"{out_dir}.beam_{len(evaluated) + 1:02d}_{item.candidate.module_name}"
        shutil.rmtree(temp_dir, ignore_errors=True)
        try:
            archive_state = item.candidate.plan.get("archive_state") if isinstance(item.candidate.plan, dict) else None
            if isinstance(archive_state, dict):
                task.set_archive_state(archive_state)
            else:
                descriptor = self.repair_stage._descriptor_from_repaired_input(task, item.candidate.repaired_input)
                if descriptor is not None:
                    task.set_archive_state(ArchiveState.from_archive_input(descriptor))
                else:
                    task.set_archive_input(item.candidate.repaired_input)
            extracted = self.extractor.extract(task, temp_dir, runtime_scheduler=runtime_scheduler)
            light_assessment = self._verify_beam_candidate_light(task, extracted)
            assessed = (
                self.verifier.verify(task, extracted)
                if self._beam_candidate_needs_full_verification(item, light_assessment)
                else light_assessment
            )
            evaluated[digest] = (item.candidate, extracted, assessed, temp_dir)
            return assessed
        finally:
            task.set_archive_state(original_state)

    def _promote_beam_output(self, result: ExtractionResult, temp_dir: str, out_dir: str) -> ExtractionResult:
        if os.path.abspath(temp_dir) != os.path.abspath(out_dir):
            shutil.rmtree(out_dir, ignore_errors=True)
            if os.path.exists(temp_dir):
                shutil.move(temp_dir, out_dir)
        result.out_dir = out_dir
        manifest = Path(out_dir) / ".sunpack" / "extraction_manifest.json"
        result.progress_manifest = str(manifest) if manifest.exists() else ""
        return result

    def _cleanup_beam_evaluations(
        self,
        evaluated: dict[str, tuple[RepairCandidate, ExtractionResult, VerificationResult, str]],
        *,
        keep: str = "",
    ) -> None:
        keep_abs = os.path.abspath(keep) if keep else ""
        for _candidate, _result, _verification, temp_dir in evaluated.values():
            if keep_abs and os.path.abspath(temp_dir) == keep_abs:
                continue
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _skip_tasks_inside_batch_outputs(self, tasks: List[ArchiveTask], output_dir_resolver=None) -> List[ArchiveTask]:
        output_dir_resolver = output_dir_resolver or self.extractor.default_output_dir_for_task
        output_roots = []
        for task in tasks:
            output_dir = output_dir_resolver(task)
            if output_dir:
                output_roots.append((task, absolute_path_key(output_dir)))

        filtered = []
        for task in tasks:
            task_path = absolute_path_key(task.main_path)
            inside_another_output = False
            for owner, output_root in output_roots:
                if owner is task:
                    continue
                try:
                    if os.path.commonpath([task_path, output_root]) == output_root:
                        inside_another_output = True
                        break
                except ValueError:
                    continue
            if not inside_another_output:
                filtered.append(task)
        return filtered

    def collect_result(self, task: ArchiveTask, outcome: BatchExtractionOutcome | ExtractionResult) -> str | None:
        if isinstance(outcome, ExtractionResult):
            outcome = BatchExtractionOutcome(outcome)
        path = task.main_path
        res = outcome.result
        out_dir = res.out_dir

        with self.context.lock:
            if outcome.success:
                self.context.success_count += 1
                if outcome.verification is not None and outcome.verification.decision_hint == DECISION_ACCEPT_PARTIAL:
                    _ensure_recovery_rank(outcome)
                    recovery_report = _write_recovery_report(task, outcome, out_dir, config=self.config)
                    self.context.partial_success_count += 1
                    self.context.recovered_outputs.append({
                        "archive": task.main_path,
                        "out_dir": out_dir,
                        "completeness": outcome.verification.completeness,
                        "assessment_status": outcome.verification.assessment_status,
                        "source_integrity": outcome.verification.source_integrity,
                        "archive_coverage": _coverage_payload(outcome.verification),
                        "progress_manifest": res.progress_manifest,
                        "recovery_report": recovery_report,
                        "selected_attempt": dict(outcome.recovery_rank),
                        "comparison": dict(outcome.comparison),
                    })
                self.context.processed_keys.add(task.key)
                self.context.unpacked_archives.append(res.all_parts or task.all_parts)
                self.context.flatten_candidates.add(out_dir)
                return out_dir
            self.context.failed_tasks.append(self._failure_message(task, outcome))
            return None

    def _failure_message(self, task: ArchiveTask, outcome: BatchExtractionOutcome) -> str:
        name = os.path.basename(task.main_path)
        if outcome.result.success and outcome.verification is not None and not _verification_accepts(outcome.verification):
            return f"{name} [{self._verification_failure_summary(outcome)}]"
        return f"{name} [{outcome.result.error}]"

    def _verification_failure_summary(self, outcome: BatchExtractionOutcome) -> str:
        verification = outcome.verification
        if verification is None:
            return "校验失败"
        steps = "; ".join(f"{step.method}:{step.status}" for step in verification.steps) or "none"
        return (
            "校验失败: "
            f"completeness={getattr(verification, 'completeness', '')}, "
            f"assessment={getattr(verification, 'assessment_status', '')}, "
            f"decision={getattr(verification, 'decision_hint', '')}, "
            f"coverage={getattr(getattr(verification, 'archive_coverage', None), 'completeness', '')}, "
            f"attempts={outcome.attempts}, "
            f"steps={steps}"
        )


def _verification_accepts(verification: VerificationResult | Any) -> bool:
    decision = getattr(verification, "decision_hint", "")
    return decision in {DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL}


def _verification_accepts_partial(verification: VerificationResult | Any) -> bool:
    return getattr(verification, "decision_hint", "") == DECISION_ACCEPT_PARTIAL


def _resource_guard_violations(analysis: dict[str, Any], guard: dict[str, Any]) -> list[dict[str, Any]]:
    checks = [
        ("file_count", "max_file_count"),
        ("item_count", "max_item_count"),
        ("total_unpacked_size", "max_total_unpacked_size"),
        ("largest_item_size", "max_largest_item_size"),
    ]
    violations: list[dict[str, Any]] = []
    for field, limit_key in checks:
        limit = _optional_positive_int(guard.get(limit_key))
        if limit is None:
            continue
        actual = _safe_int(analysis.get(field))
        if actual > limit:
            violations.append({"field": field, "limit": limit, "actual": actual})
    ratio_limit = _optional_positive_float(guard.get("max_compression_ratio"))
    if ratio_limit is not None:
        unpacked = _safe_int(analysis.get("total_unpacked_size"))
        packed = _safe_int(analysis.get("total_packed_size") or analysis.get("archive_size"))
        if packed > 0:
            ratio = unpacked / packed
            if ratio > ratio_limit:
                violations.append({"field": "compression_ratio", "limit": ratio_limit, "actual": ratio})
    return violations


def _optional_positive_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _optional_positive_float(value: Any) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _source_input_digest(source_input: dict[str, Any]) -> str:
    payload = json.dumps(source_input or {}, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _recovery_attempt_from_outcome(outcome: BatchExtractionOutcome) -> RecoveryAttempt:
    return RecoveryAttempt(
        attempt_id=outcome.attempt_id or _recovery_attempt_id(outcome),
        verification=outcome.verification,
        extraction_result=outcome.result,
        archive_state=dict(outcome.archive_state_payload or {}),
        patch_digest=outcome.patch_digest,
        patch_lineage=list(outcome.patch_lineage or []),
        round_index=outcome.round_index,
        source=outcome.attempt_source,
        repair_module=outcome.repair_module,
        patch_cost=_patch_cost(outcome.archive_state_payload or {}),
        metadata={
            "out_dir": outcome.result.out_dir,
            "progress_manifest": outcome.result.progress_manifest,
        },
    )


def _apply_recovery_comparison(comparison, outcomes: list[BatchExtractionOutcome | None]) -> None:
    by_id = {
        outcome.attempt_id or _recovery_attempt_id(outcome): outcome
        for outcome in outcomes
        if outcome is not None
    }
    rejected = [
        _attempt_summary(attempt, comparison.ranks.get(attempt.attempt_id))
        for attempt in comparison.rejected
    ]
    selected_id = comparison.best.attempt_id if comparison.best is not None else ""
    for attempt_id, outcome in by_id.items():
        rank = comparison.ranks.get(attempt_id)
        if rank is not None:
            outcome.recovery_rank = _rank_payload(rank)
        outcome.comparison = {
            "selected_attempt_id": selected_id,
            "stop_reason": comparison.stop_reason,
            "should_continue_repair": comparison.should_continue_repair,
            "selected": _attempt_summary(comparison.best, comparison.ranks.get(selected_id)) if comparison.best is not None else {},
        }
        outcome.rejected_attempts = list(rejected)


def _first_terminal_repair_result(results: list[Any]):
    for result in results:
        if result is not None and not getattr(result, "ok", False):
            return result
    return None


def _ensure_recovery_rank(outcome: BatchExtractionOutcome) -> None:
    if outcome.recovery_rank or outcome.verification is None:
        return
    attempt = _recovery_attempt_from_outcome(outcome)
    rank = rank_attempt(attempt)
    outcome.recovery_rank = _rank_payload(rank)
    outcome.comparison = {
        "selected_attempt_id": attempt.attempt_id,
        "stop_reason": "single_attempt",
        "should_continue_repair": rank.decision == "continue_repair",
        "selected": _attempt_summary(attempt, rank),
    }




def _rank_payload(rank) -> dict[str, Any]:
    return {
        "attempt_id": rank.attempt_id,
        "rank_score": rank.rank_score,
        "decision": rank.decision,
        "rank_vector": dict(rank.rank_vector),
        "reasons": list(rank.reasons),
    }


def _attempt_summary(attempt, rank) -> dict[str, Any]:
    if attempt is None:
        return {}
    verification = attempt.verification
    coverage = verification.archive_coverage
    return {
        "attempt_id": attempt.attempt_id,
        "source": attempt.source,
        "repair_module": attempt.repair_module,
        "patch_digest": attempt.patch_digest,
        "round_index": attempt.round_index,
        "rank": _rank_payload(rank) if rank is not None else {},
        "verification": {
            "decision_hint": verification.decision_hint,
            "assessment_status": verification.assessment_status,
            "completeness": verification.completeness,
        },
        "archive_coverage": {
            "completeness": coverage.completeness,
            "expected_files": coverage.expected_files,
            "complete_files": coverage.complete_files,
            "partial_files": coverage.partial_files,
            "failed_files": coverage.failed_files,
            "missing_files": coverage.missing_files,
        },
    }


def _recovery_attempt_id(outcome: BatchExtractionOutcome) -> str:
    payload = {
        "archive": outcome.result.archive,
        "out_dir": outcome.result.out_dir,
        "source": outcome.attempt_source,
        "round_index": outcome.round_index,
        "patch_digest": outcome.patch_digest,
        "repair_module": outcome.repair_module,
        "progress_manifest": outcome.result.progress_manifest,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _patch_cost(archive_state: dict[str, Any]) -> float:
    patches = archive_state.get("patches") or archive_state.get("patch_stack") or []
    cost = 0.0
    for patch in patches:
        if not isinstance(patch, dict):
            continue
        operations = patch.get("operations") or []
        cost += 0.02
        for operation in operations:
            if not isinstance(operation, dict):
                continue
            size = operation.get("size")
            data = operation.get("data_b64") or operation.get("data") or ""
            cost += 0.01
            try:
                cost += min(0.2, max(0, int(size or len(str(data)))) / (1024 * 1024 * 100))
            except (TypeError, ValueError):
                continue
    return min(1.0, cost)


def _retarget_result_output(result: ExtractionResult, old_dir: str, new_dir: str) -> None:
    old = Path(old_dir)
    new = Path(new_dir)
    progress_manifest = result.progress_manifest
    result.out_dir = str(new)
    if not progress_manifest:
        return
    manifest_path = Path(progress_manifest)
    try:
        relative = manifest_path.relative_to(old)
    except ValueError:
        candidate = new / ".sunpack" / "extraction_manifest.json"
        result.progress_manifest = str(candidate) if candidate.exists() else progress_manifest
        return
    result.progress_manifest = str(new / relative)


def _coverage_payload(verification: VerificationResult) -> dict[str, Any]:
    coverage = verification.archive_coverage
    return {
        "completeness": coverage.completeness,
        "file_coverage": coverage.file_coverage,
        "byte_coverage": coverage.byte_coverage,
        "expected_files": coverage.expected_files,
        "matched_files": coverage.matched_files,
        "complete_files": coverage.complete_files,
        "partial_files": coverage.partial_files,
        "failed_files": coverage.failed_files,
        "missing_files": coverage.missing_files,
        "unverified_files": coverage.unverified_files,
        "expected_bytes": coverage.expected_bytes,
        "matched_bytes": coverage.matched_bytes,
        "complete_bytes": coverage.complete_bytes,
        "confidence": coverage.confidence,
        "sources": list(coverage.sources),
    }


def _coverage_complete_files(payload: dict[str, Any]) -> int:
    coverage = payload.get("archive_coverage") if isinstance(payload, dict) else {}
    if not isinstance(coverage, dict):
        return 0
    try:
        return max(0, int(coverage.get("complete_files") or 0))
    except (TypeError, ValueError):
        return 0


def _verification_payload(verification: VerificationResult) -> dict[str, Any]:
    return {
        "completeness": verification.completeness,
        "recoverable_upper_bound": verification.recoverable_upper_bound,
        "assessment_status": verification.assessment_status,
        "source_integrity": verification.source_integrity,
        "decision_hint": verification.decision_hint,
        "archive_coverage": _coverage_payload(verification),
        "files": _file_recovery_items(verification),
    }


def _write_recovery_report(
    task: ArchiveTask,
    outcome: BatchExtractionOutcome,
    out_dir: str,
    *,
    config: dict[str, Any] | None = None,
) -> str:
    verification = outcome.verification
    if verification is None:
        return ""
    manifest = _result_progress_manifest(outcome.result)
    payload = {
        "version": 1,
        "archive": task.main_path,
        "out_dir": out_dir,
        "success_kind": "partial",
        "progress_manifest": outcome.result.progress_manifest,
        "archive_state": _archive_state_payload_for_outcome(task, outcome),
        "verification": _verification_payload(verification),
        "archive_coverage": _coverage_payload(verification),
        "selected_attempt": dict(outcome.recovery_rank),
        "comparison": dict(outcome.comparison),
        "rejected_attempts": list(outcome.rejected_attempts),
        "files": _file_recovery_items(verification, manifest=manifest),
    }
    target = Path(out_dir) / ".sunpack" / "recovery_report.json"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        pretty = _json_pretty_reports(config)
        target.write_text(_json_text(payload, pretty=pretty), encoding="utf-8")
        _annotate_progress_manifest(outcome.result.progress_manifest, payload, manifest=manifest, pretty=pretty)
        return str(target)
    except OSError:
        return ""


def _archive_state_payload(task: ArchiveTask) -> dict[str, Any]:
    try:
        state = task.archive_state()
    except (TypeError, ValueError):
        return {}
    return {
        "patch_digest": state.effective_patch_digest(),
        "state_is_patched": bool(state.patches),
        "source": state.source.to_dict(),
        "patch_stack": [patch.to_dict() for patch in state.patches],
    }


def _archive_state_payload_for_outcome(task: ArchiveTask, outcome: BatchExtractionOutcome) -> dict[str, Any]:
    if isinstance(outcome.archive_state_payload, dict) and outcome.archive_state_payload:
        raw = dict(outcome.archive_state_payload)
        return {
            "patch_digest": outcome.patch_digest or str(raw.get("patch_digest") or ""),
            "state_is_patched": bool(raw.get("patches") or raw.get("patch_stack")),
            "source": raw.get("source") if isinstance(raw.get("source"), dict) else {},
            "patch_stack": list(raw.get("patches") or raw.get("patch_stack") or []),
        }
    return _archive_state_payload(task)


def _annotate_progress_manifest(
    manifest_path: str,
    recovery_report: dict[str, Any],
    *,
    manifest: dict[str, Any] | None = None,
    pretty: bool = False,
) -> None:
    if not manifest_path:
        return
    path = Path(manifest_path)
    if not path.is_file():
        return
    if manifest is None:
        manifest = _read_manifest(manifest_path)
    if not isinstance(manifest, dict):
        return
    manifest["recovery"] = {
        "success_kind": recovery_report.get("success_kind"),
        "verification": recovery_report.get("verification"),
        "archive_coverage": recovery_report.get("archive_coverage"),
    }
    files = manifest.get("files")
    if isinstance(files, list):
        for item in files:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "unverified")
            item["recovery_status"] = "kept_complete" if status == "complete" else "kept_partial_or_unverified"
            item["user_action"] = _user_action_for_file_status(status)
    try:
        path.write_text(_json_text(manifest, pretty=pretty), encoding="utf-8")
    except OSError:
        return


def _file_recovery_items(
    verification: VerificationResult,
    *,
    manifest_path: str = "",
    manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for observation in verification.file_observations:
        status = _normalize_file_status(observation.state)
        payload = {
            "archive_path": observation.archive_path,
            "output_path": observation.path,
            "status": status,
            "bytes_written": int(observation.bytes_written or 0),
            "expected_size": observation.expected_size,
            "progress": observation.progress,
            "crc_expected": observation.crc_expected,
            "crc_actual": observation.crc_actual,
            "method": observation.method,
            "failure_stage": str(observation.details.get("failure_stage") or ""),
            "failure_kind": _observation_failure_kind(observation, status),
            "message": str(observation.details.get("message") or ""),
            "user_action": _user_action_for_file_status(status),
        }
        key = (str(payload["archive_path"]), str(payload["output_path"]))
        if key in seen:
            continue
        seen.add(key)
        items.append(payload)

    if manifest is None:
        manifest = _read_manifest(manifest_path)
    for raw in list(manifest.get("files") or []) + list(manifest.get("discarded_files") or []):
        if not isinstance(raw, dict):
            continue
        status = _normalize_file_status(raw.get("status"))
        if raw in manifest.get("discarded_files", []):
            status = "discarded"
        payload = {
            "archive_path": str(raw.get("archive_path") or ""),
            "output_path": str(raw.get("path") or ""),
            "status": status,
            "bytes_written": int(raw.get("bytes_written", 0) or 0),
            "expected_size": raw.get("expected_size"),
            "progress": _progress_from_manifest_item(raw),
            "crc_ok": raw.get("crc_ok"),
            "failure_stage": str(raw.get("failure_stage") or ""),
            "failure_kind": str(raw.get("failure_kind") or ""),
            "message": str(raw.get("message") or ""),
            "retention": str(raw.get("retention") or ""),
            "user_action": _user_action_for_file_status(status),
        }
        key = (payload["archive_path"], payload["output_path"])
        if key in seen:
            if status == "discarded":
                _merge_discarded_file_status(items, key, payload)
            else:
                _merge_manifest_file_details(items, key, payload)
            continue
        if status != "discarded" and _merge_manifest_file_details_by_archive_path(items, payload):
            continue
        seen.add(key)
        items.append(payload)
    return sorted(items, key=lambda item: (_file_status_rank(str(item.get("status") or "")), str(item.get("archive_path") or item.get("output_path") or "")))


def _read_manifest(manifest_path: str) -> dict[str, Any]:
    if not manifest_path:
        return {}
    path = Path(manifest_path)
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _result_progress_manifest(result: ExtractionResult) -> dict[str, Any]:
    cached = getattr(result, "progress_manifest_payload", None)
    if isinstance(cached, dict):
        return cached
    manifest = _read_manifest(result.progress_manifest)
    if manifest:
        result.progress_manifest_payload = manifest
    return manifest


def _json_pretty_reports(config: dict[str, Any] | None) -> bool:
    payload = config or {}
    reporting = payload.get("reporting") if isinstance(payload.get("reporting"), dict) else {}
    if "pretty_json" in reporting:
        return bool(reporting.get("pretty_json"))
    if "compact_json" in reporting:
        return not bool(reporting.get("compact_json"))
    debug = payload.get("debug") if isinstance(payload.get("debug"), dict) else {}
    return bool(debug.get("pretty_json_reports", False))


def _json_text(payload: Any, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(payload, ensure_ascii=False, indent=2)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _merge_discarded_file_status(items: list[dict[str, Any]], key: tuple[str, str], discarded: dict[str, Any]) -> None:
    for item in items:
        if (str(item.get("archive_path") or ""), str(item.get("output_path") or "")) != key:
            continue
        if item.get("status") == "failed":
            item["retention"] = discarded.get("retention", "discarded")
            return
        item["observed_status"] = item.get("status")
        item["status"] = "discarded"
        item["retention"] = discarded.get("retention", "discarded")
        item["user_action"] = _user_action_for_file_status("discarded")
        if discarded.get("failure_stage"):
            item["failure_stage"] = discarded.get("failure_stage")
        if discarded.get("failure_kind"):
            item["failure_kind"] = discarded.get("failure_kind")
        if discarded.get("message"):
            item["message"] = discarded.get("message")
        return


def _merge_manifest_file_details(items: list[dict[str, Any]], key: tuple[str, str], manifest_item: dict[str, Any]) -> None:
    for item in items:
        if (str(item.get("archive_path") or ""), str(item.get("output_path") or "")) != key:
            continue
        _merge_file_details(item, manifest_item)
        return


def _merge_manifest_file_details_by_archive_path(items: list[dict[str, Any]], manifest_item: dict[str, Any]) -> bool:
    archive_path = str(manifest_item.get("archive_path") or "")
    if not archive_path:
        return False
    matches = [item for item in items if str(item.get("archive_path") or "") == archive_path]
    if len(matches) != 1:
        return False
    _merge_file_details(matches[0], manifest_item)
    return True


def _merge_file_details(item: dict[str, Any], extra: dict[str, Any]) -> None:
    if _file_status_rank(str(extra.get("status") or "")) > _file_status_rank(str(item.get("status") or "")):
        item["observed_status"] = extra.get("status")
    elif _file_status_rank(str(extra.get("status") or "")) < _file_status_rank(str(item.get("status") or "")):
        item["observed_status"] = item.get("status")
        item["status"] = extra.get("status")
        item["user_action"] = _user_action_for_file_status(str(extra.get("status") or ""))
    for field in ("failure_stage", "failure_kind", "message", "retention"):
        if extra.get(field) and not item.get(field):
            item[field] = extra.get(field)
    if extra.get("crc_ok") is not None and item.get("crc_ok") is None:
        item["crc_ok"] = extra.get("crc_ok")
    if extra.get("output_path") and (not item.get("output_path") or not Path(str(item.get("output_path") or "")).is_absolute()):
        item["output_path"] = extra.get("output_path")
    if int(extra.get("bytes_written", 0) or 0) > int(item.get("bytes_written", 0) or 0):
        item["bytes_written"] = int(extra.get("bytes_written", 0) or 0)
    if item.get("expected_size") in {None, ""} and extra.get("expected_size") not in {None, ""}:
        item["expected_size"] = extra.get("expected_size")
    if item.get("progress") is None and extra.get("progress") is not None:
        item["progress"] = extra.get("progress")


def _observation_failure_kind(observation: Any, status: str) -> str:
    details = observation.details if isinstance(getattr(observation, "details", None), dict) else {}
    failure_kind = str(details.get("failure_kind") or "")
    if failure_kind:
        return failure_kind
    if status == "failed" and observation.crc_expected is not None and observation.crc_actual is not None:
        if int(observation.crc_expected) != int(observation.crc_actual):
            return "checksum_error"
    return ""


def _normalize_file_status(value: Any) -> str:
    status = str(value or "unverified")
    if status in {"complete", "partial", "failed", "missing", "unverified", "discarded"}:
        return status
    return "unverified"


def _progress_from_manifest_item(item: dict[str, Any]) -> float | None:
    expected = item.get("expected_size")
    try:
        expected_int = int(expected)
    except (TypeError, ValueError):
        return None
    if expected_int <= 0:
        return None
    return min(1.0, max(0.0, int(item.get("bytes_written", 0) or 0) / expected_int))


def _user_action_for_file_status(status: str) -> str:
    return {
        "complete": "safe_to_use",
        "partial": "inspect_manually",
        "unverified": "inspect_manually",
        "failed": "not_recovered",
        "missing": "not_recovered",
        "discarded": "discarded_low_quality",
    }.get(status, "inspect_manually")


def _file_status_rank(status: str) -> int:
    return {
        "complete": 0,
        "partial": 1,
        "unverified": 2,
        "failed": 3,
        "missing": 4,
        "discarded": 5,
    }.get(status, 9)
