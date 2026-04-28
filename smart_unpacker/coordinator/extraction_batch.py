import os
import shutil
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List

from smart_unpacker.contracts.run_context import RunContext
from smart_unpacker.contracts.archive_state import ArchiveState
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.analysis_stage import ArchiveAnalysisStage
from smart_unpacker.coordinator.repair_beam import RepairBeamCandidate, RepairBeamLoop, RepairBeamState
from smart_unpacker.coordinator.repair_loop import RepairLoopLimits, RepairLoopState
from smart_unpacker.coordinator.repair_stage import ArchiveRepairStage
from smart_unpacker.coordinator.resource_preflight import ResourcePreflightInspector
from smart_unpacker.coordinator.scheduling import (
    ConcurrencyScheduler,
    TaskExecutor,
    build_scheduler_profile_config,
    resolve_max_workers,
)
from smart_unpacker.detection import NestedOutputScanPolicy
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.extraction.progress import filter_extraction_outputs
from smart_unpacker.rename.scheduler import RenameScheduler
from smart_unpacker.repair.candidate import RepairCandidate
from smart_unpacker.verification import VerificationResult, VerificationScheduler
from smart_unpacker.verification.result import DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL, DECISION_REPAIR, DECISION_RETRY_EXTRACT
from smart_unpacker.support.path_keys import absolute_path_key


@dataclass
class BatchExtractionOutcome:
    result: ExtractionResult
    verification: VerificationResult | None = None
    attempts: int = 1

    @property
    def success(self) -> bool:
        if not self.result.success:
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
        tasks = self._settle_analysis_repair_loops(tasks)
        output_dir_resolver = self.rename_scheduler.build_output_dir_resolver(
            tasks,
            self.extractor.default_output_dir_for_task,
        )
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
            self.resource_inspector.record_estimated_single_task_profile(ready_tasks[0])
        else:
            self._inspect_resource_profiles(ready_tasks)

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

    def _build_scheduler_config(self, config: dict) -> dict:
        performance = config.get("performance", {}) if isinstance(config.get("performance"), dict) else {}
        scheduler_config = build_scheduler_profile_config(performance.get("scheduler_profile", "auto"))
        scheduler_config.update({
            key: value
            for key, value in performance.items()
            if key != "scheduler_profile" and value is not None
        })
        return scheduler_config

    def _settle_analysis_repair_loops(self, tasks: list[ArchiveTask]) -> list[ArchiveTask]:
        max_workers = self._stage_max_workers(
            enabled_key="parallel_repair_settle",
            workers_key="repair_settle_max_workers",
            task_count=len(tasks),
            default_workers=2,
        )
        if max_workers > 1:
            indexed = [_IndexedStageTask(index, task) for index, task in enumerate(tasks)]
            results = self._execute_indexed_stage(
                indexed,
                max_workers=max_workers,
                worker=lambda item: (
                    item.index,
                    self._settle_single_analysis_repair_loop(
                        item.task,
                        analysis_stage=self._parallel_analysis_stage(),
                        repair_stage=self._parallel_repair_stage(),
                    ),
                ),
            )
            settled: list[ArchiveTask] = []
            for _index, task_group in sorted(results, key=lambda item: item[0]):
                settled.extend(task_group)
            return settled

        settled: list[ArchiveTask] = []
        for task in tasks:
            settled.extend(self._settle_single_analysis_repair_loop(task))
        return settled

    def _settle_single_analysis_repair_loop(
        self,
        task: ArchiveTask,
        *,
        analysis_stage: ArchiveAnalysisStage | None = None,
        repair_stage: ArchiveRepairStage | None = None,
    ) -> list[ArchiveTask]:
        analysis_stage = analysis_stage or self.analysis_stage
        repair_stage = repair_stage or self.repair_stage
        current_tasks = [task]
        settled: list[ArchiveTask] = []
        while current_tasks:
            current = current_tasks.pop(0)
            state = RepairLoopState(current, self.repair_loop_limits)
            while state.can_attempt(trigger="analysis"):
                repair_result = repair_stage.repair_medium_confidence_task(current)
                if repair_result is None:
                    break
                if not state.record_result(repair_result, trigger="analysis"):
                    break
                analyzed = analysis_stage.analyze_task_to_tasks(current)
                if len(analyzed) == 1:
                    current = analyzed[0]
                    state = RepairLoopState(current, self.repair_loop_limits)
                    continue
                current_tasks.extend(analyzed)
                current = None
                break
            if current is not None:
                settled.append(current)
        return settled

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

    def _parallel_analysis_stage(self):
        if type(self.analysis_stage) is ArchiveAnalysisStage:
            return ArchiveAnalysisStage(self.config)
        return self.analysis_stage

    def _parallel_repair_stage(self):
        if type(self.repair_stage) is ArchiveRepairStage:
            return ArchiveRepairStage(self.config)
        return self.repair_stage

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

        attempt_index = 0
        while attempt_index < attempts:
            result = self.extractor.extract(task, out_dir, runtime_scheduler=runtime_scheduler)
            if not result.success:
                verification = self.verifier.verify(task, result) if result.partial_outputs else None
                state = RepairLoopState(task, self.repair_loop_limits)
                if state.can_attempt(trigger="extraction", failure=result):
                    repair_result = self.repair_stage.repair_after_extraction_failure_result(task, result)
                    can_continue = state.record_result(repair_result, trigger="extraction")
                else:
                    can_continue = False
                if can_continue:
                    shutil.rmtree(out_dir, ignore_errors=True)
                    self.analysis_stage.analyze_task(task)
                    continue
                if verification is not None and self._accept_partial_output(result, verification):
                    self._filter_partial_outputs(result)
                    return BatchExtractionOutcome(
                        result=result,
                        verification=verification,
                        attempts=attempt_index + 1,
                    )
                return BatchExtractionOutcome(result=result, attempts=attempt_index + 1)

            verification = self.verifier.verify(task, result)
            outcome = BatchExtractionOutcome(result=result, verification=verification, attempts=attempt_index + 1)
            if _verification_accepts(verification):
                return outcome

            if verification.decision_hint == DECISION_REPAIR:
                state = RepairLoopState(task, self.repair_loop_limits)
                if state.can_attempt(trigger="verification"):
                    if self._beam_enabled():
                        beam_outcome = self._repair_after_verification_with_beam(
                            task,
                            result,
                            verification,
                            out_dir,
                            runtime_scheduler,
                            state,
                        )
                        if beam_outcome is not None:
                            return beam_outcome
                    repair_result = self.repair_stage.repair_after_verification_assessment_result(task, result, verification)
                    if state.record_result(repair_result, trigger="verification"):
                        shutil.rmtree(out_dir, ignore_errors=True)
                        self.analysis_stage.analyze_task(task)
                        continue
            if self._accept_partial_output(result, verification):
                self._filter_partial_outputs(result)
                return outcome

            last_outcome = outcome
            if attempt_index >= max_verification_retries:
                break
            if verification.decision_hint not in {DECISION_RETRY_EXTRACT, DECISION_REPAIR} and not self._retry_on_verification_failure():
                break
            if cleanup_failed_output:
                shutil.rmtree(result.out_dir, ignore_errors=True)
            attempt_index += 1

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
        if verification.decision_hint != DECISION_ACCEPT_PARTIAL:
            return False
        min_completeness = float(config.get("partial_min_completeness", 0.2) or 0.0)
        if float(verification.completeness or 0.0) < min_completeness:
            return False
        return bool(result.partial_outputs or verification.partial_files or verification.complete_files or verification.unverified_files)

    def _filter_partial_outputs(self, result: ExtractionResult) -> None:
        if not result.progress_manifest:
            return
        try:
            filter_extraction_outputs(result.progress_manifest)
        except Exception:
            return

    def _retry_on_verification_failure(self) -> bool:
        return bool(self.verifier.config.get("retry_on_verification_failure", True))

    def _beam_enabled(self) -> bool:
        beam = self.repair_stage.config.get("beam") if isinstance(self.repair_stage.config.get("beam"), dict) else {}
        return bool(beam.get("enabled", False)) and self.repair_stage.scheduler is not None

    def _repair_after_verification_with_beam(
        self,
        task: ArchiveTask,
        result: ExtractionResult,
        verification: VerificationResult,
        out_dir: str,
        runtime_scheduler: ConcurrencyScheduler,
        loop_state: RepairLoopState,
    ) -> BatchExtractionOutcome | None:
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
            self._cleanup_beam_evaluations(evaluated)
            return None

        digest = _source_input_digest(best.source_input)
        selected = evaluated.get(digest)
        if selected is None:
            self._cleanup_beam_evaluations(evaluated)
            return None
        candidate, extracted, assessed, temp_dir = selected
        repair_result = candidate.to_result(selection={
            "strategy": "beam",
            "score": best.score,
            "completeness": assessed.completeness,
            "decision_hint": assessed.decision_hint,
            "archive_coverage": _coverage_payload(assessed),
        })
        if not loop_state.record_result(repair_result, trigger="verification_beam"):
            self._cleanup_beam_evaluations(evaluated)
            return None
        self.analysis_stage.analyze_task(task)

        if _verification_accepts(assessed):
            final_result = self._promote_beam_output(extracted, temp_dir, out_dir)
            self._cleanup_beam_evaluations(evaluated, keep=temp_dir)
            if self._accept_partial_output(final_result, assessed):
                self._filter_partial_outputs(final_result)
            return BatchExtractionOutcome(result=final_result, verification=assessed, attempts=1)

        self._cleanup_beam_evaluations(evaluated)
        shutil.rmtree(out_dir, ignore_errors=True)
        return None

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
            assessed = self.verifier.verify(task, extracted)
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
                    recovery_report = _write_recovery_report(task, outcome, out_dir)
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


def _source_input_digest(source_input: dict[str, Any]) -> str:
    payload = json.dumps(source_input or {}, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


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


def _write_recovery_report(task: ArchiveTask, outcome: BatchExtractionOutcome, out_dir: str) -> str:
    verification = outcome.verification
    if verification is None:
        return ""
    payload = {
        "version": 1,
        "archive": task.main_path,
        "out_dir": out_dir,
        "success_kind": "partial",
        "progress_manifest": outcome.result.progress_manifest,
        "verification": _verification_payload(verification),
        "archive_coverage": _coverage_payload(verification),
        "files": _file_recovery_items(verification, manifest_path=outcome.result.progress_manifest),
    }
    target = Path(out_dir) / ".sunpack" / "recovery_report.json"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        _annotate_progress_manifest(outcome.result.progress_manifest, payload)
        return str(target)
    except OSError:
        return ""


def _annotate_progress_manifest(manifest_path: str, recovery_report: dict[str, Any]) -> None:
    if not manifest_path:
        return
    path = Path(manifest_path)
    if not path.is_file():
        return
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
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
        path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        return


def _file_recovery_items(verification: VerificationResult, *, manifest_path: str = "") -> list[dict[str, Any]]:
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
            "user_action": _user_action_for_file_status(status),
        }
        key = (str(payload["archive_path"]), str(payload["output_path"]))
        if key in seen:
            continue
        seen.add(key)
        items.append(payload)

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
