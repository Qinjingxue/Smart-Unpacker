import os
import shutil
from dataclasses import dataclass
from typing import List

from smart_unpacker.contracts.run_context import RunContext
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.analysis_stage import ArchiveAnalysisStage
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
from smart_unpacker.rename.scheduler import RenameScheduler
from smart_unpacker.verification import VerificationResult, VerificationScheduler
from smart_unpacker.support.path_keys import absolute_path_key


@dataclass
class BatchExtractionOutcome:
    result: ExtractionResult
    verification: VerificationResult | None = None
    attempts: int = 1

    @property
    def success(self) -> bool:
        if not self.result.success:
            return False
        return self.verification is None or self.verification.ok


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
        self.analysis_stage.analyze_tasks(tasks)
        self.repair_stage.repair_medium_confidence_tasks(tasks)
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
        for task in tasks:
            out_dir = output_dir_resolver(task)
            preflight = self.extractor.inspect(task, out_dir)
            if preflight.skip_result is not None:
                skipped_results.append((task, BatchExtractionOutcome(preflight.skip_result)))
                continue
            ready_tasks.append(task)

        if not ready_tasks:
            return skipped_results
        if len(ready_tasks) == 1:
            self.resource_inspector.record_estimated_single_task_profile(ready_tasks[0])
        else:
            for task in ready_tasks:
                self.resource_inspector.inspect(task)

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

        for attempt_index in range(attempts):
            result = self.extractor.extract(task, out_dir, runtime_scheduler=runtime_scheduler)
            if not result.success:
                if self.repair_stage.repair_after_extraction_failure(task, result):
                    shutil.rmtree(out_dir, ignore_errors=True)
                    result = self.extractor.extract(task, out_dir, runtime_scheduler=runtime_scheduler)
                    if result.success:
                        verification = self.verifier.verify(task, result)
                        return BatchExtractionOutcome(result=result, verification=verification, attempts=attempt_index + 1)
                return BatchExtractionOutcome(result=result, attempts=attempt_index + 1)

            verification = self.verifier.verify(task, result)
            outcome = BatchExtractionOutcome(result=result, verification=verification, attempts=attempt_index + 1)
            if verification.ok:
                return outcome

            last_outcome = outcome
            if attempt_index >= max_verification_retries:
                break
            if cleanup_failed_output:
                shutil.rmtree(result.out_dir, ignore_errors=True)

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
                self.context.processed_keys.add(task.key)
                self.context.unpacked_archives.append(res.all_parts or task.all_parts)
                self.context.flatten_candidates.add(out_dir)
                return out_dir
            self.context.failed_tasks.append(self._failure_message(task, outcome))
            return None

    def _failure_message(self, task: ArchiveTask, outcome: BatchExtractionOutcome) -> str:
        name = os.path.basename(task.main_path)
        if outcome.result.success and outcome.verification is not None and not outcome.verification.ok:
            return f"{name} [{self._verification_failure_summary(outcome)}]"
        return f"{name} [{outcome.result.error}]"

    def _verification_failure_summary(self, outcome: BatchExtractionOutcome) -> str:
        verification = outcome.verification
        if verification is None:
            return "校验失败"
        steps = "; ".join(
            f"{step.method}:{step.score_delta:+d}=>{step.score_after}"
            for step in verification.steps
        ) or "none"
        return (
            "校验失败: "
            f"status={verification.status}, "
            f"score={verification.score}, "
            f"pass={verification.pass_threshold}, "
            f"attempts={outcome.attempts}, "
            f"steps={steps}"
        )
