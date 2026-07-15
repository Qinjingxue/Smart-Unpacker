import os
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List

from sunpack.contracts.run_context import RunContext
from sunpack.contracts.results import OutcomeKind, TargetRunResult
from sunpack.contracts.archive_state import ArchiveState
from sunpack.contracts.tasks import ArchiveTask
from sunpack.analysis.stage import ArchiveAnalysisStage
from sunpack.postprocess.failed_output_cleanup import REPAIR_ENTERED_FACT, cleanup_failed_output_if_eligible
from sunpack.postprocess.recovery_outputs import (
    cleanup_beam_evaluations,
    cleanup_shelved_outcome,
    promote_beam_output,
    promote_recovery_outcome,
    remove_output,
    shelve_outcome_if_needed,
)
from sunpack.repair.beam import RepairBeamCandidate, RepairBeamLoop, RepairBeamState
from sunpack.repair.loop import RepairLoopLimits, RepairLoopState, terminal_failure_reason
from sunpack.coordinator.repair_runtime_transition import RepairRuntimeTransitionEvaluator
from sunpack.repair.stage import ArchiveRepairStage
from sunpack.coordinator.resource_preflight import ResourcePreflightInspector
from sunpack.relations.stage import ArchiveRelationStage
from sunpack.coordinator.verification_stage import verify_and_project
from sunpack.coordinator.scheduling import (
    ConcurrencyScheduler,
    TaskExecutor,
    build_scheduler_profile_config,
    resolve_max_workers,
)
from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.support.output_inventory import OutputInventory
from sunpack.contracts.extraction import ExtractionResult
from sunpack.extraction.knowledge import write_extraction_result
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.extraction.progress import filter_extraction_manifest_payload, filter_extraction_outputs
from sunpack.passwords.directory_context import DirectoryPasswordContextStore
from sunpack.rename.scheduler import RenameScheduler
from sunpack.repair.candidate import RepairCandidate, candidate_feature_payload
from sunpack.repair.knowledge import (
    write_repair_archive_status,
    write_repair_candidate_log,
    write_repair_result,
)
from sunpack.verification import RecoveryAttempt, VerificationResult, VerificationScheduler, compare_attempts, rank_attempt
from sunpack.verification.comparison import score_verification_payload
from sunpack.contracts.verification import DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL, DECISION_REPAIR, DECISION_RETRY_EXTRACT
from sunpack.support.path_keys import absolute_path_key
from sunpack.support import repair_trace
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.i18n import I18nContext
from sunpack.config.advanced_defaults import advanced_config_value


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
    planned_out_dir: str = ""

    @property
    def outcome_kind(self) -> OutcomeKind:
        if terminal_failure_reason(self.result):
            return OutcomeKind.FAILURE
        if _verification_accepts_partial(self.verification):
            return OutcomeKind.PARTIAL_SUCCESS
        if self.result.success and _verification_accepts_complete_strict(self.verification):
            return OutcomeKind.COMPLETE_SUCCESS
        return OutcomeKind.FAILURE


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
        runtime_scheduler: ConcurrencyScheduler,
        rename_scheduler: RenameScheduler | None = None,
        config: dict | None = None,
        analysis_stage: ArchiveAnalysisStage | None = None,
        progress_reporter: Any | None = None,
        executor_pool=None,
    ):
        self.context = context
        self.extractor = extractor
        self.output_scan_policy = output_scan_policy
        self.runtime_scheduler = runtime_scheduler
        self.rename_scheduler = rename_scheduler or RenameScheduler()
        self.config = config or {}
        cli_config = self.config.get("cli") if isinstance(self.config.get("cli"), dict) else {}
        self.i18n = I18nContext(cli_config.get("language"))
        self.scheduler_config = self._build_scheduler_config(self.config)
        self.max_workers = resolve_max_workers()
        self.analysis_stage = analysis_stage or ArchiveAnalysisStage(
            self.config,
            workload_executor=self._execute_analysis_workload,
        )
        self.progress_reporter = progress_reporter
        self.executor_pool = executor_pool
        self.progress_round_index = 1
        self.progress_direct_mode = False
        self.relation_stage = ArchiveRelationStage()
        self.repair_stage = ArchiveRepairStage(self.config)
        self.repair_loop_limits = RepairLoopLimits.from_config(self.repair_stage.config)
        self.verifier = VerificationScheduler(self.config, password_session=self.extractor.password_session)
        self.directory_password_contexts = DirectoryPasswordContextStore(self.config)
        performance = advanced_config_value(("performance",))
        if isinstance(self.config.get("performance"), dict):
            performance.update(self.config["performance"])
        self.resource_inspector = ResourcePreflightInspector(
            password_session=self.extractor.password_session,
            rename_scheduler=self.rename_scheduler,
            precise_resource_min_size_mb=performance["precise_resource_min_size_mb"],
        )

    def set_progress_round(self, round_index: int, *, direct: bool = False) -> None:
        self.progress_round_index = max(1, int(round_index or 1))
        self.progress_direct_mode = bool(direct)

    def prepare_tasks(self, tasks: List[ArchiveTask]):
        self.relation_stage.resolve_tasks(tasks)
        # Physical source paths are immutable. Detected formats and logical
        # volume identities travel through ArchiveInputDescriptor/ArchiveState.

    def execute(
        self,
        tasks: List[ArchiveTask],
        *,
        default_output_dir_for_task=None,
    ) -> List[str]:
        if not tasks:
            if self.progress_reporter is not None:
                self.progress_reporter.begin_round(self.progress_round_index, [], direct=self.progress_direct_mode)
            return []

        self.prepare_tasks(tasks)
        tasks = self.analysis_stage.analyze_tasks(tasks)
        self.directory_password_contexts.annotate(tasks)
        output_dir_resolver = self.rename_scheduler.build_output_dir_resolver(
            tasks,
            default_output_dir_for_task or self.extractor.default_output_dir_for_task,
        )
        output_dir_resolver = self._cached_output_dir_resolver(output_dir_resolver)
        tasks = self._skip_tasks_inside_batch_outputs(tasks, output_dir_resolver)
        if self.progress_reporter is not None:
            self.progress_reporter.begin_round(self.progress_round_index, tasks, direct=self.progress_direct_mode)
        results = self._execute_ready_tasks(tasks, output_dir_resolver)

        output_dirs = []
        output_inventories: dict[str, OutputInventory] = {}
        for task, outcome in results:
            output_dir = self.collect_result(task, outcome)
            if output_dir:
                output_dirs.append(output_dir)
                self.directory_password_contexts.remember(output_dir, task)
                inventory = OutputInventory.from_value(
                    outcome.result.output_inventory or outcome.result.output_inventory_payload,
                    expected_root=output_dir,
                )
                if inventory is not None:
                    output_inventories[os.path.normcase(os.path.abspath(output_dir))] = inventory
        if isinstance(self.output_scan_policy, NestedOutputScanPolicy):
            return self.output_scan_policy.scan_roots_from_outputs(
                output_dirs,
                inventories=output_inventories,
            )
        return self.output_scan_policy.scan_roots_from_outputs(output_dirs)

    def _execute_ready_tasks(self, tasks: List[ArchiveTask], output_dir_resolver) -> list[tuple[ArchiveTask, BatchExtractionOutcome]]:
        ready_tasks: list[ArchiveTask] = []
        skipped_results: list[tuple[ArchiveTask, BatchExtractionOutcome]] = []
        for _index, task, _out_dir, preflight in self._inspect_tasks_before_extract(tasks, output_dir_resolver):
            if preflight.skip_result is not None:
                outcome = BatchExtractionOutcome(preflight.skip_result)
                skipped_results.append((task, outcome))
                self._report_task_finished(task, outcome)
                continue
            ready_tasks.append(task)

        if not ready_tasks:
            return skipped_results
        if len(ready_tasks) == 1:
            guard_enabled = bool(self._resource_guard_config().get("enabled", False))
            if guard_enabled or knowledge_view.resource_analysis(ready_tasks[0]):
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
            for task, outcome in guarded_results:
                self._report_task_finished(task, outcome)
        if not ready_tasks:
            return skipped_results

        executor = TaskExecutor(
            self.runtime_scheduler,
            max_workers=self.max_workers,
            executor_pool=self.executor_pool,
        )
        def execute_one(task, runtime_scheduler):
            planned_out_dir = output_dir_resolver(task)
            outcome = self._extract_verify_with_retries(task, planned_out_dir, runtime_scheduler)
            outcome.planned_out_dir = planned_out_dir
            self._report_task_finished(task, outcome)
            return task, outcome

        return skipped_results + executor.execute_all(
            ready_tasks,
            execute_one,
            workload_label="extraction",
        )

    def _report_task_started(self, task: ArchiveTask) -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.task_started(task, self.progress_round_index)

    def _report_task_finished(self, task: ArchiveTask, outcome: BatchExtractionOutcome) -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.task_finished(task, outcome, self.progress_round_index)

    def _report_task_status(self, task: ArchiveTask, state: str, detail: str = "") -> None:
        if self.progress_reporter is not None:
            self.progress_reporter.task_status(task, state, detail)

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
            analysis = knowledge_view.resource_analysis(task)
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
        performance = advanced_config_value(("performance",))
        if isinstance(config.get("performance"), dict):
            performance.update(config["performance"])
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
                self._report_task_started(task)
                out_dir = output_dir_resolver(task)
                results.append((index, task, out_dir, self.extractor.inspect(task, out_dir)))
            return results

        indexed = [_IndexedStageTask(index, task) for index, task in enumerate(tasks)]

        def inspect_one(item: _IndexedStageTask):
            self._report_task_started(item.task)
            out_dir = output_dir_resolver(item.task)
            return item.index, item.task, out_dir, self.extractor.inspect(item.task, out_dir)

        results = self._execute_indexed_stage(
            indexed,
            max_workers=max_workers,
            worker=inspect_one,
            workload_label="preflight-inspect",
        )
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
            workload_label="resource-preflight",
        )

    def _execute_indexed_stage(
        self,
        tasks: list[_IndexedStageTask],
        *,
        max_workers: int,
        worker,
        workload_label: str,
    ) -> list[Any]:
        executor = TaskExecutor(
            self.runtime_scheduler,
            max_workers=max_workers,
            executor_pool=self.executor_pool,
        )
        return executor.execute_all(tasks, worker, workload_label=workload_label)

    def _execute_analysis_workload(
        self,
        tasks,
        worker,
        *,
        max_workers: int,
        workload_label: str,
    ):
        executor = TaskExecutor(
            self.runtime_scheduler,
            max_workers=max_workers,
            executor_pool=self.executor_pool,
        )
        return executor.execute_all(tasks, worker, workload_label=workload_label)

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
        task.fact_bag.set(REPAIR_ENTERED_FACT, False)
        verification_config = self.verifier.config
        max_verification_retries = max(0, int(verification_config.get("max_retries", 0) or 0))
        cleanup_failed_output = bool(verification_config.get("cleanup_failed_output", True))
        attempts = max_verification_retries + 1
        last_outcome: BatchExtractionOutcome | None = None
        incumbent_outcome: BatchExtractionOutcome | None = None

        attempt_index = 0
        attempt_sequence = 0
        while attempt_index < attempts:
            self._report_task_status(task, "extracting")
            result = self.extractor.extract(task, out_dir, runtime_scheduler=runtime_scheduler)
            write_extraction_result(task, result)
            current_sequence = attempt_sequence
            attempt_sequence += 1
            if not result.success:
                self._report_task_status(task, "error", str(result.error or ""))
                verification = verify_and_project(self.verifier, task, result)
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
                if _verification_accepts_complete(verification):
                    selected = self._selected_acceptable_outcome(incumbent_outcome, current_outcome, out_dir)
                    if selected is not None:
                        return selected
                if verification.decision_hint == DECISION_REPAIR:
                    state = RepairLoopState(task, self.repair_loop_limits)
                    if self._comparison_no_improvement_patience_exhausted(
                        state,
                        current_outcome,
                        trigger="verification_comparison",
                    ):
                        selected = self._selected_acceptable_outcome(incumbent_outcome, current_outcome, out_dir, final=True)
                        return selected or current_outcome
                    if state.can_attempt(trigger="verification", failure=result):
                        task.fact_bag.set(REPAIR_ENTERED_FACT, True)
                        self._report_task_status(task, "repairing")
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
                            cleanup_shelved_outcome(incumbent_outcome, keep=handled)
                            return handled
                        if handled:
                            self._refresh_analysis_after_repair(task)
                            continue
                selected = self._selected_acceptable_outcome(incumbent_outcome, current_outcome, out_dir, final=True)
                if selected is not None:
                    return selected
                return current_outcome

            verification = verify_and_project(self.verifier, task, result)
            outcome = BatchExtractionOutcome(result=result, verification=verification, attempts=attempt_index + 1)
            self._annotate_recovery_outcome(task, outcome, source="original", round_index=current_sequence)
            if _verification_accepts_complete(verification):
                selected = self._selected_acceptable_outcome(incumbent_outcome, outcome, out_dir) or outcome
                cleanup_shelved_outcome(incumbent_outcome, keep=selected)
                return selected

            incumbent_outcome = self._select_better_recovery_outcome(incumbent_outcome, outcome)

            if verification.decision_hint == DECISION_REPAIR:
                state = RepairLoopState(task, self.repair_loop_limits)
                if self._comparison_no_improvement_patience_exhausted(
                    state,
                    outcome,
                    trigger="verification_comparison",
                ):
                    selected = self._selected_acceptable_outcome(incumbent_outcome, outcome, out_dir, final=True)
                    return selected or outcome
                if state.can_attempt(trigger="verification"):
                    task.fact_bag.set(REPAIR_ENTERED_FACT, True)
                    self._report_task_status(task, "repairing")
                    if self._repair_policy_disables_beam(task, result, verification):
                        handled = self._repair_after_verification_with_scheduler(
                            task,
                            result,
                            verification,
                            state,
                        )
                        if handled:
                            self._refresh_analysis_after_repair(task)
                            continue
                    elif self._beam_enabled():
                        shelve_outcome_if_needed(incumbent_outcome, out_dir)
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
                                cleanup_shelved_outcome(incumbent_outcome, keep=handled)
                                return handled
                            if handled:
                                self._refresh_analysis_after_repair(task)
                                continue
            selected = self._selected_acceptable_outcome(incumbent_outcome, outcome, out_dir, final=verification.decision_hint != DECISION_REPAIR)
            if selected is not None:
                return selected

            last_outcome = outcome
            if attempt_index >= max_verification_retries:
                break
            if verification.decision_hint not in {DECISION_RETRY_EXTRACT, DECISION_REPAIR} and not self._retry_on_verification_failure():
                break
            if cleanup_failed_output:
                remove_output(result.out_dir)
            attempt_index += 1

        selected = self._selected_acceptable_outcome(incumbent_outcome, last_outcome, out_dir, final=True)
        if selected is not None:
            return selected
        return last_outcome or BatchExtractionOutcome(
            result=ExtractionResult(
                success=False,
                archive=task.main_path,
                out_dir=out_dir,
                all_parts=task.all_parts,
                error=self.i18n.t("failure.verification_failed"),
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

    def _refresh_analysis_after_repair(self, task: ArchiveTask) -> None:
        try:
            refresh = getattr(self.analysis_stage, "refresh_task_analysis", None)
            if callable(refresh):
                refresh(task)
                return
            analyze_to_tasks = getattr(self.analysis_stage, "analyze_task_to_tasks", None)
            if callable(analyze_to_tasks):
                analyze_to_tasks(task)
                return
            analyze_task = getattr(self.analysis_stage, "analyze_task", None)
            if callable(analyze_task):
                analyze_task(task)
        except Exception as exc:
            _append_repair_candidate_log(task, {
                "phase": "analysis_refresh_failed",
                "error": str(exc),
            })

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
        repair_trace.write_probe_event("policy_probe_transition", {
            "run_id": _policy_probe_run_id(task),
            "query_id": f"{task.key or task.main_path}:{outcome.round_index}",
            "archive": task.main_path,
            "archive_key": task.key,
            "logical_name": str(task.logical_name or ""),
            "round": int(outcome.round_index or 0),
            "attempt_id": outcome.attempt_id,
            "attempt_source": outcome.attempt_source,
            "repair_module": outcome.repair_module,
            "patch_digest": outcome.patch_digest,
            "patch_lineage_count": len(outcome.patch_lineage or []),
            "extraction": _extraction_summary(outcome.result),
            "verification": _verification_summary(outcome.verification),
            "comparison": dict(outcome.comparison or {}),
            "continue_repair": bool(
                outcome.verification is not None
                and getattr(outcome.verification, "decision_hint", "") == DECISION_REPAIR
            ),
        })

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
        *,
        final: bool = False,
    ) -> BatchExtractionOutcome | None:
        selected = self._select_better_recovery_outcome(incumbent, challenger)
        if selected is None or selected.verification is None:
            return None
        if not self._outcome_accepts(selected, final=final):
            return None
        _ensure_recovery_rank(selected)
        promote_recovery_outcome(selected, out_dir)
        if self._accept_partial_output(selected.result, selected.verification):
            self._filter_partial_outputs(selected.result)
        return selected

    def _outcome_accepts(self, outcome: BatchExtractionOutcome, *, final: bool = False) -> bool:
        verification = outcome.verification
        if verification is None:
            return False
        if outcome.result.success and _verification_accepts_complete(verification):
            return True
        if self._repair_continue_after_partial() and not final:
            return False
        return self._accept_partial_output(outcome.result, verification)

    def _repair_continue_after_partial(self) -> bool:
        repair_config = self.repair_stage.config if isinstance(getattr(self.repair_stage, "config", None), dict) else {}
        return bool(repair_config.get("continue_after_partial", True))

    def _recovery_min_improvement(self) -> float:
        verification_config = self.verifier.config
        try:
            return max(0.0, float(verification_config["recovery_min_improvement"] or 0.0))
        except (TypeError, ValueError):
            return 0.0

    def _comparison_no_improvement_patience_exhausted(
        self,
        loop_state: RepairLoopState,
        outcome: BatchExtractionOutcome,
        *,
        trigger: str,
    ) -> bool:
        comparison = outcome.comparison if isinstance(outcome.comparison, dict) else {}
        if str(comparison.get("stop_reason") or "") != "no_improvement":
            loop_state.record_recovery_comparison(comparison, trigger=trigger)
            return False
        exhausted = loop_state.record_recovery_comparison(comparison, trigger=trigger)
        _append_repair_candidate_log(loop_state.task, {
            "phase": "comparison_no_improvement_patience",
            "trigger": trigger,
            "exhausted": bool(exhausted),
            "comparison": dict(comparison),
        })
        return exhausted

    def _retry_on_verification_failure(self) -> bool:
        return bool(self.verifier.config.get("retry_on_verification_failure", True))

    def _beam_enabled(self) -> bool:
        beam = self.repair_stage.config.get("beam") if isinstance(self.repair_stage.config.get("beam"), dict) else {}
        return bool(beam.get("enabled", False)) and self.repair_stage.scheduler is not None

    def _repair_policy_disables_beam(
        self,
        task: ArchiveTask,
        result: ExtractionResult,
        verification: VerificationResult,
    ) -> bool:
        repair_trace.write_probe_event("policy_probe_beam_gate_start", {
            "run_id": _policy_probe_run_id(task),
            "query_id": f"{task.key or task.main_path}:beam_gate",
            "archive": task.main_path,
            "archive_key": task.key,
            "decision_hint": getattr(verification, "decision_hint", ""),
        })
        checker = getattr(self.repair_stage, "policy_active_for_verification", None)
        if not callable(checker):
            repair_trace.write_probe_event("policy_probe_beam_gate_done", {
                "run_id": _policy_probe_run_id(task),
                "query_id": f"{task.key or task.main_path}:beam_gate",
                "active": False,
                "reason": "missing_checker",
            })
            return False
        active = bool(checker(task, result, verification))
        repair_trace.write_probe_event("policy_probe_beam_gate_done", {
            "run_id": _policy_probe_run_id(task),
            "query_id": f"{task.key or task.main_path}:beam_gate",
            "active": active,
        })
        return active

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
        if self._repair_policy_disables_beam(task, result, verification):
            return self._repair_after_verification_with_scheduler(
                task,
                result,
                verification,
                loop_state,
            )
        if not self._beam_enabled():
            return False
        shelve_outcome_if_needed(incumbent_outcome, out_dir)
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

    def _repair_after_verification_with_scheduler(
        self,
        task: ArchiveTask,
        result: ExtractionResult,
        verification: VerificationResult,
        loop_state: RepairLoopState,
    ) -> bool:
        repair_trace.write_probe_event("policy_probe_scheduler_repair_start", {
            "run_id": _policy_probe_run_id(task),
            "query_id": f"{task.key or task.main_path}:scheduler_repair",
            "archive": task.main_path,
            "archive_key": task.key,
            "decision_hint": getattr(verification, "decision_hint", ""),
        })
        repair_result = self.repair_stage.repair_after_verification_assessment_result(task, result, verification)
        handled = bool(loop_state.record_result(repair_result, trigger="verification_policy"))
        repair_trace.write_probe_event("policy_probe_scheduler_repair_done", {
            "run_id": _policy_probe_run_id(task),
            "query_id": f"{task.key or task.main_path}:scheduler_repair",
            "handled": handled,
            "result_status": getattr(repair_result, "status", "") if repair_result is not None else "",
            "result_module": getattr(repair_result, "module_name", "") if repair_result is not None else "",
        })
        return handled

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
        active = getattr(scheduler, "policy_active_for_job", None)
        if callable(active) and active(job):
            return None

        evaluated: dict[str, tuple[RepairCandidate, ExtractionResult, VerificationResult, str]] = {}
        beam = RepairBeamLoop.from_config(
            scheduler,
            self.repair_stage.config,
            analyze=lambda candidate: {"confidence": float(candidate.confidence or 0.0)},
            assess=lambda item: self._assess_beam_candidate(task, item, out_dir, runtime_scheduler, evaluated),
            should_assess=self._beam_candidate_should_assess,
            score_assessment=score_verification_payload,
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
        _append_beam_run_candidate_log(task, run, phase="beam_run")
        _append_repair_candidate_log(task, {
            "phase": "beam_stop_reason",
            "reason": str(getattr(run, "stop_reason", "") or ""),
            "rounds": len(getattr(run, "rounds", []) or []),
            "rounds_without_global_improvement": int(getattr(run, "rounds_without_global_improvement", 0) or 0),
            "frontier_exhausted": bool(getattr(run, "frontier_exhausted", False)),
            "best_state": _beam_state_summary(run.best_state),
        })
        terminal_result = _first_terminal_repair_result(run.terminal_results)
        if terminal_result is not None and not evaluated:
            write_repair_result(task, terminal_result, phase="beam_terminal")
            return _BeamRepairTerminal(repair_result=terminal_result)
        best = run.best_state
        if best is None:
            if terminal_result is not None:
                write_repair_result(task, terminal_result, phase="beam_terminal")
                return _BeamRepairTerminal(repair_result=terminal_result)
            cleanup_beam_evaluations(evaluated)
            return None

        digest = _source_input_digest(best.source_input)
        selected = evaluated.get(digest)
        if selected is None and best.archive_state:
            digest = _source_input_digest({"archive_state": best.archive_state})
            selected = evaluated.get(digest)
        if selected is None:
            cleanup_beam_evaluations(evaluated)
            _append_repair_candidate_log(task, {
                "phase": "beam_no_selected_evaluation",
                "best_state": _beam_state_summary(best),
                "evaluated_count": len(evaluated),
            })
            return None
        candidate, extracted, assessed, temp_dir = selected
        cleanup_beam_evaluations({
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
        _append_repair_candidate_log(task, {
            "phase": "beam_evaluation",
            "candidate": candidate_feature_payload(evaluation.candidate),
            "verification": _verification_summary(evaluation.verification),
            "extraction": _extraction_summary(evaluation.result),
            "temp_dir": evaluation.temp_dir,
        })
        self._annotate_recovery_outcome(
            task,
            beam_outcome,
            source="beam",
            round_index=round_index,
            repair_module=evaluation.candidate.module_name,
        )
        selected = self._select_better_recovery_outcome(incumbent_outcome, beam_outcome)
        if selected is not beam_outcome:
            if self._comparison_no_improvement_patience_exhausted(
                loop_state,
                beam_outcome,
                trigger="verification_beam_comparison",
            ):
                _append_repair_candidate_log(task, {
                    "phase": "beam_stop",
                    "reason": "comparison_no_improvement_patience",
                    "candidate": candidate_feature_payload(evaluation.candidate),
                    "comparison": dict(beam_outcome.comparison),
                })
                cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
                    evaluation.candidate,
                    evaluation.result,
                    evaluation.verification,
                    evaluation.temp_dir,
                )})
                return False
            _append_repair_candidate_log(task, {
                "phase": "beam_rejected",
                "reason": "no_repair_improvement",
                "candidate": candidate_feature_payload(evaluation.candidate),
                "comparison": dict(beam_outcome.comparison),
            })
            cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
                evaluation.candidate,
                evaluation.result,
                evaluation.verification,
                evaluation.temp_dir,
            )})
            return False
        self._apply_beam_candidate_to_task(task, evaluation.candidate)
        if not loop_state.record_result(evaluation.repair_result, trigger="verification_beam"):
            cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
                evaluation.candidate,
                evaluation.result,
                evaluation.verification,
                evaluation.temp_dir,
            )})
            return False

        if _verification_accepts_complete(evaluation.verification):
            _append_repair_candidate_log(task, {
                "phase": "beam_selected",
                "reason": "complete_repair",
                "candidate": candidate_feature_payload(evaluation.candidate),
                "verification": _verification_summary(evaluation.verification),
            })
            if self._accept_partial_output(evaluation.result, evaluation.verification):
                self._filter_partial_outputs(evaluation.result)
            final_result = promote_beam_output(evaluation.result, evaluation.temp_dir, out_dir)
            beam_outcome.result = final_result
            promote_recovery_outcome(beam_outcome, out_dir)
            return beam_outcome

        if _verification_accepts_partial(evaluation.verification) and not loop_state.can_attempt(trigger="verification_beam_best_partial"):
            _append_repair_candidate_log(task, {
                "phase": "beam_selected",
                "reason": "repair_budget_best_partial",
                "candidate": candidate_feature_payload(evaluation.candidate),
                "verification": _verification_summary(evaluation.verification),
            })
            if self._accept_partial_output(evaluation.result, evaluation.verification):
                self._filter_partial_outputs(evaluation.result)
            final_result = promote_beam_output(evaluation.result, evaluation.temp_dir, out_dir)
            beam_outcome.result = final_result
            promote_recovery_outcome(beam_outcome, out_dir)
            return beam_outcome

        if not bool(beam_outcome.comparison.get("should_continue_repair", True)):
            if not self._comparison_no_improvement_patience_exhausted(
                loop_state,
                beam_outcome,
                trigger="verification_beam_comparison",
            ):
                _append_repair_candidate_log(task, {
                    "phase": "beam_continue",
                    "reason": "comparison_no_improvement_under_patience",
                    "candidate": candidate_feature_payload(evaluation.candidate),
                    "comparison": dict(beam_outcome.comparison),
                })
                cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
                    evaluation.candidate,
                    evaluation.result,
                    evaluation.verification,
                    evaluation.temp_dir,
                )})
                remove_output(out_dir)
                return True
            _append_repair_candidate_log(task, {
                "phase": "beam_stop",
                "reason": "comparison_should_not_continue",
                "candidate": candidate_feature_payload(evaluation.candidate),
                "comparison": dict(beam_outcome.comparison),
            })
            cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
                evaluation.candidate,
                evaluation.result,
                evaluation.verification,
                evaluation.temp_dir,
            )})
            return False

        cleanup_beam_evaluations({evaluation.outcome.attempt_id: (
            evaluation.candidate,
            evaluation.result,
            evaluation.verification,
            evaluation.temp_dir,
        )})
        remove_output(out_dir)
        _append_repair_candidate_log(task, {
            "phase": "beam_continue",
            "candidate": candidate_feature_payload(evaluation.candidate),
            "verification": _verification_summary(evaluation.verification),
        })
        return True

    def _apply_beam_candidate_to_task(self, task: ArchiveTask, candidate: RepairCandidate) -> None:
        state = self._archive_state_for_candidate(task, candidate)
        if state is not None:
            task.set_archive_state(state)
        else:
            task.set_archive_input(candidate.repaired_input)
        write_repair_archive_status(task, repaired=True)

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
                    archive_input=knowledge_view.source_input(task),
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
            return verify_and_project(self.verifier, task, result)
        light_config = dict(self.config)
        light_config["verification"] = verification_config
        return verify_and_project(VerificationScheduler(light_config, password_session=self.extractor.password_session), task, result)

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
        temp_dir = f"{out_dir}.beam_{len(evaluated) + 1:02d}_{item.candidate.module_name}"
        evaluator = RepairRuntimeTransitionEvaluator(
            extractor=self.extractor,
            verifier=self.verifier,
            repair_stage=self.repair_stage,
            analysis_stage=self.analysis_stage,
            runtime_scheduler=runtime_scheduler,
            light_verify=self._verify_beam_candidate_light,
            needs_full_verification=lambda candidate, light: self._beam_candidate_needs_full_verification(
                RepairBeamCandidate(candidate=candidate, state=item.state, score=item.score),
                light,
            ),
            source_digest=_source_input_digest,
        )
        transition = evaluator.evaluate(task, item.candidate, temp_dir=temp_dir)
        evaluated[transition.source_digest] = (
            item.candidate,
            transition.result,
            transition.verification,
            transition.temp_dir,
        )
        return transition.verification

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
        _write_repair_candidate_jsonl(task, outcome, out_dir)
        repair_trace.write_probe_event("policy_probe_terminal", {
            "run_id": _policy_probe_run_id(task),
            "archive": task.main_path,
            "archive_key": task.key,
            "logical_name": str(task.logical_name or ""),
            "attempt_id": outcome.attempt_id,
            "attempt_source": outcome.attempt_source,
            "round": int(outcome.round_index or 0),
            "repair_module": outcome.repair_module,
            "patch_digest": outcome.patch_digest,
            "outcome_kind": outcome.outcome_kind.value,
            "extraction": _extraction_summary(outcome.result),
            "verification": _verification_summary(outcome.verification) if outcome.verification is not None else {},
            "comparison": dict(outcome.comparison or {}),
            "candidate_log_count": len(knowledge_view.repair_candidate_log(task)),
            "repair_candidate_log_path": knowledge_view.repair_candidate_log_path(task),
        })

        cleanup = cleanup_failed_output_if_eligible(
            out_dir,
            planned_output_dir=outcome.planned_out_dir,
            failed=outcome.outcome_kind == OutcomeKind.FAILURE,
            repair_entered=bool(task.fact_bag.get(REPAIR_ENTERED_FACT)),
        )
        diagnostics = res.diagnostics if isinstance(res.diagnostics, dict) else {}
        res.diagnostics = {**diagnostics, "failed_output_cleanup": cleanup.to_dict()}

        with self.context.lock:
            if outcome.outcome_kind == OutcomeKind.COMPLETE_SUCCESS:
                self.context.success_count += 1
                self.context.processed_keys.add(task.key)
                self.context.unpacked_archives.append(res.all_parts or task.all_parts)
                self.context.flatten_candidates.add(out_dir)
                self.context.target_results.append(TargetRunResult(
                    input_path=task.main_path,
                    outcome_kind=OutcomeKind.COMPLETE_SUCCESS,
                    output_dir=out_dir,
                    verification=_verification_payload(outcome.verification) if outcome.verification is not None else {},
                ))
                return out_dir
            if outcome.outcome_kind == OutcomeKind.PARTIAL_SUCCESS:
                if outcome.verification is not None:
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
                self.context.target_results.append(TargetRunResult(
                    input_path=task.main_path,
                    outcome_kind=OutcomeKind.PARTIAL_SUCCESS,
                    output_dir=out_dir,
                    verification=_verification_payload(outcome.verification) if outcome.verification is not None else {},
                    error=str(res.error or ""),
                ))
                return out_dir
            self.context.failed_tasks.append(self._failure_message(task, outcome))
            if outcome.result.failure is not None:
                self.context.failures.append(outcome.result.failure)
            self.context.target_results.append(TargetRunResult(
                input_path=task.main_path,
                outcome_kind=OutcomeKind.FAILURE,
                output_dir=out_dir,
                verification=_verification_payload(outcome.verification) if outcome.verification is not None else {},
                error=str(res.error or ""),
                failure=outcome.result.failure,
            ))
            return None

    def _failure_message(self, task: ArchiveTask, outcome: BatchExtractionOutcome) -> str:
        name = os.path.basename(task.main_path)
        if outcome.result.success and outcome.verification is not None and not _verification_accepts(outcome.verification):
            return f"{name} [{self._verification_failure_summary(outcome)}]"
        return f"{name} [{outcome.result.error}]"

    def _verification_failure_summary(self, outcome: BatchExtractionOutcome) -> str:
        verification = outcome.verification
        if verification is None:
            return self.i18n.t("failure.verification_failed")
        steps = "; ".join(f"{step.method}:{step.status}" for step in verification.steps) or "none"
        return self.i18n.t(
            "failure.verification_failed_detail",
            completeness=getattr(verification, "completeness", ""),
            integrity=getattr(verification, "assessment_status", ""),
            decision=getattr(verification, "decision_hint", ""),
        ) + (
            f", coverage={getattr(getattr(verification, 'archive_coverage', None), 'completeness', '')}, "
            f"attempts={outcome.attempts}, steps={steps}"
        )


def _verification_accepts(verification: VerificationResult | Any) -> bool:
    decision = getattr(verification, "decision_hint", "")
    return decision in {DECISION_ACCEPT, DECISION_ACCEPT_PARTIAL}


def _verification_accepts_complete(verification: VerificationResult | Any) -> bool:
    decision = getattr(verification, "decision_hint", "")
    status = getattr(verification, "assessment_status", "")
    return decision == DECISION_ACCEPT or status == "complete"


def _verification_accepts_complete_strict(verification: VerificationResult | Any) -> bool:
    if verification is None:
        return False
    # The verifier's decision is the contract boundary. Some extraction backends
    # cannot provide per-file coverage, so an accepted result may legitimately
    # carry an "unknown" assessment while still being a full success.
    return getattr(verification, "decision_hint", "") == DECISION_ACCEPT


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


def _policy_probe_run_id(task: ArchiveTask) -> str:
    return str(
        os.environ.get("SUNPACK_REPAIR_POLICY_PROBE_RUN_ID")
        or knowledge_view.sample_id(task)
        or task.key
        or task.main_path
    )


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


def _append_beam_run_candidate_log(task: ArchiveTask, run: Any, *, phase: str) -> None:
    for round_result in getattr(run, "rounds", []) or []:
        for item in getattr(round_result, "candidates", []) or []:
            candidate = getattr(item, "candidate", None)
            if candidate is None:
                continue
            _append_repair_candidate_log(task, {
                "phase": phase,
                "round": int(getattr(round_result, "round_index", 0) or 0),
                "candidate": candidate_feature_payload(candidate),
                "beam_score": float(getattr(item, "score", 0.0) or 0.0),
                "analyze": dict(getattr(item, "analyze", {}) or {}),
                "assessment": dict(getattr(item, "assessment", {}) or {}),
                "state_in": _beam_state_summary(getattr(item, "state", None)),
            })


def _append_repair_candidate_log(task: ArchiveTask, payload: dict[str, Any]) -> None:
    fact_bag = getattr(task, "fact_bag", None)
    if fact_bag is None or not hasattr(fact_bag, "set"):
        return
    log = knowledge_view.repair_candidate_log(task)
    log.append(_jsonable_candidate_log_payload(payload))
    limit = 200
    fact_bag.set("repair.candidate_log", log[-limit:])
    write_repair_candidate_log(task, log[-limit:])


def _write_repair_candidate_jsonl(task: ArchiveTask, outcome: BatchExtractionOutcome, out_dir: str) -> str:
    entries = knowledge_view.repair_candidate_log(task)
    if not entries:
        return ""
    target_dir = Path(out_dir) / ".sunpack"
    target = target_dir / "repair_candidates.jsonl"
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as handle:
            for record in _repair_candidate_jsonl_records(task, outcome, entries):
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str))
                handle.write("\n")
        task.fact_bag.set("repair.candidate_log_path", str(target))
        write_repair_candidate_log(task, entries, path=str(target))
        return str(target)
    except OSError:
        return ""


def _repair_candidate_jsonl_records(
    task: ArchiveTask,
    outcome: BatchExtractionOutcome,
    entries: list[Any],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            continue
        base = _candidate_record_base(task, outcome, entry, index=index)
        selection = entry.get("selection") if isinstance(entry.get("selection"), dict) else {}
        selection_candidates = selection.get("candidates") if isinstance(selection.get("candidates"), list) else []
        if selection_candidates:
            selected_module = str(selection.get("selected_module") or "")
            selected_id = _candidate_id(entry.get("candidate") if isinstance(entry.get("candidate"), dict) else {})
            for candidate in selection_candidates:
                if not isinstance(candidate, dict):
                    continue
                candidate_id = _candidate_id(candidate)
                selected = bool(candidate_id and candidate_id == selected_id) or (
                    not selected_id and selected_module and str(candidate.get("module") or "") == selected_module
                )
                records.append({
                    **base,
                    "phase": f"{base['phase']}.candidate",
                    "candidate": dict(candidate),
                    "selected": selected,
                    "rejected": not selected,
                    "selection": {
                        key: value
                        for key, value in selection.items()
                        if key != "candidates"
                    },
                })
            continue
        generation = entry.get("generation") if isinstance(entry.get("generation"), dict) else {}
        generation_candidates = generation.get("candidates") if isinstance(generation.get("candidates"), list) else []
        if generation_candidates:
            for candidate in generation_candidates:
                if not isinstance(candidate, dict):
                    continue
                records.append({
                    **base,
                    "phase": f"{base['phase']}.generated",
                    "candidate": dict(candidate),
                    "selected": False,
                    "rejected": False,
                    "generation": {
                        key: value
                        for key, value in generation.items()
                        if key != "candidates"
                    },
                })
        capability = entry.get("capability") if isinstance(entry.get("capability"), dict) else {}
        module_records = capability.get("modules") if isinstance(capability.get("modules"), list) else []
        for module in module_records:
            if not isinstance(module, dict):
                continue
            records.append({
                **base,
                "phase": f"{base['phase']}.module_feedback",
                "module_feedback": dict(module),
                "selected": bool(module.get("selected")),
                "rejected": not bool(module.get("selected")),
            })
        if generation_candidates or module_records:
            continue
        records.append({
            **base,
            "candidate": dict(entry.get("candidate") or {}) if isinstance(entry.get("candidate"), dict) else {},
            "selected": _candidate_log_selected(entry),
            "rejected": _candidate_log_rejected(entry),
        })
    return records


def _candidate_record_base(
    task: ArchiveTask,
    outcome: BatchExtractionOutcome,
    entry: dict[str, Any],
    *,
    index: int,
) -> dict[str, Any]:
    return {
        "version": 1,
        "index": index,
        "archive": task.main_path,
        "archive_key": task.key,
        "logical_name": str(task.logical_name or ""),
        "attempt_id": str(entry.get("attempt_id") or outcome.attempt_id or ""),
        "attempt_source": outcome.attempt_source,
        "round": int(entry.get("round", outcome.round_index or 0) or 0),
        "phase": str(entry.get("phase") or ""),
        "repair_module": str(entry.get("repair_module") or outcome.repair_module or ""),
        "patch_digest": str(entry.get("patch_digest") or outcome.patch_digest or ""),
        "verification": dict(entry.get("verification") or _verification_summary(outcome.verification)) if outcome.verification is not None else dict(entry.get("verification") or {}),
        "extraction": dict(entry.get("extraction") or _extraction_summary(outcome.result)),
        "comparison": dict(entry.get("comparison") or outcome.comparison),
        "reason": str(entry.get("reason") or ""),
    }


def _candidate_log_selected(entry: dict[str, Any]) -> bool:
    phase = str(entry.get("phase") or "")
    return phase in {"beam_selected", "scheduler_repair"} or bool(entry.get("selected"))


def _candidate_log_rejected(entry: dict[str, Any]) -> bool:
    phase = str(entry.get("phase") or "")
    return phase in {"beam_rejected", "beam_stop"} or bool(entry.get("rejected"))


def _candidate_id(candidate: dict[str, Any]) -> str:
    return str(candidate.get("candidate_id") or "")


def _jsonable_candidate_log_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(payload, ensure_ascii=False, default=str))


def _beam_state_summary(state: Any) -> dict[str, Any]:
    if state is None:
        return {}
    return {
        "digest": getattr(state, "digest", ""),
        "format": getattr(state, "format", ""),
        "round_index": int(getattr(state, "round_index", 0) or 0),
        "score": float(getattr(state, "score", 0.0) or 0.0),
        "completeness": float(getattr(state, "completeness", 0.0) or 0.0),
        "recoverable_upper_bound": float(getattr(state, "recoverable_upper_bound", 1.0) or 1.0),
        "assessment_status": str(getattr(state, "assessment_status", "") or ""),
        "source_integrity": str(getattr(state, "source_integrity", "") or ""),
        "decision_hint": str(getattr(state, "decision_hint", "") or ""),
        "actions": list(getattr(state, "actions", []) or []),
    }


def _verification_summary(verification: VerificationResult | Any) -> dict[str, Any]:
    coverage = getattr(verification, "archive_coverage", None)
    output_quality = _output_quality_payload(verification)
    return {
        "decision_hint": getattr(verification, "decision_hint", ""),
        "assessment_status": getattr(verification, "assessment_status", ""),
        "source_integrity": getattr(verification, "source_integrity", ""),
        "completeness": float(getattr(verification, "completeness", 0.0) or 0.0),
        "recoverable_upper_bound": float(getattr(verification, "recoverable_upper_bound", 1.0) or 1.0),
        "output_quality_score": output_quality["score"],
        "output_file_count": output_quality["file_count"],
        "output_total_bytes": output_quality["total_bytes"],
        "output_complete_ratio": output_quality["complete_ratio"],
        "output_failed_ratio": output_quality["failed_ratio"],
        "output_empty": output_quality["empty"],
        "output_confidence": output_quality["confidence"],
        "output_quality": output_quality,
        "complete_files": int(getattr(verification, "complete_files", 0) or 0),
        "partial_files": int(getattr(verification, "partial_files", 0) or 0),
        "failed_files": int(getattr(verification, "failed_files", 0) or 0),
        "missing_files": int(getattr(verification, "missing_files", 0) or 0),
        "repair_hints": dict(getattr(verification, "repair_hints", {}) or {}),
        "archive_coverage": {
            "completeness": float(getattr(coverage, "completeness", 0.0) or 0.0) if coverage is not None else 0.0,
            "expected_files": int(getattr(coverage, "expected_files", 0) or 0) if coverage is not None else 0,
            "complete_files": int(getattr(coverage, "complete_files", 0) or 0) if coverage is not None else 0,
            "partial_files": int(getattr(coverage, "partial_files", 0) or 0) if coverage is not None else 0,
            "failed_files": int(getattr(coverage, "failed_files", 0) or 0) if coverage is not None else 0,
            "missing_files": int(getattr(coverage, "missing_files", 0) or 0) if coverage is not None else 0,
        },
    }


def _extraction_summary(result: ExtractionResult) -> dict[str, Any]:
    diagnostics = result.diagnostics if isinstance(result.diagnostics, dict) else {}
    worker = diagnostics.get("result") if isinstance(diagnostics.get("result"), dict) else {}
    return {
        "success": bool(result.success),
        "partial_outputs": bool(result.partial_outputs),
        "error": result.error,
        "progress_manifest": result.progress_manifest,
        "failure_stage": worker.get("failure_stage") or diagnostics.get("failure_stage"),
        "failure_kind": worker.get("failure_kind") or diagnostics.get("failure_kind"),
        "native_status": worker.get("native_status"),
        "files_written": worker.get("files_written"),
        "bytes_written": worker.get("bytes_written"),
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
    output_quality = _output_quality_payload(verification)
    return {
        "completeness": verification.completeness,
        "recoverable_upper_bound": verification.recoverable_upper_bound,
        "assessment_status": verification.assessment_status,
        "source_integrity": verification.source_integrity,
        "decision_hint": verification.decision_hint,
        "output_quality_score": output_quality["score"],
        "output_file_count": output_quality["file_count"],
        "output_total_bytes": output_quality["total_bytes"],
        "output_complete_ratio": output_quality["complete_ratio"],
        "output_failed_ratio": output_quality["failed_ratio"],
        "output_empty": output_quality["empty"],
        "output_confidence": output_quality["confidence"],
        "output_quality": output_quality,
        "repair_hints": dict(getattr(verification, "repair_hints", {}) or {}),
        "archive_coverage": _coverage_payload(verification),
        "files": _file_recovery_items(verification),
    }


def _output_quality_payload(verification: VerificationResult | Any) -> dict[str, Any]:
    return {
        "score": float(getattr(verification, "output_quality_score", 0.0) or 0.0),
        "file_count": int(getattr(verification, "output_file_count", 0) or 0),
        "total_bytes": int(getattr(verification, "output_total_bytes", 0) or 0),
        "complete_ratio": float(getattr(verification, "output_complete_ratio", 0.0) or 0.0),
        "failed_ratio": float(getattr(verification, "output_failed_ratio", 0.0) or 0.0),
        "empty": bool(getattr(verification, "output_empty", True)),
        "confidence": float(getattr(verification, "output_confidence", 0.0) or 0.0),
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
        "repair_candidate_log": knowledge_view.repair_candidate_log(task),
        "repair_candidate_log_path": knowledge_view.repair_candidate_log_path(task),
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
