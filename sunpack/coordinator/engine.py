from __future__ import annotations

import copy
import os
import queue
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from sunpack.analysis.stage import ArchiveAnalysisStage
from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse, PipelineTarget
from sunpack.contracts.results import OutcomeKind, RunSummary
from sunpack.contracts.run_context import RunContext
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner
from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.coordinator.nested_extraction_policy import NestedExtractionPolicy
from sunpack.coordinator.recursion import RecursionController
from sunpack.coordinator.reporting import RunReporter
from sunpack.coordinator.scheduling import (
    ConcurrencyScheduler,
    TaskExecutor,
    build_scheduler_profile_config,
    resolve_max_workers,
)
from sunpack.config.advanced_defaults import advanced_config_value
from sunpack.coordinator.space_guard import ExtractionSpaceGuard
from sunpack.coordinator.task_scan import ArchiveTaskScanner
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.i18n import I18nContext
from sunpack.postprocess.actions import PostProcessActions
from sunpack.rename.scheduler import RenameScheduler
from sunpack.support.output_paths import default_output_dir_for_task
from sunpack.support.path_keys import path_key
from sunpack.support.archive_sessions import clear_archive_sessions


@dataclass
class _Submission:
    request_id: str
    targets: tuple[PipelineTarget, ...]
    direct: bool
    defer_postprocess: bool
    user_passwords: tuple[str, ...]
    builtin_passwords: tuple[str, ...]
    future: Future


class PipelineHandle:
    def __init__(self, engine: "PipelineEngine", submission: _Submission):
        self._engine = engine
        self._submission = submission
        self._finalize_lock = threading.Lock()
        self._finalized = not submission.defer_postprocess

    @property
    def request_id(self) -> str:
        return self._submission.request_id

    def result(self, timeout: float | None = None) -> PipelineResponse:
        return self._submission.future.result(timeout=timeout)

    def finalize(self, output_path_map: Mapping[str, str] | None = None) -> PipelineResponse:
        response = self.result()
        with self._finalize_lock:
            if not self._finalized:
                self._engine.finalize(response, output_path_map=output_path_map)
                self._finalized = True
        return response


class PipelineEngine:
    """Process-scoped pipeline runtime with asynchronous micro-batch intake."""

    _STOP = object()

    def __init__(self, config: dict):
        self.config = config
        pipeline_config = config.get("pipeline") if isinstance(config.get("pipeline"), dict) else {}
        self.batch_window_seconds = max(0.0, float(pipeline_config["batch_window_seconds"]))
        self.max_batch_requests = max(1, int(pipeline_config["max_batch_requests"]))
        queue_capacity = max(1, int(pipeline_config["queue_capacity"]))
        self._queue: queue.Queue = queue.Queue(maxsize=queue_capacity)
        self._runtime = _PipelineRuntime(config)
        self._thread: threading.Thread | None = None
        self._lifecycle_lock = threading.Lock()
        self._pressure_lock = threading.Lock()
        self._active_request_count = 0
        self._password_source_lock = threading.Lock()
        self._user_passwords = tuple(config.get("user_passwords", []) or [])
        self._builtin_passwords = tuple(config.get("builtin_passwords", []) or [])
        self._started = False
        self._accepting = False
        self._closed = False

    @property
    def extractor(self) -> ExtractionScheduler:
        return self._runtime.extractor

    @property
    def batch_runner(self) -> ExtractionBatchRunner:
        return self._runtime.batch_runner

    @property
    def resource_scheduler(self) -> ConcurrencyScheduler:
        return self._runtime.resource_scheduler

    @property
    def task_scanner(self) -> ArchiveTaskScanner:
        return self._runtime.task_scanner

    @property
    def output_scan_policy(self) -> NestedOutputScanPolicy:
        return self._runtime.output_scan_policy

    @property
    def recent_passwords(self) -> list[str]:
        return list(self.extractor.recent_passwords)

    def is_idle(self) -> bool:
        with self._pressure_lock:
            return self._active_request_count == 0 and self._queue.empty()

    def start(self) -> "PipelineEngine":
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("PipelineEngine is closed")
            if self._started:
                return self
            self._runtime.start()
            self._started = True
            self._accepting = True
            self._thread = threading.Thread(target=self._dispatch_loop, name="sunpack-pipeline", daemon=True)
            self._thread.start()
        return self

    def submit(
        self,
        targets: Iterable[str | PipelineTarget],
        *,
        direct: bool = False,
        defer_postprocess: bool = False,
    ) -> PipelineHandle:
        normalized = tuple(self._normalize_target(target) for target in targets)
        if not normalized:
            raise ValueError("PipelineEngine.submit requires at least one target")
        with self._password_source_lock:
            user_passwords = self._user_passwords
            builtin_passwords = self._builtin_passwords
        submission = _Submission(
            request_id=uuid.uuid4().hex,
            targets=normalized,
            direct=bool(direct),
            defer_postprocess=bool(defer_postprocess),
            user_passwords=user_passwords,
            builtin_passwords=builtin_passwords,
            future=Future(),
        )
        with self._lifecycle_lock:
            if not self._started or not self._accepting:
                raise RuntimeError("PipelineEngine must be started before submit")
            self._queue.put(submission)
            self._sync_pipeline_pressure()
        return PipelineHandle(self, submission)

    def update_password_sources(self, *, user_passwords: Iterable[str], builtin_passwords: Iterable[str]) -> None:
        with self._password_source_lock:
            self._user_passwords = tuple(user_passwords)
            self._builtin_passwords = tuple(builtin_passwords)

    def reconfigure_request(self, config: dict) -> None:
        """Refresh request-scoped config while preserving long-lived native workers."""
        _replace_mapping_in_place(self.config, config)
        cli_config = self.config.get("cli") if isinstance(self.config.get("cli"), dict) else {}
        self._runtime.quiet = bool(cli_config.get("quiet", False))
        self._runtime.verbose = bool(cli_config.get("verbose", False))

    def finalize(
        self,
        response: PipelineResponse,
        *,
        output_path_map: Mapping[str, str] | None = None,
    ) -> None:
        mapping = {
            path_key(old): os.path.abspath(new)
            for old, new in (output_path_map or {}).items()
        }
        def remap(path: str) -> str:
            normalized = os.path.abspath(path)
            exact = mapping.get(path_key(normalized))
            if exact:
                return exact
            ancestors = [
                (old, new)
                for old, new in (output_path_map or {}).items()
                if _is_relative_to(normalized, old)
            ]
            if not ancestors:
                return path
            old, new = max(ancestors, key=lambda item: len(os.path.abspath(item[0])))
            return os.path.join(os.path.abspath(new), os.path.relpath(normalized, os.path.abspath(old)))

        archives_to_clean = [
            [remap(path) for path in archive_parts]
            for archive_parts in response.artifacts.archives_to_clean
        ]
        flatten_targets = [remap(path) for path in response.artifacts.flatten_targets]
        PostProcessActions(self.config).apply(
            archives_to_clean=archives_to_clean,
            flatten_targets=flatten_targets,
        )

    def close(self, *, graceful: bool = True) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            self._accepting = False
            thread = self._thread
            if self._started:
                self._queue.put(self._STOP)
        if thread is not None and graceful:
            thread.join()
        self._runtime.close()
        with self._lifecycle_lock:
            self._closed = True
            self._started = False

    def __enter__(self) -> "PipelineEngine":
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close(graceful=True)

    def _dispatch_loop(self) -> None:
        while True:
            item = self._queue.get()
            if item is self._STOP:
                self._set_active_request_count(0)
                self._queue.task_done()
                return
            batch = [item]
            self._set_active_request_count(len(batch))
            deadline = time.monotonic() + self.batch_window_seconds
            while len(batch) < self.max_batch_requests:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    candidate = self._queue.get(timeout=timeout)
                except queue.Empty:
                    break
                if candidate is self._STOP:
                    self._queue.task_done()
                    self._set_active_request_count(len(batch))
                    self._execute_batch(batch)
                    return
                batch.append(candidate)
                self._set_active_request_count(len(batch))
            self._execute_batch(batch)

    def _execute_batch(self, submissions: list[_Submission]) -> None:
        try:
            compatible: dict[tuple, list[_Submission]] = {}
            for submission in submissions:
                key = (submission.direct, submission.user_passwords, submission.builtin_passwords)
                compatible.setdefault(key, []).append(submission)
            for (direct, user_passwords, builtin_passwords), group in compatible.items():
                self.extractor.password_store.replace_sources(
                    user_passwords=list(user_passwords),
                    builtin_passwords=list(builtin_passwords),
                )
                try:
                    self._runtime.execute(group, direct=direct)
                finally:
                    self._runtime.release_request_state()
        except Exception as exc:
            for submission in submissions:
                if not submission.future.done():
                    submission.future.set_exception(exc)
        finally:
            for _submission in submissions:
                self._queue.task_done()
            self._set_active_request_count(0)

    def _set_active_request_count(self, count: int) -> None:
        with self._pressure_lock:
            self._active_request_count = max(0, int(count or 0))
            pressure = self._active_request_count + self._queue.qsize()
        self.resource_scheduler.set_pipeline_request_backlog(pressure)

    def _sync_pipeline_pressure(self) -> None:
        with self._pressure_lock:
            pressure = self._active_request_count + self._queue.qsize()
        self.resource_scheduler.set_pipeline_request_backlog(pressure)

    @staticmethod
    def _normalize_target(target: str | PipelineTarget) -> PipelineTarget:
        if isinstance(target, PipelineTarget):
            return PipelineTarget(os.path.abspath(os.path.normpath(target.path)), dict(target.output))
        return PipelineTarget(os.path.abspath(os.path.normpath(str(target))))


def _replace_mapping_in_place(target: dict, source: dict) -> None:
    for key in tuple(target):
        if key not in source:
            target.pop(key, None)
    for key, value in source.items():
        current = target.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            _replace_mapping_in_place(current, value)
        else:
            target[key] = copy.deepcopy(value)


class _PipelineRuntime:
    """Long-lived pipeline components; request state is rebound per micro-batch."""

    def __init__(self, config: dict):
        self.config = config
        cli_config = config.get("cli") if isinstance(config.get("cli"), dict) else {}
        self.i18n = I18nContext(cli_config.get("language"))
        self.language = self.i18n.language
        self.quiet = bool(cli_config.get("quiet", False))
        self.verbose = bool(cli_config.get("verbose", False))
        analysis_config = config.get("analysis") if isinstance(config.get("analysis"), dict) else {}
        analysis_workers = max(1, int(analysis_config.get("task_max_workers", 4) or 4))
        module_workers = max(1, int(analysis_config.get("max_workers", 3) or 3))
        max_workers = resolve_max_workers()
        performance = advanced_config_value(("performance",))
        if isinstance(config.get("performance"), dict):
            performance.update(config["performance"])
        scheduler_config = build_scheduler_profile_config(performance.get("scheduler_profile", "auto"))
        scheduler_config.update({
            key: value
            for key, value in performance.items()
            if key != "scheduler_profile" and value is not None
        })
        initial_limit = scheduler_config.get("initial_concurrency_limit", max_workers)
        self.resource_scheduler = ConcurrencyScheduler(
            scheduler_config,
            current_limit=initial_limit,
            max_workers=max_workers,
        )
        self.analysis_executor_pool = ThreadPoolExecutor(
            max_workers=analysis_workers,
            thread_name_prefix="sunpack-analysis-task",
        )
        self.analysis_module_pool = ThreadPoolExecutor(
            max_workers=module_workers,
            thread_name_prefix="sunpack-analysis-module",
        )
        self.analysis_stage = ArchiveAnalysisStage(
            config,
            executor_pool=self.analysis_executor_pool,
            module_executor_pool=self.analysis_module_pool,
            workload_executor=self._execute_analysis_workload,
        )
        self.executor_pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="sunpack-task",
        )
        initial_context = RunContext()
        self.task_scanner = ArchiveTaskScanner(config, initial_context)
        self.rename_scheduler = RenameScheduler()
        self.output_scan_policy = NestedOutputScanPolicy(config)
        self.nested_extraction_policy = NestedExtractionPolicy(config)
        performance_config = config.get("performance", {}) if isinstance(config.get("performance"), dict) else {}
        self.extractor = ExtractionScheduler(
            cli_passwords=config.get("user_passwords", []),
            builtin_passwords=config.get("builtin_passwords", []),
            max_retries=config.get("max_retries", 3),
            process_config=performance_config,
            output_config=config.get("output", {}),
            extraction_config={
                **(config.get("extraction", {}) if isinstance(config.get("extraction"), dict) else {}),
                "language": self.language,
            },
        )
        initial_reporter = self._new_reporter()
        self.batch_runner = ExtractionBatchRunner(
            initial_context,
            self.extractor,
            self.output_scan_policy,
            self.resource_scheduler,
            self.rename_scheduler,
            config,
            analysis_stage=self.analysis_stage,
            progress_reporter=initial_reporter,
            executor_pool=self.executor_pool,
        )

    def start(self) -> None:
        self.resource_scheduler.start()

    def _execute_analysis_workload(
        self,
        tasks,
        worker,
        *,
        max_workers: int,
        workload_label: str,
    ):
        executor = TaskExecutor(
            self.resource_scheduler,
            max_workers=max_workers,
            executor_pool=self.analysis_executor_pool,
        )
        return executor.execute_all(tasks, worker, workload_label=workload_label)

    def execute(self, submissions: list[_Submission], *, direct: bool) -> None:
        start_time = time.time()
        context = RunContext()
        reporter = self._new_reporter()
        postprocess = PostProcessActions(self.config, context, language=self.language)
        space_guard = ExtractionSpaceGuard(context, postprocess)
        self.task_scanner.context = context
        self.batch_runner.context = context
        self.batch_runner.progress_reporter = reporter
        self.extractor.ensure_space = space_guard.ensure_space
        self.extractor.set_progress_callback(reporter.task_progress)

        all_targets = [target.path for submission in submissions for target in submission.targets]
        first_target = all_targets[0] if all_targets else os.getcwd()
        monitor_root = first_target if os.path.isdir(first_target) else os.path.dirname(first_target)
        space_guard.bind_root(monitor_root)
        ownership = _RequestOwnership(submissions, self.config)
        recursion = self._new_recursion()
        round_index = 1
        current_roots = list(dict.fromkeys(all_targets))
        current_tasks = self.task_scanner.direct_file_tasks(current_roots) if direct else None
        current_scan_session = None

        while current_tasks if direct else current_roots:
            if direct:
                tasks = current_tasks or []
            else:
                reporter.scan_started(round_index)
                tasks = self.task_scanner.scan_targets(
                    current_roots,
                    scan_session=current_scan_session,
                    is_recursive_scan=(round_index > 1),
                )
            authorization = self.nested_extraction_policy.authorize_batch(
                tasks,
                current_roots,
                current_scan_session or self.task_scanner.last_scan_session,
                round_index=round_index,
            )
            tasks = authorization.allowed_tasks
            context.policy_skips.extend(authorization.skipped)
            ownership.remember_tasks(tasks)
            self.batch_runner.set_progress_round(round_index, direct=direct and round_index == 1)
            before_results = len(context.target_results)
            new_roots = self.batch_runner.execute(
                tasks,
                default_output_dir_for_task=ownership.output_dir_for_task,
            )
            next_scan_session = self.output_scan_policy.take_scan_session(new_roots)
            ownership.remember_results(context.target_results[before_results:])
            if not recursion.should_continue(round_index, bool(new_roots)):
                break
            if recursion.mode == "prompt" and not recursion.prompt_continue(round_index):
                break
            current_roots = new_roots
            current_scan_session = next_scan_session
            current_tasks = (
                self.task_scanner.scan_targets(new_roots, scan_session=current_scan_session, is_recursive_scan=True)
                if direct
                else None
            )
            round_index += 1

        responses = ownership.responses(context, recent_passwords=self.extractor.recent_passwords)
        for submission in submissions:
            response = responses[submission.request_id]
            first_request_target = submission.targets[0].path
            request_log_root = (
                first_request_target
                if os.path.isdir(first_request_target)
                else os.path.dirname(first_request_target)
            )
            reporter.log_final_summary(
                request_log_root,
                start_time,
                response.summary.success_count,
                response.summary.failed_tasks,
                recovered_outputs=response.summary.recovered_outputs,
                failures=response.summary.failures,
            )
            if not submission.defer_postprocess:
                PostProcessActions(self.config).apply(
                    archives_to_clean=response.artifacts.archives_to_clean,
                    flatten_targets=response.artifacts.flatten_targets,
                )
            submission.future.set_result(response)

    def close(self) -> None:
        self.resource_scheduler.set_pipeline_request_backlog(0)
        self.resource_scheduler.stop()
        self.extractor.close()
        self.executor_pool.shutdown(wait=True, cancel_futures=False)
        self.analysis_executor_pool.shutdown(wait=True, cancel_futures=False)
        self.analysis_module_pool.shutdown(wait=True, cancel_futures=False)

    def release_request_state(self) -> None:
        """Drop references that are valid only for one compatible request group."""
        context = RunContext()
        self.task_scanner.context = context
        self.batch_runner.context = context
        self.batch_runner.progress_reporter = None
        self.batch_runner.directory_password_contexts.clear()
        self.extractor.ensure_space = lambda _required_gb: True
        self.extractor.set_progress_callback(None)
        self.analysis_stage.clear_report_cache()
        clear_archive_sessions()

    def _new_reporter(self) -> RunReporter:
        return RunReporter(language=self.language, quiet=self.quiet, verbose=self.verbose)

    def _new_recursion(self) -> RecursionController:
        config = self.config.get("recursive_extract", {"mode": "fixed", "max_rounds": 1})
        if not isinstance(config, dict):
            raise ValueError("recursive_extract must be normalized before PipelineEngine starts")
        return RecursionController(
            mode=str(config.get("mode", "fixed")),
            max_rounds=int(config.get("max_rounds", 1)),
            language=self.language,
        )


class _RequestOwnership:
    def __init__(self, submissions: list[_Submission], config: dict):
        self.submissions = submissions
        self.config = config
        self._task_owner: dict[str, str] = {}
        self._task_keys: dict[str, list[str]] = {item.request_id: [] for item in submissions}
        self._output_owner: dict[str, str] = {}

    def remember_tasks(self, tasks) -> None:
        for task in tasks:
            owner = self.owner_for_path(task.main_path)
            self._task_owner[path_key(task.main_path)] = owner.request_id
            self._task_keys[owner.request_id].append(task.key)

    def remember_results(self, results) -> None:
        for result in results:
            owner = self.owner_for_path(result.input_path)
            if result.output_dir:
                self._output_owner[path_key(result.output_dir)] = owner.request_id

    def output_dir_for_task(self, task) -> str:
        owner = self.owner_for_path(task.main_path)
        target = self._target_for_path(owner, task.main_path)
        output_config = {
            **(self.config.get("output", {}) if isinstance(self.config.get("output"), dict) else {}),
            **dict(target.output),
        }
        return default_output_dir_for_task(task, output_config)

    def owner_for_path(self, path: str) -> _Submission:
        normalized = os.path.abspath(path)
        known = self._task_owner.get(path_key(normalized)) or self._owner_for_output(normalized)
        if known:
            return self._submission(known)
        exact = []
        containing = []
        for submission in self.submissions:
            for target in submission.targets:
                if path_key(target.path) == path_key(normalized):
                    exact.append(submission)
                elif os.path.isdir(target.path) and _is_relative_to(normalized, target.path):
                    containing.append((len(target.path), submission))
        if exact:
            return exact[0]
        if containing:
            return max(containing, key=lambda item: item[0])[1]
        return self.submissions[0]

    def responses(self, context: RunContext, *, recent_passwords: Iterable[str]) -> dict[str, PipelineResponse]:
        results = {item.request_id: [] for item in self.submissions}
        for result in context.target_results:
            results[self.owner_for_path(result.input_path).request_id].append(result)
        archives = {item.request_id: [] for item in self.submissions}
        for parts in context.unpacked_archives:
            if parts:
                archives[self.owner_for_path(parts[0]).request_id].append(tuple(parts))
        flatten = {item.request_id: [] for item in self.submissions}
        for path in context.flatten_candidates:
            owner_id = self._owner_for_output(path) or self.owner_for_path(path).request_id
            flatten[owner_id].append(path)

        responses = {}
        for submission in self.submissions:
            request_results = results[submission.request_id]
            failed = [
                f"{os.path.basename(result.input_path)} [{result.error or getattr(result.failure, 'message', '')}]"
                for result in request_results
                if result.outcome_kind == OutcomeKind.FAILURE
            ]
            if len(self.submissions) == 1:
                failed = list(context.failed_tasks)
                failures = list(context.failures)
            else:
                failures = [
                    result.failure
                    for result in request_results
                    if result.failure is not None
                ]
                failures.extend(
                    failure
                    for failure in context.failures
                    if failure not in failures and self._failure_owner(failure) == submission.request_id
                )
            recovered = [
                item for item in context.recovered_outputs
                if self.owner_for_path(str(item.get("out_dir") or item.get("archive") or "")).request_id == submission.request_id
            ]
            summary = RunSummary(
                success_count=sum(result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS for result in request_results),
                failed_tasks=failed,
                processed_keys=list(dict.fromkeys(self._task_keys[submission.request_id])),
                partial_success_count=sum(result.outcome_kind == OutcomeKind.PARTIAL_SUCCESS for result in request_results),
                recovered_outputs=recovered,
                failures=failures,
                target_results=request_results,
                policy_skips=[
                    item
                    for item in context.policy_skips
                    if self.owner_for_path(str(item.get("path") or "")).request_id
                    == submission.request_id
                ],
            )
            responses[submission.request_id] = PipelineResponse(
                request_id=submission.request_id,
                summary=summary,
                artifacts=PipelineArtifacts(
                    archives_to_clean=tuple(archives[submission.request_id]),
                    flatten_targets=tuple(sorted(flatten[submission.request_id], key=lambda value: value.count(os.sep))),
                ),
                recent_passwords=tuple(recent_passwords),
            )
        return responses

    def _target_for_path(self, submission: _Submission, path: str) -> PipelineTarget:
        exact = [target for target in submission.targets if path_key(target.path) == path_key(path)]
        if exact:
            return exact[0]
        containing = [target for target in submission.targets if os.path.isdir(target.path) and _is_relative_to(path, target.path)]
        return max(containing, key=lambda target: len(target.path)) if containing else submission.targets[0]

    def _owner_for_output(self, path: str) -> str:
        normalized = os.path.abspath(path)
        matches = [
            (len(output), owner)
            for output_key, owner in self._output_owner.items()
            for output in [output_key]
            if output_key == path_key(normalized) or _is_relative_to(normalized, output_key)
        ]
        return max(matches, default=(0, ""), key=lambda item: item[0])[1]

    def _failure_owner(self, failure) -> str:
        details = getattr(failure, "details", {})
        path = str(details.get("path") or details.get("archive") or "") if isinstance(details, dict) else ""
        return self.owner_for_path(path).request_id if path else ""

    def _submission(self, request_id: str) -> _Submission:
        return next(item for item in self.submissions if item.request_id == request_id)


def _is_relative_to(path: str, root: str) -> bool:
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (OSError, ValueError):
        return False
