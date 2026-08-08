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

from sunpack.detection.input_planning import ArchiveInputPlanningStage
from sunpack.repair_inspection import RepairInspectionService
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
from sunpack.platform.windows.shell_notify import notify_shell_directories_updated
from sunpack.rename.scheduler import OutputReservationRegistry, RenameScheduler
from sunpack.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from sunpack.support.output_paths import default_output_dir_for_task
from sunpack.support.path_keys import path_key
from sunpack.support.archive_sessions import clear_archive_sessions
from sunpack.detection.options import DetectionOptions


@dataclass
class _Submission:
    request_id: str
    targets: tuple[PipelineTarget, ...]
    direct: bool
    defer_postprocess: bool
    user_passwords: tuple[str, ...]
    builtin_passwords: tuple[str, ...]
    config: dict
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

    def done(self) -> bool:
        return self._submission.future.done()

    def add_done_callback(self, callback) -> None:
        self._submission.future.add_done_callback(lambda _future: callback(self))

    def finalize(self, output_path_map: Mapping[str, str] | None = None) -> PipelineResponse:
        response = self.result()
        with self._finalize_lock:
            if not self._finalized:
                self._engine._finalize_submission(self._submission, response, output_path_map=output_path_map)
                self._finalized = True
        return response


class PipelineEngine:
    """Process-scoped services with independently completing request pipelines."""

    _STOP = object()

    def __init__(self, config: dict, detection_options: DetectionOptions | None = None):
        self.config = config
        self.detection_options = detection_options or DetectionOptions()
        pipeline_config = config.get("pipeline") if isinstance(config.get("pipeline"), dict) else {}
        queue_capacity = max(1, int(pipeline_config["queue_capacity"]))
        configured_active = pipeline_config.get("max_active_pipeline_requests")
        self.max_active_pipeline_requests = (
            max(1, int(configured_active))
            if configured_active is not None
            else max(2, min(4, resolve_max_workers()))
        )
        self._queue: queue.Queue = queue.Queue(maxsize=queue_capacity)
        self._services = _PipelineServices(config, self.detection_options)
        self._runtime = self._services
        self._request_pool: ThreadPoolExecutor | None = None
        self._request_runtime_factory = _RequestRuntime
        self._thread: threading.Thread | None = None
        self._lifecycle_lock = threading.Lock()
        self._dispatch_condition = threading.Condition()
        self._pressure_lock = threading.Lock()
        self._active_request_count = 0
        self._pending_request_count = 0
        self._outstanding_request_count = 0
        self._active_request_futures: dict[Future, _Submission] = {}
        self._path_leases = _PathLeaseRegistry()
        self._cancel_pending_on_stop = False
        self._password_source_lock = threading.Lock()
        self._config_lock = threading.Lock()
        self._recent_passwords_lock = threading.Lock()
        self._recent_passwords: list[str] = []
        self._user_passwords = tuple(config.get("user_passwords", []) or [])
        self._builtin_passwords = tuple(config.get("builtin_passwords", []) or [])
        self._started = False
        self._accepting = False
        self._closed = False

    @property
    def resource_scheduler(self) -> ConcurrencyScheduler:
        return self._services.resource_scheduler

    @property
    def recent_passwords(self) -> list[str]:
        with self._recent_passwords_lock:
            return list(self._recent_passwords)

    def is_idle(self) -> bool:
        with self._pressure_lock:
            return (
                getattr(self, "_outstanding_request_count", self._active_request_count) == 0
                and self._queue.empty()
            )

    def start(self) -> "PipelineEngine":
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("PipelineEngine is closed")
            if self._started:
                return self
            self._services.start()
            self._request_pool = ThreadPoolExecutor(
                max_workers=self.max_active_pipeline_requests,
                thread_name_prefix="sunpack-request",
            )
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
        with self._config_lock:
            request_config = copy.deepcopy(self.config)
        request_config["user_passwords"] = list(user_passwords)
        request_config["builtin_passwords"] = list(builtin_passwords)
        submission = _Submission(
            request_id=uuid.uuid4().hex,
            targets=normalized,
            direct=bool(direct),
            defer_postprocess=bool(defer_postprocess),
            user_passwords=user_passwords,
            builtin_passwords=builtin_passwords,
            config=request_config,
            future=Future(),
        )
        with self._lifecycle_lock:
            if not self._started or not self._accepting:
                raise RuntimeError("PipelineEngine must be started before submit")
            self._change_outstanding_request_count(1)
            self._queue.put(submission)
            self._sync_pipeline_pressure()
        return PipelineHandle(self, submission)

    def update_password_sources(self, *, user_passwords: Iterable[str], builtin_passwords: Iterable[str]) -> None:
        with self._password_source_lock:
            self._user_passwords = tuple(user_passwords)
            self._builtin_passwords = tuple(builtin_passwords)

    def reconfigure_request(self, config: dict) -> None:
        """Refresh the snapshot source for future requests only."""
        with self._config_lock:
            _replace_mapping_in_place(self.config, config)

    def finalize(
        self,
        response: PipelineResponse,
        *,
        output_path_map: Mapping[str, str] | None = None,
    ) -> None:
        with self._config_lock:
            config = copy.deepcopy(self.config)
        _finalize_response(config, response, output_path_map=output_path_map)

    def _finalize_submission(
        self,
        submission: _Submission,
        response: PipelineResponse,
        *,
        output_path_map: Mapping[str, str] | None = None,
    ) -> None:
        _finalize_response(submission.config, response, output_path_map=output_path_map)

    def close(self, *, graceful: bool = True) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            self._accepting = False
            thread = self._thread
            self._cancel_pending_on_stop = not graceful
            if self._started:
                self._queue.put(self._STOP)
        if thread is not None:
            thread.join()
        if self._request_pool is not None:
            self._request_pool.shutdown(wait=True, cancel_futures=False)
        self._services.close()
        with self._lifecycle_lock:
            self._closed = True
            self._started = False

    def __enter__(self) -> "PipelineEngine":
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close(graceful=True)

    def _dispatch_loop(self) -> None:
        pending: list[_Submission] = []
        stopping = False
        while True:
            if not pending and not stopping:
                item = self._queue.get()
                if item is self._STOP:
                    stopping = True
                    self._queue.task_done()
                else:
                    pending.append(item)
            while not stopping:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                if item is self._STOP:
                    stopping = True
                    self._queue.task_done()
                    break
                pending.append(item)
            self._set_pending_request_count(len(pending))

            if stopping and self._cancel_pending_on_stop:
                for submission in pending:
                    submission.future.cancel()
                    self._queue.task_done()
                    self._change_outstanding_request_count(-1)
                pending.clear()
                self._set_pending_request_count(0)

            scheduled = False
            while pending and self._active_count() < self.max_active_pipeline_requests:
                index = next(
                    (
                        i for i, submission in enumerate(pending)
                        if self._path_leases.try_acquire(
                            submission.request_id,
                            [target.path for target in submission.targets],
                        )
                    ),
                    None,
                )
                if index is None:
                    break
                submission = pending.pop(index)
                self._set_pending_request_count(len(pending))
                assert self._request_pool is not None
                worker_future = self._request_pool.submit(self._execute_submission, submission)
                with self._dispatch_condition:
                    self._active_request_futures[worker_future] = submission
                    active = len(self._active_request_futures)
                self._set_active_request_count(active)
                worker_future.add_done_callback(self._request_finished)
                scheduled = True

            if stopping and not pending and self._active_count() == 0:
                self._set_active_request_count(0)
                return
            if not scheduled:
                with self._dispatch_condition:
                    self._dispatch_condition.wait(timeout=0.05)

    def _execute_submission(self, submission: _Submission) -> None:
        try:
            runtime = self._request_runtime_factory(
                self._services,
                submission,
                self.detection_options,
                self._path_leases,
            )
            response = runtime.execute()
            self._remember_recent_passwords(response.recent_passwords)
            if not submission.future.done():
                submission.future.set_result(response)
        except Exception as exc:
            if not submission.future.done():
                submission.future.set_exception(exc)
        finally:
            self._services.output_reservations.release(submission.request_id)

    def _request_finished(self, worker_future: Future) -> None:
        with self._dispatch_condition:
            submission = self._active_request_futures.pop(worker_future, None)
            active = len(self._active_request_futures)
            self._dispatch_condition.notify_all()
        self._set_active_request_count(active)
        if submission is not None:
            self._path_leases.release(submission.request_id)
            self._queue.task_done()
            self._change_outstanding_request_count(-1)

    def _active_count(self) -> int:
        with self._dispatch_condition:
            return len(self._active_request_futures)

    def _remember_recent_passwords(self, passwords: Iterable[str]) -> None:
        with self._recent_passwords_lock:
            for password in reversed(list(passwords)):
                if password in self._recent_passwords:
                    self._recent_passwords.remove(password)
                self._recent_passwords.insert(0, password)
            del self._recent_passwords[20:]

    def _set_active_request_count(self, count: int) -> None:
        with self._pressure_lock:
            self._active_request_count = max(0, int(count or 0))
            pressure = self._outstanding_request_count
        self.resource_scheduler.set_pipeline_request_backlog(pressure)

    def _set_pending_request_count(self, count: int) -> None:
        with self._pressure_lock:
            self._pending_request_count = max(0, int(count or 0))
            pressure = self._outstanding_request_count
        self.resource_scheduler.set_pipeline_request_backlog(pressure)

    def _change_outstanding_request_count(self, delta: int) -> None:
        with self._pressure_lock:
            self._outstanding_request_count = max(0, self._outstanding_request_count + int(delta))
            pressure = self._outstanding_request_count
        self.resource_scheduler.set_pipeline_request_backlog(pressure)

    def _sync_pipeline_pressure(self) -> None:
        with self._pressure_lock:
            pressure = self._outstanding_request_count
        self.resource_scheduler.set_pipeline_request_backlog(pressure)

    @staticmethod
    def _normalize_target(target: str | PipelineTarget) -> PipelineTarget:
        if isinstance(target, PipelineTarget):
            return PipelineTarget(os.path.abspath(os.path.normpath(target.path)), dict(target.output))
        return PipelineTarget(os.path.abspath(os.path.normpath(str(target))))


class _PathLeaseRegistry:
    def __init__(self):
        self._condition = threading.Condition()
        self._owned: dict[str, set[str]] = {}

    def try_acquire(self, owner: str, paths: Iterable[str]) -> bool:
        normalized = {os.path.abspath(os.path.normpath(path)) for path in paths if path}
        with self._condition:
            if self._conflicts(owner, normalized):
                return False
            self._owned.setdefault(owner, set()).update(normalized)
            return True

    def acquire(self, owner: str, paths: Iterable[str]) -> None:
        normalized = {os.path.abspath(os.path.normpath(path)) for path in paths if path}
        with self._condition:
            while self._conflicts(owner, normalized):
                self._condition.wait()
            self._owned.setdefault(owner, set()).update(normalized)

    def replace(self, owner: str, paths: Iterable[str]) -> None:
        """Replace a provisional top-level lease with a discovered member set.

        Dropping the provisional lease before waiting prevents two different
        split members from each holding one path while requesting the other.
        """
        normalized = {os.path.abspath(os.path.normpath(path)) for path in paths if path}
        with self._condition:
            self._owned.pop(owner, None)
            self._condition.notify_all()
            while self._conflicts(owner, normalized):
                self._condition.wait()
            self._owned[owner] = normalized

    def release(self, owner: str) -> None:
        with self._condition:
            self._owned.pop(owner, None)
            self._condition.notify_all()

    def _conflicts(self, owner: str, candidates: set[str]) -> bool:
        for current_owner, current_paths in self._owned.items():
            if current_owner == owner:
                continue
            for candidate in candidates:
                for current in current_paths:
                    if path_key(candidate) == path_key(current):
                        return True
                    if os.path.isdir(candidate) and _is_relative_to(current, candidate):
                        return True
                    if os.path.isdir(current) and _is_relative_to(candidate, current):
                        return True
        return False


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


class _PipelineServices:
    """Thread-safe process services shared by all request runtimes."""

    def __init__(self, config: dict, detection_options: DetectionOptions | None = None):
        self.config = config
        self.output_reservations = OutputReservationRegistry()
        planning_config = config.get("input_planning") if isinstance(config.get("input_planning"), dict) else {}
        analysis_config = config.get("analysis") if isinstance(config.get("analysis"), dict) else {}
        planning_workers = max(1, int(planning_config.get("task_max_workers", 4) or 4))
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
        self.input_planning_executor_pool = ThreadPoolExecutor(
            max_workers=planning_workers,
            thread_name_prefix="sunpack-input-planning-task",
        )
        self.analysis_capability_pool = ThreadPoolExecutor(
            max_workers=module_workers,
            thread_name_prefix="sunpack-analysis-capability",
        )
        self.repair_inspection_service = RepairInspectionService(
            config,
            executor_pool=self.analysis_capability_pool,
        )
        self.executor_pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="sunpack-task",
        )
        performance_config = config.get("performance", {}) if isinstance(config.get("performance"), dict) else {}
        self.sevenzip_runner = SevenZipRunner(performance_config)

    def start(self) -> None:
        self.resource_scheduler.start()

    def close(self) -> None:
        self.resource_scheduler.set_pipeline_request_backlog(0)
        self.resource_scheduler.stop()
        self.sevenzip_runner.close()
        self.executor_pool.shutdown(wait=True, cancel_futures=False)
        self.input_planning_executor_pool.shutdown(wait=True, cancel_futures=False)
        self.analysis_capability_pool.shutdown(wait=True, cancel_futures=False)
        clear_archive_sessions()


class _RequestRuntime:
    """All mutable state belonging to exactly one PipelineEngine submission."""

    def __init__(
        self,
        services: _PipelineServices,
        submission: _Submission,
        detection_options: DetectionOptions,
        path_leases: _PathLeaseRegistry,
    ):
        self.services = services
        self.submission = submission
        self.config = submission.config
        self.path_leases = path_leases
        cli_config = self.config.get("cli") if isinstance(self.config.get("cli"), dict) else {}
        self.i18n = I18nContext(cli_config.get("language"))
        self.language = self.i18n.language
        self.quiet = bool(cli_config.get("quiet", False))
        self.verbose = bool(cli_config.get("verbose", False))
        self.context = RunContext()
        self.reporter = RunReporter(language=self.language, quiet=self.quiet, verbose=self.verbose)
        self.postprocess = PostProcessActions(self.config, self.context, language=self.language)
        self.space_guard = ExtractionSpaceGuard(self.context, self.postprocess)
        self.task_scanner = ArchiveTaskScanner(
            self.config,
            self.context,
            detection_options=detection_options,
        )
        self.input_planning_stage = ArchiveInputPlanningStage(
            self.config,
            executor_pool=services.input_planning_executor_pool,
            module_executor_pool=services.analysis_capability_pool,
            workload_executor=self._execute_input_planning_workload,
        )
        self.output_scan_policy = NestedOutputScanPolicy(self.config)
        self.nested_extraction_policy = NestedExtractionPolicy(self.config)
        self.rename_scheduler = RenameScheduler(
            services.output_reservations,
            submission.request_id,
        )
        performance = self.config.get("performance", {}) if isinstance(self.config.get("performance"), dict) else {}
        self.extractor = ExtractionScheduler(
            cli_passwords=submission.user_passwords,
            builtin_passwords=submission.builtin_passwords,
            max_retries=self.config.get("max_retries", 3),
            process_config=performance,
            output_config=self.config.get("output", {}),
            extraction_config={
                **(self.config.get("extraction", {}) if isinstance(self.config.get("extraction"), dict) else {}),
                "language": self.language,
            },
            sevenzip_runner=services.sevenzip_runner.fork(),
        )
        self.extractor.ensure_space = self.space_guard.ensure_space
        self.extractor.set_progress_callback(self.reporter.task_progress)
        self.batch_runner = ExtractionBatchRunner(
            self.context,
            self.extractor,
            self.output_scan_policy,
            services.resource_scheduler,
            self.rename_scheduler,
            self.config,
            repair_inspection_service=services.repair_inspection_service,
            progress_reporter=self.reporter,
            executor_pool=services.executor_pool,
            request_id=submission.request_id,
        )

    def _execute_input_planning_workload(
        self,
        tasks,
        worker,
        *,
        max_workers: int,
        workload_label: str,
    ):
        executor = TaskExecutor(
            self.services.resource_scheduler,
            max_workers=max_workers,
            executor_pool=self.services.input_planning_executor_pool,
            request_id=self.submission.request_id,
        )
        return executor.execute_all(tasks, worker, workload_label=workload_label)

    def execute(self) -> PipelineResponse:
        start_time = time.time()
        submission = self.submission
        all_targets = [target.path for target in submission.targets]
        first_target = all_targets[0] if all_targets else os.getcwd()
        monitor_root = first_target if os.path.isdir(first_target) else os.path.dirname(first_target)
        self.space_guard.bind_root(monitor_root)
        ownership = _RequestOwnership([submission], self.config)
        recursion = self._new_recursion()
        round_index = 1
        current_roots = list(dict.fromkeys(all_targets))
        current_tasks = self.task_scanner.direct_file_tasks(current_roots) if submission.direct else None
        current_scan_session = None

        try:
            while current_tasks if submission.direct else current_roots:
                if submission.direct:
                    tasks = current_tasks or []
                else:
                    self.reporter.scan_started(round_index)
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
                tasks = self.input_planning_stage.plan_tasks(authorization.allowed_tasks)
                self.context.policy_skips.extend(authorization.skipped)
                ownership.remember_tasks(tasks)
                member_paths = [
                    path
                    for task in tasks
                    for path in (task.all_parts or [task.main_path])
                ]
                self.path_leases.replace(
                    submission.request_id,
                    [*all_targets, *member_paths],
                )
                self.batch_runner.set_progress_round(
                    round_index,
                    direct=submission.direct and round_index == 1,
                )
                before_results = len(self.context.target_results)
                new_roots = self.batch_runner.execute(
                    tasks,
                    default_output_dir_for_task=ownership.output_dir_for_task,
                )
                next_scan_session = self.output_scan_policy.take_scan_session(new_roots)
                ownership.remember_results(self.context.target_results[before_results:])
                if not recursion.should_continue(round_index, bool(new_roots)):
                    break
                if recursion.mode == "prompt" and not recursion.prompt_continue(round_index):
                    break
                current_roots = new_roots
                current_scan_session = next_scan_session
                current_tasks = (
                    self.task_scanner.scan_targets(new_roots, scan_session=current_scan_session, is_recursive_scan=True)
                    if submission.direct
                    else None
                )
                round_index += 1

            response = ownership.responses(
                self.context,
                recent_passwords=self.extractor.recent_passwords,
            )[submission.request_id]
            request_log_root = first_target if os.path.isdir(first_target) else os.path.dirname(first_target)
            self.reporter.log_final_summary(
                request_log_root,
                start_time,
                response.summary.success_count,
                response.summary.failed_tasks,
                recovered_outputs=response.summary.recovered_outputs,
                failures=response.summary.failures,
            )
            if not submission.defer_postprocess:
                _finalize_response(self.config, response)
            return response
        finally:
            self.extractor.set_progress_callback(None)
            self.extractor.close()
            self.input_planning_stage.clear_report_cache()

    def _new_recursion(self) -> RecursionController:
        config = self.config.get("recursive_extract", {"mode": "fixed", "max_rounds": 1})
        if not isinstance(config, dict):
            raise ValueError("recursive_extract must be normalized before PipelineEngine starts")
        return RecursionController(
            mode=str(config.get("mode", "fixed")),
            max_rounds=int(config.get("max_rounds", 1)),
            language=self.language,
        )


def _finalize_response(
    config: dict,
    response: PipelineResponse,
    *,
    output_path_map: Mapping[str, str] | None = None,
) -> None:
    mapping = {path_key(old): os.path.abspath(new) for old, new in (output_path_map or {}).items()}

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
    shell_refresh_paths = [remap(path) for path in response.artifacts.shell_refresh_paths]
    PostProcessActions(config).apply(
        archives_to_clean=archives_to_clean,
        flatten_targets=flatten_targets,
    )
    notify_shell_directories_updated(shell_refresh_paths)


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
                    shell_refresh_paths=tuple(dict.fromkeys([
                        *(path for archive_parts in archives[submission.request_id] for path in archive_parts),
                        *(
                            result.output_dir
                            for result in request_results
                            if result.outcome_kind in {OutcomeKind.COMPLETE_SUCCESS, OutcomeKind.PARTIAL_SUCCESS}
                            and result.output_dir
                        ),
                        *(
                            str(item.get("out_dir") or "")
                            for item in recovered
                            if str(item.get("out_dir") or "")
                        ),
                    ])),
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
