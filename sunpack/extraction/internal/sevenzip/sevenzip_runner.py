import json
import os
import queue
import subprocess
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable

import psutil

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.internal.sevenzip.worker_diagnostics import attach_worker_diagnostics
from sunpack.support import archive_knowledge_projection as knowledge_view
from sunpack.support.archive_state_view import ArchiveStateByteView
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path
from sunpack.support.runtime_cwd import runtime_working_directory


def _apply_native_environment(environment: dict[str, str], process_config: dict) -> dict[str, str]:
    """Project Python configuration into the native worker's control plane."""

    def set_int(config_key: str, environment_key: str, minimum: int = 1) -> None:
        value = process_config.get(config_key)
        if value is None:
            return
        try:
            value = int(value)
        except (TypeError, ValueError):
            return
        if value >= minimum:
            environment[environment_key] = str(value)

    def set_bytes_from_mb(config_key: str, environment_key: str) -> None:
        value = process_config.get(config_key)
        if value is None:
            return
        try:
            value = float(value)
        except (TypeError, ValueError):
            return
        if value > 0:
            environment[environment_key] = str(max(1, int(value * 1024 * 1024)))

    def set_float(config_key: str, environment_key: str) -> None:
        value = process_config.get(config_key)
        if value is None:
            return
        try:
            environment[environment_key] = str(float(value))
        except (TypeError, ValueError):
            return

    native_extract_threads = process_config.get("native_extract_threads")
    if native_extract_threads is not None:
        try:
            native_extract_threads = int(native_extract_threads)
        except (TypeError, ValueError):
            native_extract_threads = None
        if native_extract_threads is not None:
            # Zero is an explicit request for native machine auto-detection;
            # never let a stale parent-process value override that contract.
            environment.pop("SUNPACK_NATIVE_EXTRACT_THREADS", None)
            if native_extract_threads > 0:
                environment["SUNPACK_NATIVE_EXTRACT_THREADS"] = str(native_extract_threads)
    set_int("native_async_writer_threads", "SUNPACK_ASYNC_WRITER_THREADS")
    set_int("native_sample_interval_ms", "SUNPACK_NATIVE_SAMPLE_INTERVAL_MS", minimum=100)
    set_int("native_initial_active_jobs", "SUNPACK_NATIVE_INITIAL_ACTIVE_JOBS", minimum=0)

    memory_budget = process_config.get("native_memory_budget_bytes")
    try:
        memory_budget = int(memory_budget) if memory_budget is not None else 0
    except (TypeError, ValueError):
        memory_budget = 0
    if process_config.get("native_memory_budget_bytes") is not None:
        environment.pop("SUNPACK_NATIVE_MEMORY_BUDGET_BYTES", None)
    if memory_budget > 0:
        environment["SUNPACK_NATIVE_MEMORY_BUDGET_BYTES"] = str(memory_budget)

    native_adaptive = process_config.get("native_adaptive_enabled")
    if native_adaptive is not None:
        if isinstance(native_adaptive, str):
            enabled = native_adaptive.strip().lower() not in {"0", "false", "no", "off"}
        else:
            enabled = bool(native_adaptive)
        environment["SUNPACK_NATIVE_ADAPTIVE_ENABLED"] = "1" if enabled else "0"

    set_int("scale_up_streak_required", "SUNPACK_NATIVE_SCALE_UP_STREAK_REQUIRED")
    set_int("scale_down_streak_required", "SUNPACK_NATIVE_SCALE_DOWN_STREAK_REQUIRED")
    set_int("throughput_window_size", "SUNPACK_NATIVE_THROUGHPUT_WINDOW_SIZE", minimum=4)
    set_float("throughput_regression_ratio", "SUNPACK_NATIVE_THROUGHPUT_REGRESSION_RATIO")
    set_int("profile_calibration_min_parallel", "SUNPACK_NATIVE_PROFILE_MIN_PARALLEL")
    set_float("scheduler_idle_decay_seconds", "SUNPACK_NATIVE_IDLE_DECAY_SECONDS")
    set_int("medium_backlog_threshold", "SUNPACK_NATIVE_MEDIUM_BACKLOG_THRESHOLD")
    set_int("high_backlog_threshold", "SUNPACK_NATIVE_HIGH_BACKLOG_THRESHOLD")
    set_int("medium_floor_workers", "SUNPACK_NATIVE_MEDIUM_FLOOR_JOBS")
    set_int("high_floor_workers", "SUNPACK_NATIVE_HIGH_FLOOR_JOBS")
    set_float("cpu_scale_up_threshold_percent", "SUNPACK_NATIVE_CPU_SCALE_UP_PERCENT")
    set_float("cpu_scale_down_threshold_percent", "SUNPACK_NATIVE_CPU_SCALE_DOWN_PERCENT")
    set_bytes_from_mb("scale_up_threshold_mb_s", "SUNPACK_NATIVE_IO_SCALE_UP_BYTES")
    set_bytes_from_mb("scale_up_backlog_threshold_mb_s", "SUNPACK_NATIVE_IO_SCALE_UP_BACKLOG_BYTES")
    set_bytes_from_mb("scale_down_threshold_mb_s", "SUNPACK_NATIVE_IO_SCALE_DOWN_BYTES")
    set_bytes_from_mb(
        "memory_scale_down_available_mb",
        "SUNPACK_NATIVE_MEMORY_SCALE_DOWN_AVAILABLE_BYTES",
    )
    set_bytes_from_mb(
        "memory_scale_up_available_mb",
        "SUNPACK_NATIVE_MEMORY_SCALE_UP_AVAILABLE_BYTES",
    )
    set_int("profile_calibration_window_size", "SUNPACK_NATIVE_PROFILE_WINDOW_SIZE", minimum=4)
    set_int("profile_calibration_max_delta", "SUNPACK_NATIVE_PROFILE_MAX_DELTA", minimum=0)
    set_int("native_max_queue_jobs", "SUNPACK_NATIVE_MAX_QUEUE_JOBS")
    set_int("native_priority_aging_quantum", "SUNPACK_NATIVE_PRIORITY_AGING_QUANTUM")
    set_float("profile_regression_ratio", "SUNPACK_NATIVE_PROFILE_REGRESSION_RATIO")
    set_float("profile_improvement_ratio", "SUNPACK_NATIVE_PROFILE_IMPROVEMENT_RATIO")
    scheduler_profile = process_config.get("scheduler_profile")
    if scheduler_profile:
        environment["SUNPACK_NATIVE_SCHEDULER_PROFILE"] = str(scheduler_profile)
    profile_cache_path = process_config.get("profile_calibration_cache_path")
    if profile_cache_path:
        environment["SUNPACK_NATIVE_PROFILE_CACHE_PATH"] = str(profile_cache_path)
    profile_cache_enabled = process_config.get("profile_calibration_cache_enabled")
    if profile_cache_enabled is not None:
        if isinstance(profile_cache_enabled, str):
            enabled = profile_cache_enabled.strip().lower() not in {"0", "false", "no", "off"}
        else:
            enabled = bool(profile_cache_enabled)
        environment["SUNPACK_NATIVE_PROFILE_CACHE_ENABLED"] = "1" if enabled else "0"
    return environment


class _PersistentWorker:
    def __init__(self, worker_path: str, startupinfo, process_config: dict | None = None):
        self.worker_path = worker_path
        self.startupinfo = startupinfo
        self.process_config = process_config or {}
        self.process: subprocess.Popen | None = None
        self.worker_epoch = ""
        self.stderr_queue: queue.Queue[str | None] = queue.Queue()
        self._job_queues: dict[str, queue.Queue[str | None]] = {}
        self._job_states: dict[str, dict[str, Any]] = {}
        self._async_jobs: dict[str, dict[str, Any]] = {}
        self._orphan_queue: queue.Queue[str | None] = queue.Queue()
        self._dispatch_lock = threading.Lock()
        self._stdin_lock = threading.Lock()
        self._watchdog_stop = threading.Event()
        self._start()
        threading.Thread(target=self._watchdog_loop, daemon=True, name="sunpack-native-watchdog").start()

    def _start(self) -> None:
        self.worker_epoch = uuid.uuid4().hex
        environment = os.environ.copy()
        _apply_native_environment(environment, self.process_config)
        self.process = subprocess.Popen(
            [self.worker_path, "--persistent"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            startupinfo=self.startupinfo,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            cwd=runtime_working_directory(),
            env=environment,
        )
        threading.Thread(target=self._dispatch_stdout, args=(self.process.stdout,), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.process.stderr, self.stderr_queue), daemon=True).start()

    def register_job(self, job_id: str) -> None:
        with self._dispatch_lock:
            if job_id in self._job_queues:
                raise RuntimeError(f"sevenzip_worker job id is already active: {job_id}")
            self._job_queues[job_id] = queue.Queue()
            self._job_states[job_id] = {
                "state": "submitted",
                "worker_epoch": self.worker_epoch,
            }

    def unregister_job(self, job_id: str) -> None:
        with self._dispatch_lock:
            self._job_queues.pop(job_id, None)
            self._job_states.pop(job_id, None)

    def submit_async(
        self,
        payload: str,
        job_id: str,
        *,
        on_line: Callable[[str], bool],
        on_timeout: Callable[[str], None],
    ) -> None:
        """Send a job without allocating a Python wait thread.

        The stdout dispatcher is the only reader of the persistent worker's
        pipe.  Completion handlers therefore receive native events directly,
        while the native process owns the extraction concurrency.
        """
        self.register_job(job_id)
        state = {
            "on_line": on_line,
            "on_timeout": on_timeout,
            "started_at": time.monotonic(),
            "last_progress_at": time.monotonic(),
            "cancel_requested": False,
            "cancel_deadline": 0.0,
            "worker_epoch": self.worker_epoch,
            "max_task_seconds": max(
                0.0,
                float(self.process_config.get("max_extract_task_seconds", 0) or 0),
            ),
            "no_progress_timeout": max(
                0.0,
                float(self.process_config.get("process_no_progress_timeout_seconds", 0) or 0),
            ),
        }
        with self._dispatch_lock:
            self._async_jobs[job_id] = state
        try:
            self.send(payload)
        except Exception:
            self._finish_async_job(job_id)
            raise

    def _finish_async_job(self, job_id: str) -> dict[str, Any] | None:
        with self._dispatch_lock:
            state = self._async_jobs.pop(job_id, None)
            output_queue = self._job_queues.pop(job_id, None)
            self._job_states.pop(job_id, None)
        if output_queue is not None:
            output_queue.put(None)
        return state

    def read_job_line(self, job_id: str, timeout: float) -> str | None:
        with self._dispatch_lock:
            output_queue = self._job_queues.get(job_id)
        if output_queue is None:
            raise RuntimeError(f"sevenzip_worker job is not registered: {job_id}")
        try:
            return output_queue.get(timeout=timeout)
        except queue.Empty:
            raise

    def _dispatch_stdout(self, stream) -> None:
        try:
            for line in stream:
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    payload = {}
                job_id = str(payload.get("job_id") or "") if isinstance(payload, dict) else ""
                with self._dispatch_lock:
                    async_state = self._async_jobs.get(job_id) if job_id else None
                    output_queue = self._job_queues.get(job_id) if job_id else None
                    job_state = self._job_states.get(job_id) if job_id else None
                    if job_state is not None and isinstance(payload, dict):
                        event = str(payload.get("event") or "")
                        if payload.get("type") == "result":
                            job_state["state"] = "result_received"
                        elif event == "job_queued":
                            job_state["state"] = "queued"
                        elif event == "job_admitted":
                            job_state["state"] = "admitted"
                        elif event == "job_started":
                            job_state["state"] = "running"
                        elif event == "job_finished":
                            job_state["state"] = "output_closed"
                if async_state is not None:
                    try:
                        async_state["last_progress_at"] = time.monotonic()
                        completed = bool(async_state["on_line"](line))
                    except Exception as exc:
                        try:
                            async_state["on_timeout"](f"sevenzip_worker completion callback failed: {exc}")
                        except Exception:
                            pass
                        completed = True
                    if completed:
                        self._finish_async_job(job_id)
                    continue
                if output_queue is not None:
                    output_queue.put(line)
                else:
                    self._orphan_queue.put(line)
        except Exception:
            pass
        finally:
            with self._dispatch_lock:
                output_queues = list(self._job_queues.values())
                async_jobs = list(self._async_jobs.items())
            for output_queue in output_queues:
                output_queue.put(None)
            for job_id, state in async_jobs:
                try:
                    state["on_timeout"]("sevenzip_worker exited before job completion")
                except Exception:
                    pass
                self._finish_async_job(job_id)

    @staticmethod
    def _pump(stream, output_queue: queue.Queue[str | None]) -> None:
        try:
            for line in stream:
                output_queue.put(line)
        except Exception:
            pass
        finally:
            output_queue.put(None)

    def is_alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def send(self, payload: str) -> None:
        if not self.is_alive() or self.process is None or self.process.stdin is None:
            raise RuntimeError("sevenzip_worker is not running")
        with self._stdin_lock:
            self.process.stdin.write(payload + "\n")
            self.process.stdin.flush()

    def cancel(self, job_id: str) -> None:
        self.send(json.dumps({"worker_command": "cancel", "job_id": job_id}, separators=(",", ":")))

    def _watchdog_loop(self) -> None:
        while not self._watchdog_stop.wait(0.1):
            if not self.is_alive():
                return
            now = time.monotonic()
            timed_out: list[tuple[str, dict[str, Any], str]] = []
            force_failed: list[tuple[str, dict[str, Any], str]] = []
            with self._dispatch_lock:
                for job_id, state in self._async_jobs.items():
                    max_task_seconds = state["max_task_seconds"]
                    no_progress_timeout = state["no_progress_timeout"]
                    timed = bool(max_task_seconds and now - state["started_at"] > max_task_seconds)
                    no_progress = bool(
                        no_progress_timeout and now - state["last_progress_at"] > no_progress_timeout
                    )
                    if not timed and not no_progress:
                        if state["cancel_requested"] and now > state["cancel_deadline"]:
                            force_failed.append((job_id, state, "sevenzip_worker cancellation grace expired"))
                        continue
                    message = (
                        "sevenzip_worker made no observable progress"
                        if no_progress
                        else "sevenzip_worker timed out"
                    )
                    if not state["cancel_requested"]:
                        state["cancel_requested"] = True
                        state["cancel_deadline"] = now + max(
                            0.5,
                            float(self.process_config.get("cancel_grace_seconds", 5) or 5),
                        )
                        timed_out.append((job_id, state, message))
                    elif now > state["cancel_deadline"]:
                        force_failed.append((job_id, state, message))
            for job_id, _state, message in timed_out:
                try:
                    self.cancel(job_id)
                except Exception:
                    force_failed.append((job_id, _state, message))
            if force_failed:
                for job_id, state, message in force_failed:
                    try:
                        state["on_timeout"](message)
                    except Exception:
                        pass
                    self._finish_async_job(job_id)
                self.close()
                return

    def close(self) -> None:
        if self.process is None:
            return
        self._watchdog_stop.set()
        if self.is_alive() and self.process.stdin is not None:
            try:
                self.process.stdin.write('{"worker_command":"shutdown","job_id":"shutdown"}\n')
                self.process.stdin.flush()
            except Exception:
                pass
        try:
            self.process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            try:
                self.process.terminate()
                self.process.wait(timeout=0.5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
        except Exception:
            pass


class _PersistentWorkerHolder:
    def __init__(self, worker_path_callback, process_config: dict):
        self.worker_path_callback = worker_path_callback
        self.process_config = process_config
        self._condition = threading.Condition()
        self._workers: list[_PersistentWorker] = []
        self._total = 0
        self._closed = False

    def acquire(self, startupinfo) -> _PersistentWorker:
        with self._condition:
            while True:
                if self._closed:
                    raise RuntimeError("sevenzip_worker pool is closed")
                alive_workers = [worker for worker in self._workers if worker.is_alive()]
                self._workers = alive_workers
                self._total = len(alive_workers)
                if self._workers:
                    # One process can now accept many in-flight jobs. The native
                    # executor owns the actual extraction parallelism.
                    return self._workers[0]
                if self._total == 0:
                    worker = _PersistentWorker(self.worker_path_callback(), startupinfo, self.process_config)
                    self._workers.append(worker)
                    self._total += 1
                    return worker
                self._condition.wait()

    def release(self, worker: _PersistentWorker, *, reusable: bool) -> None:
        with self._condition:
            if reusable and not self._closed and worker.is_alive():
                if worker not in self._workers:
                    self._workers.append(worker)
                self._condition.notify()
                return
            else:
                self._workers = [candidate for candidate in self._workers if candidate is not worker]
                worker.close()
            self._total = max(0, self._total - 1)
            self._condition.notify()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            workers = list(self._workers)
            self._workers.clear()
            self._total = 0
            self._condition.notify_all()
        for worker in workers:
            worker.close()


# Compatibility name for callers that imported the old private helper. It is
# intentionally a holder for exactly one process; worker count is no longer a
# Python scheduling concern.
_PersistentWorkerPool = _PersistentWorkerHolder


class SevenZipRunner:
    def __init__(
        self,
        process_config: dict,
        *,
        shared_worker_pool: _PersistentWorkerPool | None = None,
        shared_async_executor: ThreadPoolExecutor | None = None,
    ):
        self.process_config = process_config
        self.progress_callback = None
        self.native_event_callback = None
        self.request_id = ""
        self.worker_path = None
        self.seven_zip_dll_path = None
        self._worker_pool: _PersistentWorkerPool | None = shared_worker_pool
        self._owns_worker_pool = shared_worker_pool is None
        self._worker_pool_lock = threading.Lock()
        self._async_executor = shared_async_executor or ThreadPoolExecutor(
            thread_name_prefix="sunpack-native-submit",
        )
        self._owns_async_executor = shared_async_executor is None

    def fork(self) -> "SevenZipRunner":
        """Create request-local callback state while sharing native workers."""
        shared_pool = self._pool() if self._persistent_workers_enabled() else None
        runner = SevenZipRunner(
            self.process_config,
            shared_worker_pool=shared_pool,
            shared_async_executor=self._async_executor,
        )
        runner.worker_path = self.worker_path
        runner.seven_zip_dll_path = self.seven_zip_dll_path
        runner.native_event_callback = self.native_event_callback
        runner.request_id = self.request_id
        return runner

    def run_extract(
        self,
        *,
        archive_path: str,
        part_paths: list[str],
        out_dir: str,
        password: str | None,
        password_candidates: list[str] | tuple[str, ...] | None = None,
        selected_codepage: str | None,
        decoded_names: list[str],
        startupinfo,
        runtime_scheduler: Any,
        task: ArchiveTask,
        phase_timer: Any | None = None,
        phase_prefix: str = "sevenzip",
    ) -> subprocess.CompletedProcess:
        try:
            with _phase(phase_timer, f"{phase_prefix}_build_job"):
                job = self._build_job(
                    archive_path=archive_path,
                    part_paths=part_paths,
                    out_dir=out_dir,
                    password=password,
                    password_candidates=password_candidates,
                    selected_codepage=selected_codepage,
                    decoded_names=decoded_names,
                    task=task,
                    phase_timer=phase_timer,
                    phase_prefix=f"{phase_prefix}_build_job",
                )
        except (OSError, FileNotFoundError) as exc:
            return self._completed_process(
                ["sunpack_sevenzip_worker.exe"],
                -100,
                "",
                f"sevenzip_worker setup failed: {exc}",
                process_failure={
                    "failure_stage": "worker_setup",
                    "failure_kind": "process_start",
                    "message": str(exc),
                },
            )
        return self._run_worker(
            job,
            startupinfo=startupinfo,
            runtime_scheduler=runtime_scheduler,
            task=task,
            phase_timer=phase_timer,
            phase_prefix=phase_prefix,
        )

    def submit_extract(self, **kwargs) -> Future:
        """Submit an extraction attempt to native scheduling.

        Persistent workers receive the JSON request immediately and complete
        the returned future from the single stdout dispatcher.  The Python
        callback executor is used only for short completion continuations; it
        does not wait on native extraction jobs.
        """
        if not self._persistent_workers_enabled():
            return self._async_executor.submit(self.run_extract, **kwargs)
        try:
            job = self._build_job(
                archive_path=kwargs["archive_path"],
                part_paths=kwargs.get("part_paths") or [],
                out_dir=kwargs["out_dir"],
                password=kwargs.get("password"),
                password_candidates=kwargs.get("password_candidates"),
                selected_codepage=kwargs.get("selected_codepage"),
                decoded_names=kwargs.get("decoded_names") or [],
                task=kwargs["task"],
                phase_timer=kwargs.get("phase_timer"),
                phase_prefix=kwargs.get("phase_prefix", "sevenzip"),
            )
        except Exception as exc:
            future = Future()
            future.set_result(self._completed_process(
                [self.worker_path or "sunpack_sevenzip_worker.exe"],
                -100,
                "",
                f"sevenzip_worker setup failed: {exc}",
                process_failure={
                    "failure_stage": "worker_setup",
                    "failure_kind": "process_start",
                    "message": str(exc),
                },
            ))
            return future
        return self.submit_job(
            job,
            startupinfo=kwargs.get("startupinfo"),
            runtime_scheduler=kwargs.get("runtime_scheduler"),
            task=kwargs.get("task"),
            on_complete=kwargs.get("on_complete"),
        )

    def submit_continuation(self, callback: Callable[..., Any], *args, **kwargs) -> Future:
        """Run a short Python business continuation off the pipe reader."""
        return self._async_executor.submit(callback, *args, **kwargs)

    def failed_process_for_exception(
        self,
        exc: Exception,
        request: dict | None = None,
    ) -> subprocess.CompletedProcess:
        return self._completed_process(
            [self.worker_path or "sunpack_sevenzip_worker.exe"],
            -100,
            "",
            f"sevenzip_worker communication failed: {exc}",
            request_payload=request,
            process_failure={
                "failure_stage": "worker_communication",
                "failure_kind": "process_io",
                "message": str(exc),
            },
        )

    def submit_job(
        self,
        job: dict,
        *,
        startupinfo=None,
        runtime_scheduler: Any = None,
        task: ArchiveTask | None = None,
        on_complete=None,
    ) -> Future:
        """Submit an already prepared native job and return immediately.

        ``on_complete`` receives ``(job_id, completed_process)`` on the Python
        submission executor after the native result and all output writes have
        been observed. This is the low-level bridge for a future coordinator
        state machine; existing callers can continue using ``run_extract``.
        """
        prepared_job = dict(job)
        job_id = str(prepared_job.get("job_id") or "")
        if not job_id:
            raise ValueError("native job_id is required")
        if not self._persistent_workers_enabled():
            future = self._async_executor.submit(
                self._run_worker,
                prepared_job,
                startupinfo,
                runtime_scheduler,
                task,
            )
        else:
            future = Future()
            try:
                worker = self._pool().acquire(startupinfo)
                prepared_job["worker_epoch"] = worker.worker_epoch
                stdout_lines: list[str] = []
                stderr_lines: list[str] = []
                progress_events: list[dict[str, Any]] = []
                pending_result: subprocess.CompletedProcess | None = None
                pending_result_payload: dict[str, Any] | None = None
                backpressure_retries = 0
                max_backpressure_retries = max(
                    1,
                    int(self.process_config.get("native_backpressure_retries", 120) or 120),
                )
                payload = json.dumps(prepared_job, ensure_ascii=False, separators=(",", ":"))

                def complete(result: subprocess.CompletedProcess) -> None:
                    if not future.done():
                        future.set_result(result)

                def on_line(line: str) -> bool:
                    nonlocal pending_result, pending_result_payload, backpressure_retries
                    payload_value = self._json_line(line)
                    if payload_value:
                        payload_value.setdefault("worker_epoch", worker.worker_epoch)
                    if payload_value and payload_value.get("type") == "progress":
                        progress_events.append(payload_value)
                        self._emit_progress(task, payload_value)
                        return False
                    if payload_value and payload_value.get("type") == "native_event":
                        self._emit_native_event(task, payload_value)
                        if payload_value.get("event") == "job_finished" and pending_result is not None:
                            if (
                                isinstance(pending_result_payload, dict)
                                and pending_result_payload.get("retryable")
                                and pending_result_payload.get("native_status") == "backpressure"
                                and backpressure_retries < max_backpressure_retries
                            ):
                                backpressure_retries += 1
                                pending_result = None
                                pending_result_payload = None

                                def retry_submission() -> None:
                                    if future.done() or not worker.is_alive():
                                        return
                                    try:
                                        worker.submit_async(
                                            payload,
                                            job_id,
                                            on_line=on_line,
                                            on_timeout=on_timeout,
                                        )
                                    except Exception as exc:
                                        on_timeout(f"sevenzip_worker retry failed: {exc}")

                                delay = min(1.0, 0.05 * backpressure_retries)
                                timer = threading.Timer(delay, retry_submission)
                                timer.daemon = True
                                timer.start()
                                return True
                            complete(pending_result)
                            pending_result = None
                            pending_result_payload = None
                            return True
                        return False
                    if payload_value and payload_value.get("type") == "cancel_ack":
                        return False
                    if payload_value and payload_value.get("type") == "result":
                        returncode = 0 if payload_value.get("status") == "ok" else 1
                        self._drain_stderr(worker, stderr_lines)
                        pending_result = self._completed_process(
                            [worker.worker_path, "--persistent"],
                            returncode,
                            "".join(stdout_lines),
                            "".join(stderr_lines),
                            request_payload=prepared_job,
                            result_payload=payload_value,
                            progress_events=progress_events,
                        )
                        pending_result_payload = payload_value
                        return False
                    stdout_lines.append(line)
                    return False

                def on_timeout(message: str) -> None:
                    with worker._dispatch_lock:
                        lifecycle_state = dict(worker._job_states.get(job_id) or {})
                    failure_kind = "worker_lost" if not worker.is_alive() else "timeout"
                    complete(self._completed_process(
                        [worker.worker_path, "--persistent"],
                        -101,
                        "".join(stdout_lines),
                        message,
                        request_payload=prepared_job,
                        process_failure={
                            "failure_stage": "worker_communication",
                            "failure_kind": failure_kind,
                            "worker_epoch": worker.worker_epoch,
                            "job_state": lifecycle_state.get("state", "unknown"),
                            "message": message,
                        },
                        progress_events=progress_events,
                    ))

                worker.submit_async(
                    payload,
                    job_id,
                    on_line=on_line,
                    on_timeout=on_timeout,
                )
            except Exception as exc:
                complete(self._completed_process(
                    [self.worker_path or "sunpack_sevenzip_worker.exe"],
                    -100,
                    "",
                    f"sevenzip_worker communication failed: {exc}",
                    request_payload=prepared_job,
                    process_failure={
                        "failure_stage": "worker_communication",
                        "failure_kind": "process_io",
                        "message": str(exc),
                    },
                ))
        if on_complete is not None:
            def notify(done: Future) -> None:
                try:
                    on_complete(job_id, done.result())
                except Exception:
                    # Completion callbacks belong to the coordinator and must
                    # not turn a finished native job into an executor failure.
                    pass

            def dispatch_completion(done: Future) -> None:
                try:
                    self._async_executor.submit(notify, done)
                except RuntimeError:
                    notify(done)

            future.add_done_callback(dispatch_completion)
        return future

    def run_extract_batch(self, requests: list[dict], startupinfo=None) -> list[subprocess.CompletedProcess]:
        """Execute small independent archives through one persistent-worker IPC.

        Every request uses the same schema as ``_build_job``. Results retain their
        own job id and failure status; one bad archive does not suppress later jobs.
        The worker is discarded if the envelope times out, which cancels the only
        active native transaction safely.
        """
        if not requests:
            return []
        jobs = [dict(request) for request in requests]
        for index, job in enumerate(jobs):
            job.setdefault("job_id", f"batch-{index}")
            job.setdefault("seven_zip_dll_path", self._seven_zip_dll_path())
        batch_id = f"batch-{time.monotonic_ns()}"
        for job in jobs:
            job.setdefault("request_id", batch_id)
        worker = self._pool().acquire(startupinfo)
        for job in jobs:
            job["worker_epoch"] = worker.worker_epoch
        envelope = json.dumps(
            {"worker_command": "batch_extract", "batch_id": batch_id, "jobs": jobs},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        reusable = False
        lines_by_job: dict[str, list[str]] = {str(job["job_id"]): [] for job in jobs}
        returncodes: dict[str, int] = {}
        stderr_lines: list[str] = []
        job_ids = [str(job["job_id"]) for job in jobs]
        deadline_seconds = max(0.0, float(self.process_config.get("max_extract_task_seconds", 0) or 0))
        deadline = time.monotonic() + deadline_seconds * len(jobs) if deadline_seconds else 0.0
        try:
            for job_id in job_ids:
                worker.register_job(job_id)
            worker.send(envelope)
            while len(returncodes) < len(jobs):
                self._drain_stderr(worker, stderr_lines)
                if deadline and time.monotonic() > deadline:
                    worker.close()
                    raise TimeoutError("sevenzip_worker batch timed out")
                if not worker.is_alive():
                    raise RuntimeError("sevenzip_worker exited during batch")
                for job_id in job_ids:
                    if job_id in returncodes:
                        continue
                    try:
                        line = worker.read_job_line(job_id, timeout=0.01)
                    except queue.Empty:
                        continue
                    if line is None:
                        raise RuntimeError("sevenzip_worker closed stdout during batch")
                    payload = self._json_line(line)
                    lines_by_job[job_id].append(line)
                    if payload.get("type") == "result":
                        returncodes[job_id] = 0 if payload.get("status") == "ok" else 1
            reusable = True
            stderr = "".join(stderr_lines)
            return [self._completed_process(
                [worker.worker_path, "--persistent"],
                returncodes.get(str(job["job_id"]), -100),
                "".join(lines_by_job[str(job["job_id"])]),
                stderr,
                request_payload=job,
            ) for job in jobs]
        except Exception as exc:
            worker.close()
            return [self._completed_process(
                [self.worker_path or "sunpack_sevenzip_worker.exe"], -100, "",
                f"sevenzip_worker batch communication failed: {exc}", request_payload=job,
                process_failure={"failure_stage": "worker_communication", "failure_kind": "process_io", "message": str(exc)},
            ) for job in jobs]
        finally:
            for job_id in job_ids:
                worker.unregister_job(job_id)
            self._pool().release(worker, reusable=reusable)

    def run_extract_command(
        self,
        cmd: list[str],
        startupinfo,
        runtime_scheduler: Any,
        task: ArchiveTask,
    ) -> subprocess.CompletedProcess:
        archive_path = str(cmd[2]) if len(cmd) > 2 else getattr(task, "main_path", "")
        out_dir = ""
        password = ""
        for item in cmd:
            if isinstance(item, str) and item.startswith("-o"):
                out_dir = item[2:]
            if isinstance(item, str) and item.startswith("-p"):
                password = item[2:]
        attempt_id = f"{str(getattr(task, 'key', '') or archive_path)}:{time.monotonic_ns()}"
        job = {
            "job_id": attempt_id,
            "attempt_id": attempt_id,
            "request_id": str(self.request_id or ""),
            "seven_zip_dll_path": self._seven_zip_dll_path(),
            "archive_path": archive_path,
            "part_paths": [archive_path],
            "output_dir": out_dir,
            "password": password,
        }
        self._apply_native_job_budget(job)
        self._apply_native_scheduler_hints(job, task)
        try:
            fairness_weight = int(self.process_config.get("native_fairness_weight", 1) or 1)
        except (TypeError, ValueError):
            fairness_weight = 1
        job["native_fairness_weight"] = max(1, min(1024, fairness_weight))
        return self._run_worker(job, startupinfo=startupinfo, runtime_scheduler=runtime_scheduler, task=task)

    def _build_job(
        self,
        *,
        archive_path: str,
        part_paths: list[str],
        out_dir: str,
        password: str | None,
        password_candidates: list[str] | tuple[str, ...] | None,
        selected_codepage: str | None,
        decoded_names: list[str],
        task: ArchiveTask,
        phase_timer: Any | None = None,
        phase_prefix: str = "sevenzip_build_job",
    ) -> dict:
        attempt_id = f"{str(getattr(task, 'key', '') or archive_path)}:{time.monotonic_ns()}"
        job = {
            "job_id": attempt_id,
            "attempt_id": attempt_id,
            "request_id": str(self.request_id or ""),
            "seven_zip_dll_path": self._seven_zip_dll_path(),
            "archive_path": archive_path,
            "part_paths": list(part_paths or [archive_path]),
            "output_dir": out_dir,
            "password": password or "",
        }
        self._apply_native_job_budget(job)
        self._apply_native_scheduler_hints(job, task)
        candidates = tuple(dict.fromkeys(str(item) for item in (password_candidates or ()) if item is not None))
        if candidates:
            job["password_candidates"] = list(candidates)
        if selected_codepage:
            job["codepage"] = selected_codepage
            job["decoded_names"] = list(decoded_names)

        with _phase(phase_timer, f"{phase_prefix}_archive_state"):
            archive_state = self._archive_state(task)
        with _phase(phase_timer, f"{phase_prefix}_materialize_patched_state"):
            materialized_path = self._materialized_patched_archive(task, out_dir)
        if materialized_path:
            job["archive_path"] = materialized_path
            job["part_paths"] = [materialized_path]
            if archive_state:
                source = archive_state.get("source") if isinstance(archive_state.get("source"), dict) else {}
                if archive_state.get("format_hint") or source.get("format_hint"):
                    job["format_hint"] = archive_state.get("format_hint") or source.get("format_hint")
            return job
        if archive_state:
            job["archive_state"] = archive_state
            source = archive_state.get("source") if isinstance(archive_state.get("source"), dict) else {}
            if archive_state.get("format_hint") or source.get("format_hint"):
                job["format_hint"] = archive_state.get("format_hint") or source.get("format_hint")
        else:
            with _phase(phase_timer, f"{phase_prefix}_archive_input"):
                archive_input = self._archive_input(task, archive_path, part_paths)
            if archive_input:
                descriptor_payload = archive_input.to_dict()
                job["archive_input"] = descriptor_payload
                if descriptor_payload.get("format_hint"):
                    job["format_hint"] = descriptor_payload.get("format_hint")
        return job

    def _materialized_patched_archive(self, task: ArchiveTask, out_dir: str) -> str:
        try:
            state = task.archive_state()
        except Exception:
            return ""
        if not getattr(state, "patches", None):
            return ""
        target = Path(out_dir) / ".sunpack" / "patched_input"
        suffix = Path(str(state.source.entry_path or "")).suffix or ".bin"
        target = target.with_suffix(suffix)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            ArchiveStateByteView(state).materialize(target)
            return str(target)
        except Exception:
            return ""

    def _archive_state(self, task: ArchiveTask) -> dict | None:
        raw = getattr(getattr(task, "fact_bag", None), "get", lambda *_: None)("archive.state")
        if isinstance(raw, dict):
            return dict(raw)
        if hasattr(task, "archive_state"):
            try:
                return task.archive_state().to_dict()
            except Exception:
                return None
        return None

    def _archive_input(self, task: ArchiveTask, archive_path: str, part_paths: list[str]) -> ArchiveInputDescriptor | None:
        if hasattr(task, "archive_input"):
            raw = knowledge_view.source_input(task)
            if isinstance(raw, dict):
                return task.archive_input()
        raw = knowledge_view.source_input(task)
        if isinstance(raw, dict):
            return self._normalize_archive_input(raw, archive_path, part_paths)
        return None

    def _normalize_archive_input(self, raw: dict, archive_path: str, part_paths: list[str]) -> ArchiveInputDescriptor:
        if raw.get("kind") == "archive_input" or raw.get("open_mode"):
            return ArchiveInputDescriptor.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
        kind = str(raw.get("kind") or "file").lower()
        if kind == "file_range":
            return ArchiveInputDescriptor.from_source_input(raw, archive_path=archive_path, part_paths=part_paths)
        if kind == "concat_ranges":
            return ArchiveInputDescriptor.from_source_input(raw, archive_path=archive_path, part_paths=part_paths)
        return ArchiveInputDescriptor.from_parts(
            archive_path=archive_path,
            part_paths=list(part_paths or [archive_path]),
            format_hint=str(raw.get("format_hint") or raw.get("format") or ""),
        )

    @staticmethod
    def _completed_process(
        args,
        returncode: int | None,
        stdout: str,
        stderr: str,
        *,
        request_payload: dict | None = None,
        process_failure: dict | None = None,
        result_payload: dict | None = None,
        progress_events: list[dict] | None = None,
    ) -> subprocess.CompletedProcess:
        return attach_worker_diagnostics(
            subprocess.CompletedProcess(args, returncode, stdout or "", stderr or ""),
            request_payload=request_payload,
            process_failure=process_failure,
            result_payload=result_payload,
            progress_events=progress_events,
        )

    def _run_worker(
        self,
        job: dict,
        startupinfo,
        runtime_scheduler: Any,
        task: ArchiveTask,
        *,
        phase_timer: Any | None = None,
        phase_prefix: str = "sevenzip",
    ) -> subprocess.CompletedProcess:
        with _phase(phase_timer, f"{phase_prefix}_json_payload"):
            payload = json.dumps(job, ensure_ascii=False, separators=(",", ":"))
        if self._persistent_workers_enabled():
            with _phase(phase_timer, f"{phase_prefix}_persistent_total"):
                return self._run_persistent_worker(
                    payload,
                    startupinfo=startupinfo,
                    runtime_scheduler=runtime_scheduler,
                    task=task,
                    job=job,
                    phase_timer=phase_timer,
                    phase_prefix=phase_prefix,
                )
        if runtime_scheduler is None:
            try:
                completed = subprocess.run(
                    [self._worker_path()],
                    input=payload,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=startupinfo,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    env=self._worker_environment(),
                )
                return attach_worker_diagnostics(completed, request_payload=job)
            except (OSError, FileNotFoundError) as exc:
                return self._completed_process(
                    [self.worker_path or "sunpack_sevenzip_worker.exe"],
                    -100,
                    "",
                    f"sevenzip_worker failed to start: {exc}",
                    request_payload=job,
                    process_failure={
                        "failure_stage": "worker_start",
                        "failure_kind": "process_start",
                        "message": str(exc),
                    },
                )
        try:
            worker_path = self._worker_path()
            process = subprocess.Popen(
                [worker_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                startupinfo=startupinfo,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                env=self._worker_environment(),
            )
        except (OSError, FileNotFoundError) as exc:
            return self._completed_process(
                [self.worker_path or "sunpack_sevenzip_worker.exe"],
                -100,
                "",
                f"sevenzip_worker failed to start: {exc}",
                request_payload=job,
                process_failure={
                    "failure_stage": "worker_start",
                    "failure_kind": "process_start",
                    "message": str(exc),
                },
            )

        stdout, stderr = self._communicate_observed_worker(process, payload, runtime_scheduler, task)
        return self._completed_process(
            [self.worker_path or "sunpack_sevenzip_worker.exe"],
            process.returncode,
            stdout,
            stderr,
            request_payload=job,
        )

    def _persistent_workers_enabled(self) -> bool:
        return bool(self.process_config.get("persistent_workers", True))

    def _pool(self) -> _PersistentWorkerPool:
        with self._worker_pool_lock:
            if self._worker_pool is None:
                self._worker_pool = _PersistentWorkerPool(self._worker_path, self.process_config)
            return self._worker_pool

    def _run_persistent_worker(
        self,
        payload: str,
        startupinfo,
        runtime_scheduler: Any,
        task: ArchiveTask,
        job: dict,
        *,
        phase_timer: Any | None = None,
        phase_prefix: str = "sevenzip",
    ) -> subprocess.CompletedProcess:
        try:
            with _phase(phase_timer, f"{phase_prefix}_persistent_acquire"):
                worker = self._pool().acquire(startupinfo)
        except (OSError, FileNotFoundError, RuntimeError) as exc:
            return self._completed_process(
                [self.worker_path or "sunpack_sevenzip_worker.exe"],
                -100,
                "",
                f"sevenzip_worker failed to start: {exc}",
                request_payload=job,
                process_failure={
                    "failure_stage": "worker_start",
                    "failure_kind": "process_start",
                    "message": str(exc),
                },
            )

        reusable = False
        job_id = str(job.get("job_id") or "")
        if not job_id:
            worker.close()
            self._pool().release(worker, reusable=False)
            return self._completed_process(
                [self.worker_path or "sunpack_sevenzip_worker.exe"],
                -100,
                "",
                "sevenzip_worker job_id is required",
                request_payload=job,
                process_failure={
                    "failure_stage": "worker_setup",
                    "failure_kind": "invalid_job_id",
                    "message": "job_id is required for persistent worker dispatch",
                },
            )
        worker.register_job(job_id)
        job["worker_epoch"] = worker.worker_epoch
        try:
            with _phase(phase_timer, f"{phase_prefix}_persistent_send"):
                worker.send(payload)
            with _phase(phase_timer, f"{phase_prefix}_persistent_read_result"):
                stdout, stderr, returncode, reusable, result_payload, progress_events = self._read_persistent_worker_result(
                    worker, runtime_scheduler, task, job_id=job_id
                )
            process_failure = None
            if result_payload is None:
                with worker._dispatch_lock:
                    lifecycle_state = dict(worker._job_states.get(job_id) or {})
                process_failure = {
                    "failure_stage": "worker_communication",
                    "failure_kind": (
                        "worker_lost"
                        if not worker.is_alive()
                        else "process_timeout"
                        if returncode == -101
                        else "process_io"
                    ),
                    "worker_epoch": worker.worker_epoch,
                    "job_state": lifecycle_state.get("state", "unknown"),
                    "message": stderr or "sevenzip_worker ended without a result",
                }
            return self._completed_process(
                [worker.worker_path, "--persistent"],
                returncode,
                stdout,
                stderr,
                request_payload=job,
                process_failure=process_failure,
                result_payload=result_payload,
                progress_events=progress_events,
            )
        except Exception as exc:
            worker.close()
            return self._completed_process(
                [self.worker_path or "sunpack_sevenzip_worker.exe"],
                -100,
                "",
                f"sevenzip_worker communication failed: {exc}",
                request_payload=job,
                process_failure={
                    "failure_stage": "worker_communication",
                    "failure_kind": "process_io",
                    "worker_epoch": worker.worker_epoch,
                    "job_state": "unknown",
                    "message": str(exc),
                },
            )
        finally:
            worker.unregister_job(job_id)
            with _phase(phase_timer, f"{phase_prefix}_persistent_release"):
                self._pool().release(worker, reusable=reusable)

    def _read_persistent_worker_result(
        self,
        worker: _PersistentWorker,
        runtime_scheduler: Any,
        task: ArchiveTask,
        *,
        job_id: str | None = None,
    ) -> tuple[str, str, int, bool, dict[str, Any] | None, list[dict[str, Any]]]:
        interval = max(0.1, float(self.process_config.get("process_sample_interval_ms", 500) or 500) / 1000.0)
        max_task_seconds = max(0.0, float(self.process_config.get("max_extract_task_seconds", 0) or 0))
        no_progress_timeout = max(0.0, float(self.process_config.get("process_no_progress_timeout_seconds", 0) or 0))
        profile_key = self._task_profile_key(task)
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        progress_events: list[dict[str, Any]] = []
        started_at = time.monotonic()
        last_progress_at = started_at
        cancel_requested = False
        cancel_deadline = 0.0
        cancel_message = "sevenzip_worker timed out"
        last_io_bytes = 0
        ps_process = None
        if worker.process is not None:
            try:
                ps_process = psutil.Process(worker.process.pid)
                ps_process.cpu_percent(interval=None)
                try:
                    io_counters = ps_process.io_counters()
                    last_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes)
                except Exception:
                    last_io_bytes = 0
            except Exception:
                ps_process = None

        while True:
            self._drain_stderr(worker, stderr_lines)
            if worker.process is not None and worker.process.poll() is not None:
                self._drain_job(worker, job_id, stdout_lines)
                self._drain_stderr(worker, stderr_lines)
                return (
                    "".join(stdout_lines),
                    "".join(stderr_lines),
                    -101,
                    False,
                    None,
                    progress_events,
                )
            try:
                if job_id and hasattr(worker, "read_job_line"):
                    line = worker.read_job_line(job_id, timeout=interval)
                elif hasattr(worker, "_orphan_queue"):
                    line = worker._orphan_queue.get(timeout=interval)
                else:
                    line = worker.stdout_queue.get(timeout=interval)
            except queue.Empty:
                now = time.monotonic()
                timed_out = max_task_seconds and now - started_at > max_task_seconds
                if no_progress_timeout and now - last_progress_at > no_progress_timeout:
                    timed_out = True
                    cancel_message = "sevenzip_worker made no observable progress"
                if timed_out and not cancel_requested:
                    try:
                        worker.cancel(job_id)
                        cancel_requested = True
                        cancel_deadline = now + max(
                            0.5,
                            float(self.process_config.get("cancel_grace_seconds", 5) or 5),
                        )
                    except Exception:
                        worker.close()
                        return "".join(stdout_lines), "\n".join([*stderr_lines, cancel_message]).strip(), -101, False, None, progress_events
                if cancel_requested and now > cancel_deadline:
                    # The native cancellation path normally reaches Write or
                    # SetCompleted quickly. A stuck DLL is the one case where
                    # process isolation must still win, but this is delayed
                    # until the cancellation grace period expires.
                    worker.close()
                    return "".join(stdout_lines), "\n".join([*stderr_lines, cancel_message]).strip(), -101, False, None, progress_events
                if not cancel_requested and self._record_persistent_progress(ps_process, runtime_scheduler, profile_key, last_io_bytes):
                    try:
                        io_counters = ps_process.io_counters() if ps_process is not None else None
                        last_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes) if io_counters is not None else last_io_bytes
                    except Exception:
                        pass
                    last_progress_at = now
                continue
            if line is None:
                code = worker.process.returncode if worker.process is not None else 1
                return "".join(stdout_lines), "".join(stderr_lines), code or 1, False, None, progress_events
            last_progress_at = time.monotonic()
            payload = self._json_line(line)
            if payload:
                payload.setdefault("worker_epoch", worker.worker_epoch)
            if payload and payload.get("type") == "progress":
                progress_events.append(payload)
                self._emit_progress(task, payload)
                continue
            if payload and payload.get("type") == "native_event":
                self._emit_native_event(task, payload)
                continue
            if payload and payload.get("type") == "cancel_ack":
                continue
            if payload and payload.get("type") == "result":
                returncode = -101 if cancel_requested else (0 if payload.get("status") == "ok" else 1)
                self._drain_stderr(worker, stderr_lines)
                stderr = "".join(stderr_lines)
                if cancel_requested:
                    stderr = "\n".join([stderr, cancel_message]).strip()
                return "".join(stdout_lines), stderr, returncode, True, payload, progress_events
            stdout_lines.append(line)

    @staticmethod
    def _json_line(line: str) -> dict:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _drain_job(worker: _PersistentWorker, job_id: str, stdout_lines: list[str]) -> None:
        while True:
            try:
                if job_id and hasattr(worker, "read_job_line"):
                    line = worker.read_job_line(job_id, timeout=0)
                elif hasattr(worker, "_orphan_queue"):
                    line = worker._orphan_queue.get_nowait()
                else:
                    line = worker.stdout_queue.get_nowait()
            except queue.Empty:
                return
            if line is not None:
                stdout_lines.append(line)

    @staticmethod
    def _drain_stderr(worker: _PersistentWorker, stderr_lines: list[str]) -> None:
        while True:
            try:
                line = worker.stderr_queue.get_nowait()
            except queue.Empty:
                return
            if line is not None:
                stderr_lines.append(line)

    @staticmethod
    def _record_persistent_progress(ps_process, runtime_scheduler: Any, profile_key: str, last_io_bytes: int) -> bool:
        if ps_process is None:
            return False
        try:
            cpu_percent = ps_process.cpu_percent(interval=None)
            memory_bytes = ps_process.memory_info().rss
            io_counters = ps_process.io_counters()
            now_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes)
            io_delta = max(0, now_io_bytes - last_io_bytes)
            return io_delta > 0 or cpu_percent > 0.1
        except Exception:
            return False

    def communicate_observed_process(
        self,
        process: subprocess.Popen,
        runtime_scheduler: Any,
        task: ArchiveTask,
    ) -> tuple[str, str]:
        return self._communicate_observed_process(process, runtime_scheduler, task)

    def _communicate_observed_process(
        self,
        process: subprocess.Popen,
        runtime_scheduler: Any,
        task: ArchiveTask,
    ) -> tuple[str, str]:
        interval = max(0.1, float(self.process_config.get("process_sample_interval_ms", 500) or 500) / 1000.0)
        max_task_seconds = max(0.0, float(self.process_config.get("max_extract_task_seconds", 0) or 0))
        no_progress_timeout = max(0.0, float(self.process_config.get("process_no_progress_timeout_seconds", 0) or 0))
        profile_key = self._task_profile_key(task)
        ps_process = None
        last_io_bytes = 0
        started_at = time.monotonic()
        last_progress_at = started_at
        try:
            ps_process = psutil.Process(process.pid)
            ps_process.cpu_percent(interval=None)
            try:
                io_counters = ps_process.io_counters()
                last_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes)
            except Exception:
                last_io_bytes = 0
        except Exception:
            ps_process = None

        while True:
            try:
                return process.communicate(timeout=interval)
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                if max_task_seconds and now - started_at > max_task_seconds:
                    return self.terminate_observed_process(process, -101, "sevenzip_worker timed out")
                if ps_process is None:
                    if no_progress_timeout and now - last_progress_at > no_progress_timeout:
                        return self.terminate_observed_process(process, -102, "sevenzip_worker made no observable progress")
                    continue
                try:
                    cpu_percent = ps_process.cpu_percent(interval=None)
                    memory_bytes = ps_process.memory_info().rss
                    io_counters = ps_process.io_counters()
                    now_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes)
                    io_delta = max(0, now_io_bytes - last_io_bytes)
                    last_io_bytes = now_io_bytes
                    if io_delta > 0 or cpu_percent > 0.1:
                        last_progress_at = now
                    if no_progress_timeout and now - last_progress_at > no_progress_timeout:
                        return self.terminate_observed_process(process, -102, "sevenzip_worker made no observable progress")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    ps_process = None
                except Exception:
                    continue

    def _worker_path(self) -> str:
        if self.worker_path is None:
            self.worker_path = get_sevenzip_bridge_worker_path()
        return self.worker_path

    def _worker_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        _apply_native_environment(environment, self.process_config)
        return environment

    def close(self) -> None:
        if not self._owns_worker_pool:
            return
        with self._worker_pool_lock:
            pool = self._worker_pool
            self._worker_pool = None
        if self._owns_async_executor:
            self._async_executor.shutdown(wait=True, cancel_futures=False)
        if pool is not None:
            pool.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _seven_zip_dll_path(self) -> str:
        if self.seven_zip_dll_path is None:
            self.seven_zip_dll_path = get_7z_dll_path()
        return self.seven_zip_dll_path

    def _apply_native_job_budget(self, job: dict) -> None:
        configured = self.process_config.get("native_job_buffer_budget_bytes")
        if configured is None:
            return
        try:
            budget = int(configured)
        except (TypeError, ValueError):
            return
        if budget > 0:
            job["job_buffer_budget_bytes"] = budget

    def _apply_native_scheduler_hints(self, job: dict, task: ArchiveTask) -> None:
        """Translate Python inspection facts into native admission hints.

        These are estimates only. Native owns the actual reservations and may
        keep a job queued when its resource class does not fit.
        """
        tokens = knowledge_view.resource_tokens(task)
        analysis = knowledge_view.resource_analysis(task)
        try:
            cpu_weight = max(1, min(8, int(tokens.get("cpu", 1) or 1)))
        except (TypeError, ValueError):
            cpu_weight = 1
        try:
            io_weight = max(1, min(8, int(tokens.get("io", 1) or 1)))
        except (TypeError, ValueError):
            io_weight = 1
        try:
            memory_weight = max(1, min(8, int(tokens.get("memory", 1) or 1)))
        except (TypeError, ValueError):
            memory_weight = 1
        try:
            dictionary_bytes = max(0, int(analysis.get("largest_dictionary_size", 0) or 0))
        except (TypeError, ValueError):
            dictionary_bytes = 0
        native_memory = max(64 << 20, memory_weight * (32 << 20), dictionary_bytes + (32 << 20))
        job["native_cpu_weight"] = cpu_weight
        job["native_io_weight"] = io_weight
        job["native_memory_reserve_bytes"] = native_memory
        job["native_dictionary_reserve_bytes"] = dictionary_bytes
        job["native_solid_archive"] = bool(analysis.get("solid", False))
        profile_key = self._task_profile_key(task)
        if profile_key:
            job["native_profile_key"] = profile_key
        try:
            job["native_expected_output_bytes"] = max(
                0, int(analysis.get("total_unpacked_size", 0) or 0)
            )
            job["native_expected_file_count"] = max(0, int(analysis.get("file_count", 0) or 0))
        except (TypeError, ValueError):
            pass

    def _communicate_observed_worker(
        self,
        process: subprocess.Popen,
        payload: str,
        runtime_scheduler: Any,
        task: ArchiveTask,
    ) -> tuple[str, str]:
        interval = max(0.1, float(self.process_config.get("process_sample_interval_ms", 500) or 500) / 1000.0)
        max_task_seconds = max(0.0, float(self.process_config.get("max_extract_task_seconds", 0) or 0))
        no_progress_timeout = max(0.0, float(self.process_config.get("process_no_progress_timeout_seconds", 0) or 0))
        profile_key = self._task_profile_key(task)
        started_at = time.monotonic()
        last_progress_at = started_at
        last_io_bytes = 0
        ps_process = None
        try:
            ps_process = psutil.Process(process.pid)
            ps_process.cpu_percent(interval=None)
            try:
                io_counters = ps_process.io_counters()
                last_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes)
            except Exception:
                last_io_bytes = 0
        except Exception:
            ps_process = None

        try:
            return process.communicate(input=payload, timeout=interval)
        except subprocess.TimeoutExpired:
            pass

        while True:
            try:
                return process.communicate(timeout=interval)
            except subprocess.TimeoutExpired:
                now = time.monotonic()
                if max_task_seconds and now - started_at > max_task_seconds:
                    return self.terminate_observed_process(process, -101, "sevenzip_worker timed out")
                if ps_process is None:
                    if no_progress_timeout and now - last_progress_at > no_progress_timeout:
                        return self.terminate_observed_process(process, -102, "sevenzip_worker made no observable progress")
                    continue
                try:
                    cpu_percent = ps_process.cpu_percent(interval=None)
                    memory_bytes = ps_process.memory_info().rss
                    io_counters = ps_process.io_counters()
                    now_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes)
                    io_delta = max(0, now_io_bytes - last_io_bytes)
                    last_io_bytes = now_io_bytes
                    if io_delta > 0 or cpu_percent > 0.1:
                        last_progress_at = now
                    if no_progress_timeout and now - last_progress_at > no_progress_timeout:
                        return self.terminate_observed_process(process, -102, "sevenzip_worker made no observable progress")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    ps_process = None
                except Exception:
                    continue

    def terminate_observed_process(
        self,
        process: subprocess.Popen,
        returncode: int,
        message: str,
    ) -> tuple[str, str]:
        try:
            process.kill()
        except Exception:
            pass
        try:
            stdout, stderr = process.communicate(timeout=2.0)
        except Exception:
            stdout, stderr = "", ""
        process.returncode = returncode
        return stdout or "", f"{stderr or ''}\n{message}".strip()

    def _task_profile_key(self, task: ArchiveTask | None) -> str:
        if task is None:
            return "unknown"
        profile_key = knowledge_view.resource_profile_key(task)
        if profile_key:
            return profile_key
        return "unknown"

    def _emit_progress(self, task: ArchiveTask, event: dict[str, Any]) -> None:
        callback = self.progress_callback
        if callback is None:
            return
        try:
            callback(task, event)
        except Exception:
            pass

    def _emit_native_event(self, task: ArchiveTask | None, event: dict[str, Any]) -> None:
        callback = self.native_event_callback
        if callback is None:
            return
        try:
            callback(task, event)
        except Exception:
            pass


def _phase(timer: Any | None, name: str):
    if timer is None:
        return nullcontext()
    return timer(name)
