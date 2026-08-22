import asyncio
import json
import os
import queue
import subprocess
import threading
import time
import uuid
from concurrent.futures import Future
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable

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

    thread_capacity = process_config.get("thread_capacity")
    if thread_capacity is not None:
        try:
            thread_capacity = int(thread_capacity)
        except (TypeError, ValueError):
            thread_capacity = None
        if thread_capacity is not None:
            environment.pop("SUNPACK_NATIVE_WORKER_THREAD_CAPACITY", None)
            if thread_capacity > 0:
                environment["SUNPACK_NATIVE_WORKER_THREAD_CAPACITY"] = str(thread_capacity)
    set_int("writer_threads", "SUNPACK_ASYNC_WRITER_THREADS")
    set_int("sample_interval_ms", "SUNPACK_NATIVE_SAMPLE_INTERVAL_MS", minimum=100)
    set_int("initial_active_jobs", "SUNPACK_NATIVE_INITIAL_ACTIVE_JOBS", minimum=0)

    memory_budget = process_config.get("memory_budget_bytes")
    try:
        memory_budget = int(memory_budget) if memory_budget is not None else 0
    except (TypeError, ValueError):
        memory_budget = 0
    if process_config.get("memory_budget_bytes") is not None:
        environment.pop("SUNPACK_NATIVE_MEMORY_BUDGET_BYTES", None)
    if memory_budget > 0:
        environment["SUNPACK_NATIVE_MEMORY_BUDGET_BYTES"] = str(memory_budget)

    native_adaptive = process_config.get("adaptive_enabled")
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
    set_float("idle_decay_seconds", "SUNPACK_NATIVE_WORKER_IDLE_DECAY_SECONDS")
    set_float("idle_limit_recovery_seconds", "SUNPACK_NATIVE_IDLE_LIMIT_RECOVERY_SECONDS")
    set_float("monitor_idle_stop_seconds", "SUNPACK_NATIVE_MONITOR_IDLE_STOP_SECONDS")
    set_float("resume_warmup_seconds", "SUNPACK_NATIVE_RESUME_WARMUP_SECONDS")
    set_int("medium_backlog_threshold", "SUNPACK_NATIVE_MEDIUM_BACKLOG_THRESHOLD")
    set_int("high_backlog_threshold", "SUNPACK_NATIVE_HIGH_BACKLOG_THRESHOLD")
    set_int("medium_floor_workers", "SUNPACK_NATIVE_MEDIUM_FLOOR_JOBS")
    set_int("high_floor_workers", "SUNPACK_NATIVE_HIGH_FLOOR_JOBS")
    set_float("cpu_scale_up_threshold_percent", "SUNPACK_NATIVE_CPU_SCALE_UP_PERCENT")
    set_float("cpu_scale_down_threshold_percent", "SUNPACK_NATIVE_CPU_SCALE_DOWN_PERCENT")
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
    set_int("max_queue_jobs", "SUNPACK_NATIVE_MAX_QUEUE_JOBS")
    set_float("profile_regression_ratio", "SUNPACK_NATIVE_PROFILE_REGRESSION_RATIO")
    set_float("profile_improvement_ratio", "SUNPACK_NATIVE_PROFILE_IMPROVEMENT_RATIO")
    worker_profile = process_config.get("profile")
    if worker_profile:
        environment["SUNPACK_NATIVE_WORKER_PROFILE"] = str(worker_profile)
    process_mode = str(process_config.get("windows_process_mode") or "").strip().lower()
    environment.pop("SUNPACK_NATIVE_PROCESS_MODE", None)
    if process_mode == "background":
        environment["SUNPACK_NATIVE_PROCESS_MODE"] = process_mode
    # Profile feedback is process-local. Drop removed cache variables from the
    # inherited environment as well.
    environment.pop("SUNPACK_NATIVE_PROFILE_CACHE_PATH", None)
    environment.pop("SUNPACK_NATIVE_PROFILE_CACHE_ENABLED", None)
    return environment


class _NativeWorkerProcess:
    def __init__(self, worker_path: str, startupinfo, process_config: dict | None = None):
        self.worker_path = worker_path
        self.startupinfo = startupinfo
        self.process_config = process_config or {}
        self.process: subprocess.Popen | None = None
        self.worker_epoch = ""
        self.stderr_queue: queue.Queue[str | None] = queue.Queue()
        self._controller_events: list[dict[str, Any]] = []
        self._job_states: dict[str, dict[str, Any]] = {}
        self._async_jobs: dict[str, dict[str, Any]] = {}
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
            [self.worker_path],
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
            if job_id in self._job_states:
                raise RuntimeError(f"sevenzip_worker job id is already active: {job_id}")
            self._job_states[job_id] = {
                "state": "submitted",
                "worker_epoch": self.worker_epoch,
            }

    def controller_events(self) -> list[dict[str, Any]]:
        with self._dispatch_lock:
            return list(self._controller_events)

    def submit_async(
        self,
        payload: str,
        job_id: str,
        *,
        on_line: Callable[[str], bool],
        on_timeout: Callable[[str], None],
    ) -> None:
        """Send a job without allocating a Python wait thread.

        The stdout dispatcher is the only reader of the long-lived worker's
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
                float(self.process_config.get("max_task_seconds", 0) or 0),
            ),
            "no_progress_timeout": max(
                0.0,
                float(self.process_config.get("watchdog_no_progress_timeout_seconds", 0) or 0),
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
            self._job_states.pop(job_id, None)
        return state

    def _dispatch_stdout(self, stream) -> None:
        try:
            for line in stream:
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    payload = {}
                job_id = str(payload.get("job_id") or "") if isinstance(payload, dict) else ""
                with self._dispatch_lock:
                    if isinstance(payload, dict) and payload.get("type") == "native_controller":
                        self._controller_events.append({"received_at": time.perf_counter(), **payload})
                    async_state = self._async_jobs.get(job_id) if job_id else None
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
        except Exception:
            pass
        finally:
            with self._dispatch_lock:
                async_jobs = list(self._async_jobs.items())
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
        interval = max(
            0.01,
            float(self.process_config.get("watchdog_interval_ms", 100) or 100) / 1000.0,
        )
        while not self._watchdog_stop.wait(interval):
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


class _NativeWorkerHolder:
    def __init__(self, worker_path_callback, process_config: dict):
        self.worker_path_callback = worker_path_callback
        self.process_config = process_config
        self._lock = threading.Lock()
        self._worker: _NativeWorkerProcess | None = None
        self._closed = False

    def get_or_start(self, startupinfo) -> _NativeWorkerProcess:
        with self._lock:
            if self._closed:
                raise RuntimeError("native worker is closed")
            if self._worker is not None and self._worker.is_alive():
                return self._worker
            if self._worker is not None:
                self._worker.close()
            self._worker = _NativeWorkerProcess(
                self.worker_path_callback(), startupinfo, self.process_config
            )
            return self._worker

    def close(self) -> None:
        with self._lock:
            self._closed = True
            worker = self._worker
            self._worker = None
        if worker is not None:
            worker.close()


class _AsyncNativeWorkerProcess:
    """Long-lived native worker transported entirely by the owner event loop."""

    def __init__(self, worker_path: str, startupinfo, process_config: dict | None = None):
        self.worker_path = worker_path
        self.startupinfo = startupinfo
        self.process_config = process_config or {}
        self.process: asyncio.subprocess.Process | None = None
        self.worker_epoch = ""
        self._jobs: dict[str, dict[str, Any]] = {}
        self._stderr_lines: list[str] = []
        self._send_lock = asyncio.Lock()
        self._tasks: list[asyncio.Task] = []
        self._closing = False
        self.handshake: dict[str, Any] = {}
        self._ready: asyncio.Future | None = None

    async def start(self) -> None:
        if self.is_alive():
            return
        self.worker_epoch = uuid.uuid4().hex
        environment = _apply_native_environment(os.environ.copy(), self.process_config)
        # The native worker reports each finished job as a single JSON line on
        # stdout whose size grows with the extracted file count.  asyncio's
        # default StreamReader limit is 64 KiB; a result line that exceeds it
        # raises LimitOverrunError inside readline(), silently killing the
        # stdout dispatcher and leaving every pending job future unresolved.
        # Raise the per-line cap so large archives (thousands of entries) can
        # complete instead of hanging the pipeline after extraction finishes.
        self.process = await asyncio.create_subprocess_exec(
            self.worker_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=64 * 1024 * 1024,
            startupinfo=self.startupinfo,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            cwd=runtime_working_directory(),
            env=environment,
        )
        self._ready = asyncio.get_running_loop().create_future()
        self._tasks = [
            asyncio.create_task(self._dispatch_stdout(), name="sunpack-native-stdout"),
            asyncio.create_task(self._pump_stderr(), name="sunpack-native-stderr"),
            asyncio.create_task(self._watchdog(), name="sunpack-native-watchdog"),
        ]
        try:
            await asyncio.wait_for(asyncio.shield(self._ready), timeout=2.0)
        except asyncio.TimeoutError:
            self.handshake = {
                "profile": str(self.process_config.get("profile") or "auto"),
                "thread_capacity": int(self.process_config.get("thread_capacity", 0) or (os.cpu_count() or 1)),
                "initial_active_limit": int(self.process_config.get("initial_active_jobs", 0) or 1),
                "legacy_worker": True,
            }

    def is_alive(self) -> bool:
        return self.process is not None and self.process.returncode is None

    async def submit(self, payload: str, job_id: str, *, on_line, on_timeout) -> None:
        if job_id in self._jobs:
            raise RuntimeError(f"sevenzip_worker job id is already active: {job_id}")
        now = time.monotonic()
        self._jobs[job_id] = {
            "on_line": on_line,
            "on_timeout": on_timeout,
            "started_at": now,
            "last_progress_at": now,
            "cancel_requested": False,
            "cancel_deadline": 0.0,
            "state": "submitted",
        }
        try:
            await self.send(payload)
        except BaseException:
            self._jobs.pop(job_id, None)
            raise

    async def send(self, payload: str) -> None:
        if not self.is_alive() or self.process is None or self.process.stdin is None:
            raise RuntimeError("sevenzip_worker is not running")
        async with self._send_lock:
            self.process.stdin.write((payload + "\n").encode("utf-8"))
            await self.process.stdin.drain()

    async def cancel(self, job_id: str) -> None:
        await self.send(json.dumps({"worker_command": "cancel", "job_id": job_id}, separators=(",", ":")))

    def take_stderr(self) -> list[str]:
        lines = self._stderr_lines
        self._stderr_lines = []
        return lines

    async def _dispatch_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        try:
            while line_bytes := await self.process.stdout.readline():
                line = line_bytes.decode("utf-8", "replace")
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    payload = {}
                job_id = str(payload.get("job_id") or "") if isinstance(payload, dict) else ""
                if isinstance(payload, dict) and payload.get("type") == "worker_ready":
                    self.handshake = dict(payload)
                    if self._ready is not None and not self._ready.done():
                        self._ready.set_result(self.handshake)
                    continue
                state = self._jobs.get(job_id)
                if state is None:
                    continue
                state["last_progress_at"] = time.monotonic()
                event = str(payload.get("event") or "") if isinstance(payload, dict) else ""
                if payload.get("type") == "result":
                    state["state"] = "result_received"
                elif event:
                    state["state"] = event.removeprefix("job_")
                try:
                    completed = bool(state["on_line"](line))
                except Exception as exc:
                    state["on_timeout"](f"sevenzip_worker completion callback failed: {exc}")
                    completed = True
                if completed:
                    self._jobs.pop(job_id, None)
        finally:
            if not self._closing:
                for job_id, state in tuple(self._jobs.items()):
                    state["on_timeout"]("sevenzip_worker exited before job completion")
                    self._jobs.pop(job_id, None)

    async def _pump_stderr(self) -> None:
        assert self.process is not None and self.process.stderr is not None
        while line := await self.process.stderr.readline():
            self._stderr_lines.append(line.decode("utf-8", "replace"))

    async def _watchdog(self) -> None:
        interval = max(0.01, float(self.process_config.get("watchdog_interval_ms", 100) or 100) / 1000.0)
        while not self._closing and self.is_alive():
            await asyncio.sleep(interval)
            now = time.monotonic()
            for job_id, state in tuple(self._jobs.items()):
                max_seconds = max(0.0, float(self.process_config.get("max_task_seconds", 0) or 0))
                no_progress_seconds = max(
                    0.0,
                    float(self.process_config.get("watchdog_no_progress_timeout_seconds", 0) or 0),
                )
                timed = bool(max_seconds and now - state["started_at"] > max_seconds)
                stalled = bool(no_progress_seconds and now - state["last_progress_at"] > no_progress_seconds)
                if not timed and not stalled:
                    if not state["cancel_requested"] or now <= state["cancel_deadline"]:
                        continue
                message = "sevenzip_worker made no observable progress" if stalled else "sevenzip_worker timed out"
                if not state["cancel_requested"]:
                    state["cancel_requested"] = True
                    state["cancel_deadline"] = now + max(
                        0.5, float(self.process_config.get("cancel_grace_seconds", 5) or 5)
                    )
                    try:
                        await self.cancel(job_id)
                    except Exception:
                        state["cancel_deadline"] = 0.0
                    continue
                state["on_timeout"](message)
                self._jobs.pop(job_id, None)

    async def close(self) -> None:
        if self.process is None:
            return
        self._closing = True
        if self.is_alive():
            try:
                await self.send('{"worker_command":"shutdown","job_id":"shutdown"}')
                await asyncio.wait_for(self.process.wait(), timeout=0.5)
            except (Exception, asyncio.CancelledError):
                if self.is_alive():
                    self.process.terminate()
                    try:
                        await asyncio.wait_for(self.process.wait(), timeout=0.5)
                    except Exception:
                        self.process.kill()
        current = asyncio.current_task()
        for task in self._tasks:
            if task is not current and not task.done():
                task.cancel()
        await asyncio.gather(*(task for task in self._tasks if task is not current), return_exceptions=True)
        self._tasks.clear()


class _AsyncNativeWorkerHolder:
    def __init__(self, worker_path_callback, process_config: dict):
        self.worker_path_callback = worker_path_callback
        self.process_config = process_config
        self._lock = asyncio.Lock()
        self._worker: _AsyncNativeWorkerProcess | None = None
        self._closed = False

    async def get_or_start(self, startupinfo) -> _AsyncNativeWorkerProcess:
        async with self._lock:
            if self._closed:
                raise RuntimeError("native worker is closed")
            if self._worker is None or not self._worker.is_alive():
                if self._worker is not None:
                    await self._worker.close()
                self._worker = _AsyncNativeWorkerProcess(
                    self.worker_path_callback(), startupinfo, self.process_config
                )
                await self._worker.start()
            return self._worker

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            worker = self._worker
            self._worker = None
        if worker is not None:
            await worker.close()


class SevenZipRunner:
    def __init__(
        self,
        process_config: dict,
        *,
        shared_worker_holder: _NativeWorkerHolder | None = None,
        shared_async_worker_holder: _AsyncNativeWorkerHolder | None = None,
        event_loop=None,
    ):
        self.process_config = process_config
        self.progress_callback = None
        self.native_event_callback = None
        self.request_id = ""
        self.worker_path = None
        self.seven_zip_dll_path = None
        self._worker_holder: _NativeWorkerHolder | None = shared_worker_holder
        self._owns_worker_holder = shared_worker_holder is None
        self._async_worker_holder = shared_async_worker_holder
        self._owns_async_worker_holder = shared_async_worker_holder is None
        self._worker_holder_lock = threading.Lock()
        self._event_loop = event_loop

    def fork(self) -> "SevenZipRunner":
        """Create request-local callback state while sharing native workers."""
        shared_holder = self._worker_holder_or_create()
        shared_async_holder = self._async_worker_holder_or_create()
        runner = SevenZipRunner(
            self.process_config,
            shared_worker_holder=shared_holder,
            shared_async_worker_holder=shared_async_holder,
            event_loop=self._event_loop,
        )
        runner.worker_path = self.worker_path
        runner.seven_zip_dll_path = self.seven_zip_dll_path
        runner.native_event_callback = self.native_event_callback
        runner.request_id = self.request_id
        return runner

    def bind_event_loop(self, loop) -> None:
        self._event_loop = loop

    async def start_asyncio(self) -> dict[str, Any]:
        worker = await self._async_worker_holder_or_create().get_or_start(None)
        return dict(worker.handshake)

    def extract_attempt(
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
        return self.submit_attempt(
            job,
            startupinfo=startupinfo,
            task=task,
        ).result()

    def submit_attempt(self, job: dict | None = None, **kwargs) -> Future:
        """Submit an extraction attempt to native scheduling.

        Persistent workers receive the JSON request immediately and complete
        the returned future from the single stdout dispatcher.  The Python
        callback executor is used only for short completion continuations; it
        does not wait on native extraction jobs.
        """
        try:
            if job is None:
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
        return self._submit_native_job(
            job,
            startupinfo=kwargs.get("startupinfo"),
            task=kwargs.get("task"),
            on_complete=kwargs.get("on_complete"),
        )

    async def submit_attempt_asyncio(self, job: dict | None = None, **kwargs) -> subprocess.CompletedProcess:
        """Submit and await one native attempt without pipe or continuation threads."""
        try:
            if job is None:
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
            return self.failed_process_for_exception(exc, job)
        return await self._submit_native_job_asyncio(
            job,
            startupinfo=kwargs.get("startupinfo"),
            task=kwargs.get("task"),
        )

    async def _submit_native_job_asyncio(
        self,
        job: dict,
        *,
        startupinfo=None,
        task: ArchiveTask | None = None,
    ) -> subprocess.CompletedProcess:
        prepared_job = dict(job)
        job_id = str(prepared_job.get("job_id") or "")
        if not job_id:
            raise ValueError("native job_id is required")
        result_future = asyncio.get_running_loop().create_future()
        worker: _AsyncNativeWorkerProcess | None = None
        try:
            worker = await self._async_worker_holder_or_create().get_or_start(startupinfo)
            prepared_job["worker_epoch"] = worker.worker_epoch
            stdout_lines: list[str] = []
            stderr_lines: list[str] = []
            progress_events: list[dict[str, Any]] = []
            pending_result: subprocess.CompletedProcess | None = None
            pending_payload: dict[str, Any] | None = None
            retries = 0
            max_retries = max(1, int(self.process_config.get("backpressure_retries", 120) or 120))
            payload_text = json.dumps(prepared_job, ensure_ascii=False, separators=(",", ":"))

            def complete(value: subprocess.CompletedProcess) -> None:
                if not result_future.done():
                    result_future.set_result(value)

            async def retry_after_backpressure(delay: float) -> None:
                await asyncio.sleep(delay)
                if result_future.done() or not worker.is_alive():
                    return
                try:
                    await worker.submit(payload_text, job_id, on_line=on_line, on_timeout=on_timeout)
                except Exception as exc:
                    on_timeout(f"native worker retry failed: {exc}")

            def on_line(line: str) -> bool:
                nonlocal pending_result, pending_payload, retries
                value = self._json_line(line)
                if value:
                    value.setdefault("worker_epoch", worker.worker_epoch)
                if value and value.get("type") == "progress":
                    progress_events.append(value)
                    self._emit_progress(task, value)
                    return False
                if value and value.get("type") == "native_event":
                    self._emit_native_event(task, value)
                    if value.get("event") != "job_finished" or pending_result is None:
                        return False
                    if (
                        isinstance(pending_payload, dict)
                        and pending_payload.get("retryable")
                        and pending_payload.get("native_status") == "backpressure"
                        and retries < max_retries
                    ):
                        retries += 1
                        pending_result = None
                        pending_payload = None
                        asyncio.create_task(
                            retry_after_backpressure(min(1.0, 0.05 * retries)),
                            name=f"native-backpressure-{job_id}",
                        )
                        return True
                    complete(pending_result)
                    pending_result = None
                    pending_payload = None
                    return True
                if value and value.get("type") == "cancel_ack":
                    return False
                if value and value.get("type") == "result":
                    stderr_lines.extend(worker.take_stderr())
                    pending_result = self._completed_process(
                        [worker.worker_path],
                        0 if value.get("status") == "ok" else 1,
                        "".join(stdout_lines),
                        "".join(stderr_lines),
                        request_payload=prepared_job,
                        result_payload=value,
                        progress_events=progress_events,
                    )
                    pending_payload = value
                    return False
                stdout_lines.append(line)
                return False

            def on_timeout(message: str) -> None:
                complete(self._completed_process(
                    [worker.worker_path],
                    -101,
                    "".join(stdout_lines),
                    message,
                    request_payload=prepared_job,
                    process_failure={
                        "failure_stage": "worker_communication",
                        "failure_kind": "worker_lost" if not worker.is_alive() else "timeout",
                        "worker_epoch": worker.worker_epoch,
                        "message": message,
                    },
                    progress_events=progress_events,
                ))

            await worker.submit(payload_text, job_id, on_line=on_line, on_timeout=on_timeout)
            try:
                return await result_future
            except asyncio.CancelledError:
                try:
                    await worker.cancel(job_id)
                except Exception:
                    pass
                raise
        except Exception as exc:
            return self._completed_process(
                [self.worker_path or "sunpack_sevenzip_worker.exe"],
                -100,
                "",
                f"native worker communication failed: {exc}",
                request_payload=prepared_job,
                process_failure={
                    "failure_stage": "worker_start" if worker is None else "worker_communication",
                    "failure_kind": "process_start" if worker is None else "process_io",
                    "message": str(exc),
                },
            )

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

    def _submit_native_job(
        self,
        job: dict,
        *,
        startupinfo=None,
        task: ArchiveTask | None = None,
        on_complete=None,
    ) -> Future:
        """Submit one prepared job to the single native worker process."""
        prepared_job = dict(job)
        job_id = str(prepared_job.get("job_id") or "")
        if not job_id:
            raise ValueError("native job_id is required")
        future = Future()

        def complete(result: subprocess.CompletedProcess) -> None:
            if not future.done():
                future.set_result(result)

        worker = None
        try:
            worker = self._worker_holder_or_create().get_or_start(startupinfo)
            prepared_job["worker_epoch"] = worker.worker_epoch
            stdout_lines: list[str] = []
            stderr_lines: list[str] = []
            progress_events: list[dict[str, Any]] = []
            pending_result: subprocess.CompletedProcess | None = None
            pending_result_payload: dict[str, Any] | None = None
            backpressure_retries = 0
            max_backpressure_retries = max(
                1,
                int(self.process_config.get("backpressure_retries", 120) or 120),
            )
            payload = json.dumps(prepared_job, ensure_ascii=False, separators=(",", ":"))

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
                                    on_timeout(f"native worker retry failed: {exc}")

                            delay = min(1.0, 0.05 * backpressure_retries)
                            if self._event_loop is None:
                                on_timeout("native worker backpressure requires an event loop")
                            else:
                                self._event_loop.call_soon_threadsafe(
                                    self._event_loop.call_later,
                                    delay,
                                    retry_submission,
                                )
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
                        [worker.worker_path],
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
                failure_kind = (
                    "worker_lost"
                    if "exited before job completion" in message or not worker.is_alive()
                    else "timeout"
                )
                complete(self._completed_process(
                    [worker.worker_path],
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

            worker.submit_async(payload, job_id, on_line=on_line, on_timeout=on_timeout)
        except Exception as exc:
            process_failure = {
                "failure_stage": "worker_start" if worker is None else "worker_communication",
                "failure_kind": "process_start" if worker is None else "process_io",
                "message": str(exc),
            }
            complete(self._completed_process(
                [self.worker_path or "sunpack_sevenzip_worker.exe"],
                -100,
                "",
                f"native worker communication failed: {exc}",
                request_payload=prepared_job,
                process_failure=process_failure,
            ))
        if on_complete is not None:
            def notify(done: Future) -> None:
                try:
                    on_complete(job_id, done.result())
                except Exception:
                    pass

            future.add_done_callback(notify)
        return future

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
            "file_id": str(getattr(task, "key", "") or archive_path),
            "stage": "extract",
            "seven_zip_dll_path": self._seven_zip_dll_path(),
            "archive_path": archive_path,
            "part_paths": list(part_paths or [archive_path]),
            "output_dir": out_dir,
            "password": password or "",
        }
        self._apply_native_job_budget(job)
        self._apply_native_admission_hints(job, task)
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

    @staticmethod
    def _json_line(line: str) -> dict:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _drain_stderr(worker: _NativeWorkerProcess, stderr_lines: list[str]) -> None:
        while True:
            try:
                line = worker.stderr_queue.get_nowait()
            except queue.Empty:
                return
            if line is not None:
                stderr_lines.append(line)

    def _worker_path(self) -> str:
        if self.worker_path is None:
            self.worker_path = get_sevenzip_bridge_worker_path()
        return self.worker_path

    def _worker_holder_or_create(self) -> _NativeWorkerHolder:
        with self._worker_holder_lock:
            if self._worker_holder is None:
                self._worker_holder = _NativeWorkerHolder(self._worker_path, self.process_config)
            return self._worker_holder

    def _async_worker_holder_or_create(self) -> _AsyncNativeWorkerHolder:
        if self._async_worker_holder is None:
            self._async_worker_holder = _AsyncNativeWorkerHolder(self._worker_path, self.process_config)
        return self._async_worker_holder

    async def aclose(self) -> None:
        if self._owns_async_worker_holder and self._async_worker_holder is not None:
            holder = self._async_worker_holder
            self._async_worker_holder = None
            await holder.close()
        self.close()

    def close(self) -> None:
        if not self._owns_worker_holder:
            return
        with self._worker_holder_lock:
            holder = self._worker_holder
            self._worker_holder = None
        if holder is not None:
            holder.close()

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
        configured = self.process_config.get("job_buffer_budget_bytes")
        if configured is None:
            return
        try:
            budget = int(configured)
        except (TypeError, ValueError):
            return
        if budget > 0:
            job["job_buffer_budget_bytes"] = budget

    def _apply_native_admission_hints(self, job: dict, task: ArchiveTask) -> None:
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
            memory_weight = max(1, min(8, int(tokens.get("memory", 1) or 1)))
        except (TypeError, ValueError):
            memory_weight = 1
        try:
            dictionary_bytes = max(0, int(analysis.get("largest_dictionary_size", 0) or 0))
        except (TypeError, ValueError):
            dictionary_bytes = 0
        native_memory = max(64 << 20, memory_weight * (32 << 20), dictionary_bytes + (32 << 20))
        job["native_cpu_weight"] = cpu_weight
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

    def emit_semantic_event(self, task: ArchiveTask, event: str, **payload: Any) -> None:
        """Publish a pipeline-owned event through the ordered progress sink."""

        self._emit_progress(task, {"type": "semantic", "event": str(event), **payload})

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
