import json
import os
import queue
import subprocess
import threading
import time
from typing import Any

import psutil

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.internal.sevenzip.worker_diagnostics import attach_worker_diagnostics
from smart_unpacker.support.resources import get_7z_dll_path, get_sevenzip_worker_path


class _PersistentWorker:
    def __init__(self, worker_path: str, startupinfo):
        self.worker_path = worker_path
        self.startupinfo = startupinfo
        self.process: subprocess.Popen | None = None
        self.stdout_queue: queue.Queue[str | None] = queue.Queue()
        self.stderr_queue: queue.Queue[str | None] = queue.Queue()
        self._start()

    def _start(self) -> None:
        self.process = subprocess.Popen(
            [self.worker_path, "--persistent"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            startupinfo=self.startupinfo,
        )
        threading.Thread(target=self._pump, args=(self.process.stdout, self.stdout_queue), daemon=True).start()
        threading.Thread(target=self._pump, args=(self.process.stderr, self.stderr_queue), daemon=True).start()

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
        self.process.stdin.write(payload + "\n")
        self.process.stdin.flush()

    def close(self) -> None:
        if self.process is None:
            return
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


class _PersistentWorkerPool:
    def __init__(self, worker_path_callback, process_config: dict):
        self.worker_path_callback = worker_path_callback
        self.process_config = process_config
        self.max_workers = self._max_workers(process_config)
        self._condition = threading.Condition()
        self._idle: list[_PersistentWorker] = []
        self._total = 0
        self._closed = False

    @staticmethod
    def _max_workers(process_config: dict) -> int:
        configured = process_config.get("persistent_worker_count")
        if configured is None:
            configured = process_config.get("worker_pool_size")
        if configured is None:
            configured = min(4, max(1, os.cpu_count() or 1))
        return max(1, int(configured))

    def acquire(self, startupinfo) -> _PersistentWorker:
        with self._condition:
            while True:
                if self._closed:
                    raise RuntimeError("sevenzip_worker pool is closed")
                while self._idle:
                    worker = self._idle.pop()
                    if worker.is_alive():
                        return worker
                    self._total = max(0, self._total - 1)
                if self._total < self.max_workers:
                    worker = _PersistentWorker(self.worker_path_callback(), startupinfo)
                    self._total += 1
                    return worker
                self._condition.wait()

    def release(self, worker: _PersistentWorker, *, reusable: bool) -> None:
        with self._condition:
            if reusable and not self._closed and worker.is_alive():
                self._idle.append(worker)
            else:
                worker.close()
                self._total = max(0, self._total - 1)
            self._condition.notify()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            workers = list(self._idle)
            self._idle.clear()
            self._total = 0
            self._condition.notify_all()
        for worker in workers:
            worker.close()


class SevenZipRunner:
    def __init__(self, process_config: dict):
        self.process_config = process_config
        self.worker_path = None
        self.seven_zip_dll_path = None
        self._worker_pool: _PersistentWorkerPool | None = None
        self._worker_pool_lock = threading.Lock()

    def run_extract(
        self,
        *,
        archive_path: str,
        part_paths: list[str],
        out_dir: str,
        password: str | None,
        selected_codepage: str | None,
        startupinfo,
        runtime_scheduler: Any,
        task: ArchiveTask,
    ) -> subprocess.CompletedProcess:
        try:
            job = self._build_job(
                archive_path=archive_path,
                part_paths=part_paths,
                out_dir=out_dir,
                password=password,
                selected_codepage=selected_codepage,
                task=task,
            )
        except (OSError, FileNotFoundError) as exc:
            return self._completed_process(
                ["sevenzip_worker.exe"],
                -100,
                "",
                f"sevenzip_worker setup failed: {exc}",
                process_failure={
                    "failure_stage": "worker_setup",
                    "failure_kind": "process_start",
                    "message": str(exc),
                },
            )
        return self._run_worker(job, startupinfo=startupinfo, runtime_scheduler=runtime_scheduler, task=task)

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
        job = {
            "job_id": str(getattr(task, "key", "") or archive_path),
            "seven_zip_dll_path": self._seven_zip_dll_path(),
            "archive_path": archive_path,
            "part_paths": [archive_path],
            "output_dir": out_dir,
            "password": password,
        }
        return self._run_worker(job, startupinfo=startupinfo, runtime_scheduler=runtime_scheduler, task=task)

    def _build_job(
        self,
        *,
        archive_path: str,
        part_paths: list[str],
        out_dir: str,
        password: str | None,
        selected_codepage: str | None,
        task: ArchiveTask,
    ) -> dict:
        job = {
            "job_id": str(getattr(task, "key", "") or archive_path),
            "seven_zip_dll_path": self._seven_zip_dll_path(),
            "archive_path": archive_path,
            "part_paths": list(part_paths or [archive_path]),
            "output_dir": out_dir,
            "password": password or "",
        }
        if selected_codepage:
            job["codepage"] = selected_codepage

        archive_state = self._archive_state(task)
        if archive_state:
            job["archive_state"] = archive_state
            source = archive_state.get("source") if isinstance(archive_state.get("source"), dict) else {}
            if archive_state.get("format_hint") or source.get("format_hint"):
                job["format_hint"] = archive_state.get("format_hint") or source.get("format_hint")
        else:
            archive_input = self._archive_input(task, archive_path, part_paths)
            if archive_input:
                descriptor_payload = archive_input.to_dict()
                job["archive_input"] = descriptor_payload
                if descriptor_payload.get("format_hint"):
                    job["format_hint"] = descriptor_payload.get("format_hint")
        return job

    def _archive_state(self, task: ArchiveTask) -> dict | None:
        fact_bag = getattr(task, "fact_bag", None)
        raw = fact_bag.get("archive.state") if fact_bag is not None and hasattr(fact_bag, "get") else None
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
            raw = task.fact_bag.get("archive.input") if getattr(task, "fact_bag", None) is not None else None
            if isinstance(raw, dict):
                return task.archive_input()
        fact_bag = getattr(task, "fact_bag", None)
        raw = fact_bag.get("archive.input") if fact_bag is not None and hasattr(fact_bag, "get") else None
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
    ) -> subprocess.CompletedProcess:
        return attach_worker_diagnostics(
            subprocess.CompletedProcess(args, returncode, stdout or "", stderr or ""),
            request_payload=request_payload,
            process_failure=process_failure,
        )

    def _run_worker(self, job: dict, startupinfo, runtime_scheduler: Any, task: ArchiveTask) -> subprocess.CompletedProcess:
        payload = json.dumps(job, ensure_ascii=False, separators=(",", ":"))
        if self._persistent_workers_enabled():
            return self._run_persistent_worker(payload, startupinfo=startupinfo, runtime_scheduler=runtime_scheduler, task=task, job=job)
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
                )
                return attach_worker_diagnostics(completed, request_payload=job)
            except (OSError, FileNotFoundError) as exc:
                return self._completed_process(
                    [self.worker_path or "sevenzip_worker.exe"],
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
            )
        except (OSError, FileNotFoundError) as exc:
            return self._completed_process(
                [self.worker_path or "sevenzip_worker.exe"],
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
            [self.worker_path or "sevenzip_worker.exe"],
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
    ) -> subprocess.CompletedProcess:
        try:
            worker = self._pool().acquire(startupinfo)
        except (OSError, FileNotFoundError, RuntimeError) as exc:
            return self._completed_process(
                [self.worker_path or "sevenzip_worker.exe"],
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
        try:
            worker.send(payload)
            stdout, stderr, returncode, reusable = self._read_persistent_worker_result(worker, runtime_scheduler, task)
            return self._completed_process(
                [worker.worker_path, "--persistent"],
                returncode,
                stdout,
                stderr,
                request_payload=job,
            )
        except Exception as exc:
            worker.close()
            return self._completed_process(
                [self.worker_path or "sevenzip_worker.exe"],
                -100,
                "",
                f"sevenzip_worker communication failed: {exc}",
                request_payload=job,
                process_failure={
                    "failure_stage": "worker_communication",
                    "failure_kind": "process_io",
                    "message": str(exc),
                },
            )
        finally:
            self._pool().release(worker, reusable=reusable)

    def _read_persistent_worker_result(
        self,
        worker: _PersistentWorker,
        runtime_scheduler: Any,
        task: ArchiveTask,
    ) -> tuple[str, str, int, bool]:
        interval = max(0.1, float(self.process_config.get("process_sample_interval_ms", 500) or 500) / 1000.0)
        max_task_seconds = max(0.0, float(self.process_config.get("max_extract_task_seconds", 0) or 0))
        no_progress_timeout = max(0.0, float(self.process_config.get("process_no_progress_timeout_seconds", 0) or 0))
        profile_key = self._task_profile_key(task)
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        started_at = time.monotonic()
        last_progress_at = started_at
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
                self._drain_stdout(worker, stdout_lines)
                self._drain_stderr(worker, stderr_lines)
                return "".join(stdout_lines), "".join(stderr_lines), worker.process.returncode or 1, False
            try:
                line = worker.stdout_queue.get(timeout=interval)
            except queue.Empty:
                now = time.monotonic()
                if max_task_seconds and now - started_at > max_task_seconds:
                    worker.close()
                    return "".join(stdout_lines), "\n".join([*stderr_lines, "sevenzip_worker timed out"]).strip(), -101, False
                if self._record_persistent_progress(ps_process, runtime_scheduler, profile_key, last_io_bytes):
                    try:
                        io_counters = ps_process.io_counters() if ps_process is not None else None
                        last_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes) if io_counters is not None else last_io_bytes
                    except Exception:
                        pass
                    last_progress_at = now
                if no_progress_timeout and now - last_progress_at > no_progress_timeout:
                    worker.close()
                    return "".join(stdout_lines), "\n".join([*stderr_lines, "sevenzip_worker made no observable progress"]).strip(), -102, False
                continue
            if line is None:
                code = worker.process.returncode if worker.process is not None else 1
                return "".join(stdout_lines), "".join(stderr_lines), code or 1, False
            stdout_lines.append(line)
            last_progress_at = time.monotonic()
            payload = self._json_line(line)
            if payload and payload.get("type") == "result":
                returncode = 0 if payload.get("status") == "ok" else 1
                self._drain_stderr(worker, stderr_lines)
                return "".join(stdout_lines), "".join(stderr_lines), returncode, True

    @staticmethod
    def _json_line(line: str) -> dict:
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _drain_stdout(worker: _PersistentWorker, stdout_lines: list[str]) -> None:
        while True:
            try:
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
            if runtime_scheduler is not None:
                runtime_scheduler.record_process_sample(
                    cpu_percent=cpu_percent,
                    memory_bytes=memory_bytes,
                    io_bytes=io_delta,
                    profile_key=profile_key,
                )
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
                    if runtime_scheduler is not None:
                        runtime_scheduler.record_process_sample(
                            cpu_percent=cpu_percent,
                            memory_bytes=memory_bytes,
                            io_bytes=io_delta,
                            profile_key=profile_key,
                        )
                    if no_progress_timeout and now - last_progress_at > no_progress_timeout:
                        return self.terminate_observed_process(process, -102, "sevenzip_worker made no observable progress")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    ps_process = None
                except Exception:
                    continue

    def _worker_path(self) -> str:
        if self.worker_path is None:
            self.worker_path = get_sevenzip_worker_path()
        return self.worker_path

    def close(self) -> None:
        with self._worker_pool_lock:
            pool = self._worker_pool
            self._worker_pool = None
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
                    if runtime_scheduler is not None:
                        runtime_scheduler.record_process_sample(
                            cpu_percent=cpu_percent,
                            memory_bytes=memory_bytes,
                            io_bytes=io_delta,
                            profile_key=profile_key,
                        )
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

    def _task_profile_key(self, task: ArchiveTask) -> str:
        fact_bag = getattr(task, "fact_bag", None)
        if fact_bag is not None and hasattr(fact_bag, "get"):
            profile_key = fact_bag.get("resource.profile_key")
            if profile_key:
                return str(profile_key)
        return "unknown"
