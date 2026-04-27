import json
import subprocess
import time
from typing import Any

import psutil

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.support.resources import get_7z_dll_path, get_sevenzip_worker_path


class SevenZipRunner:
    def __init__(self, process_config: dict):
        self.process_config = process_config
        self.worker_path = None
        self.seven_zip_dll_path = None

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
            return subprocess.CompletedProcess(["sevenzip_worker.exe"], -100, "", f"sevenzip_worker setup failed: {exc}")
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

        archive_input = self._archive_input(task, archive_path, part_paths)
        if archive_input:
            descriptor_payload = archive_input.to_dict()
            job["archive_input"] = descriptor_payload
            if descriptor_payload.get("format_hint"):
                job["format_hint"] = descriptor_payload.get("format_hint")
        return job

    def _archive_input(self, task: ArchiveTask, archive_path: str, part_paths: list[str]) -> ArchiveInputDescriptor | None:
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
            return ArchiveInputDescriptor.from_legacy(raw, archive_path=archive_path, part_paths=part_paths)
        if kind == "concat_ranges":
            return ArchiveInputDescriptor.from_legacy(raw, archive_path=archive_path, part_paths=part_paths)
        return ArchiveInputDescriptor.from_parts(
            archive_path=archive_path,
            part_paths=list(part_paths or [archive_path]),
            format_hint=str(raw.get("format_hint") or raw.get("format") or ""),
        )

    def _run_worker(self, job: dict, startupinfo, runtime_scheduler: Any, task: ArchiveTask) -> subprocess.CompletedProcess:
        payload = json.dumps(job, ensure_ascii=False, separators=(",", ":"))
        if runtime_scheduler is None:
            try:
                return subprocess.run(
                    [self._worker_path()],
                    input=payload,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    startupinfo=startupinfo,
                )
            except (OSError, FileNotFoundError) as exc:
                return subprocess.CompletedProcess([self.worker_path or "sevenzip_worker.exe"], -100, "", f"sevenzip_worker failed to start: {exc}")
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
            return subprocess.CompletedProcess([self.worker_path or "sevenzip_worker.exe"], -100, "", f"sevenzip_worker failed to start: {exc}")

        stdout, stderr = self._communicate_observed_worker(process, payload, runtime_scheduler, task)
        return subprocess.CompletedProcess([self.worker_path or "sevenzip_worker.exe"], process.returncode, stdout, stderr)

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
