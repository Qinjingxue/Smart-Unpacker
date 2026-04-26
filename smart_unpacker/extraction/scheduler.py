import os
import shutil
import subprocess
import inspect
from typing import Callable, Optional

import psutil

from smart_unpacker.extraction.internal.concurrency import ConcurrencyScheduler, build_scheduler_profile_config, resolve_max_workers
from smart_unpacker.extraction.internal.executor import TaskExecutor
from smart_unpacker.extraction.internal.errors import classify_extract_error
from smart_unpacker.extraction.internal.metadata import ArchiveMetadataScanner
from smart_unpacker.extraction.internal.output_paths import default_output_dir_for_task
from smart_unpacker.extraction.internal.password_manager import ArchivePasswordTester
from smart_unpacker.extraction.internal.password_resolution import PasswordResolver
from smart_unpacker.extraction.internal.preflight import PreExtractInspector
from smart_unpacker.extraction.internal.resource_model import task_profile_key
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.contracts.tasks import ArchiveTask, SplitArchiveInfo
from smart_unpacker.rename.scheduler import RenameScheduler
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder
from smart_unpacker.passwords import PasswordStore
from smart_unpacker.support.resources import get_7z_path


class ExtractionScheduler:
    def __init__(
        self,
        cli_passwords: list[str] | None = None,
        builtin_passwords: list[str] | None = None,
        ensure_space: Optional[Callable[[int], bool]] = None,
        max_retries: int = 3,
        scheduler_profile: str | None = "auto",
        max_workers: int | None = None,
    ):
        self.password_store = PasswordStore.from_sources(
            cli_passwords=cli_passwords or [],
            builtin_passwords=builtin_passwords or [],
        )
        self.password_tester = ArchivePasswordTester(password_store=self.password_store)
        self.password_resolver = PasswordResolver(self.password_tester)
        self.metadata_scanner = ArchiveMetadataScanner()
        self.seven_z_path = get_7z_path()
        self.rename_scheduler = RenameScheduler()
        self._relations = RelationsGroupBuilder()
        self.ensure_space = ensure_space or (lambda _required_gb: True)
        self.max_retries = max(1, max_retries)
        self.scheduler_config = build_scheduler_profile_config(scheduler_profile)
        self.max_workers = max(1, max_workers or resolve_max_workers())

    @staticmethod
    def scheduler_profile_config(profile: str | None) -> dict:
        return build_scheduler_profile_config(profile)

    @property
    def recent_passwords(self) -> list[str]:
        return self.password_store.recent_passwords

    def default_output_dir_for_task(self, task: ArchiveTask) -> str:
        return default_output_dir_for_task(task)

    def extract_tasks(self, tasks: list[ArchiveTask]) -> list[tuple[ArchiveTask, ExtractionResult]]:
        return self.extract_all(tasks, self.default_output_dir_for_task)

    def extract_all(
        self,
        tasks: list[ArchiveTask],
        output_dir_resolver: Callable[[ArchiveTask], str] | None = None,
    ) -> list[tuple[ArchiveTask, ExtractionResult]]:
        if not tasks:
            return []
        output_dir_resolver = output_dir_resolver or self.default_output_dir_for_task
        inspector = PreExtractInspector(self.password_resolver, self.rename_scheduler)
        ready_tasks: list[ArchiveTask] = []
        skipped_results: list[tuple[ArchiveTask, ExtractionResult]] = []
        for task in tasks:
            preflight = inspector.inspect(task, output_dir_resolver(task))
            if preflight.skip_result is not None:
                skipped_results.append((task, preflight.skip_result))
            else:
                ready_tasks.append(task)

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
            lambda task: (task, self._call_extract_for_executor(task, output_dir_resolver(task), scheduler)),
        )

    def _call_extract_for_executor(
        self,
        task: ArchiveTask,
        out_dir: str,
        scheduler: ConcurrencyScheduler,
    ) -> ExtractionResult:
        try:
            parameters = inspect.signature(self.extract).parameters
        except (TypeError, ValueError):
            parameters = {}
        if "runtime_scheduler" in parameters:
            return self.extract(task, out_dir, runtime_scheduler=scheduler)
        return self.extract(task, out_dir)

    def extract(
        self,
        task: ArchiveTask,
        out_dir: str,
        split_info: Optional[SplitArchiveInfo] = None,
        runtime_scheduler: ConcurrencyScheduler | None = None,
    ) -> ExtractionResult:
        archive = task.main_path
        split_info = split_info or task.split_info
        archive, all_parts, split_info = self._resolve_split_entry(
            archive,
            list(task.all_parts or [archive]),
            split_info,
        )
        is_split = split_info.is_split or len(all_parts) > 1

        print(f"\n[EXTRACT] 开始: {archive}")

        if not self.ensure_space(5):
            return self._failed(archive, out_dir, all_parts, "磁盘空间不足")

        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            return self._failed(archive, out_dir, all_parts, f"目录创建失败: {exc}")

        import sys
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        retry_count = 0
        while retry_count < self.max_retries:
            if not self.ensure_space(5):
                shutil.rmtree(out_dir, ignore_errors=True)
                return self._failed(archive, out_dir, all_parts, "磁盘空间不足")

            staged = self.rename_scheduler.normalize_archive_paths(archive, all_parts, startupinfo=startupinfo)
            run_archive = staged.archive
            run_parts = staged.run_parts if hasattr(staged, "run_parts") else staged.all_parts
            cleanup_parts = getattr(staged, "cleanup_parts", run_parts)
            run_result = None
            test_result = None
            err = ""
            correct_pwd = None
            selected_codepage = None

            try:
                resolution = self.password_resolver.resolve(run_archive, task.fact_bag, part_paths=run_parts)
                correct_pwd = resolution.password
                test_result = resolution.test_result
                test_err = resolution.error_text
                if self.password_store.has_candidates():
                    if correct_pwd is None and "wrong password" in test_err:
                        shutil.rmtree(out_dir, ignore_errors=True)
                        return self._failed(archive, out_dir, run_parts, "密码错误或未知密码")

                metadata_scan = self.metadata_scanner.scan(run_archive, password=correct_pwd, part_paths=run_parts)
                if metadata_scan and metadata_scan.selected_codepage:
                    selected_codepage = metadata_scan.selected_codepage
                    print(f"[META] 文件名编码修正: -mcp={selected_codepage}")

                if correct_pwd is None:
                    err = test_err
                else:
                    cmd = [self.seven_z_path, "x", run_archive, f"-o{out_dir}", "-y"]
                    if selected_codepage:
                        cmd.append(f"-mcp={selected_codepage}")
                    if correct_pwd:
                        cmd.append(f"-p{correct_pwd}")

                    run_result = self._run_extract_command(
                        cmd,
                        startupinfo=startupinfo,
                        runtime_scheduler=runtime_scheduler,
                        task=task,
                    )

                    if run_result.returncode == 0:
                        print(f"[EXTRACT] 成功: {archive}")
                        return ExtractionResult(
                            success=True,
                            archive=archive,
                            out_dir=out_dir,
                            all_parts=cleanup_parts,
                            password_used=correct_pwd,
                            selected_codepage=selected_codepage,
                        )

                    err = f"{run_result.stdout}\n{run_result.stderr}".lower()
            finally:
                self.rename_scheduler.cleanup_normalized_split_group(staged)

            if run_result and ("no space" in err or "write error" in err or run_result.returncode == 8):
                retry_count += 1
                if self.ensure_space(10):
                    continue

            error_msg = classify_extract_error(run_result or test_result, err, archive=archive, is_split_archive=is_split)
            print(f"[EXTRACT] 失败: {archive} (错误: {error_msg})")
            shutil.rmtree(out_dir, ignore_errors=True)
            return self._failed(archive, out_dir, run_parts, error_msg)

        shutil.rmtree(out_dir, ignore_errors=True)
        return self._failed(archive, out_dir, all_parts, "磁盘空间不足")

    def _failed(self, archive: str, out_dir: str, all_parts: list[str], error: str) -> ExtractionResult:
        return ExtractionResult(
            success=False,
            archive=archive,
            out_dir=out_dir,
            all_parts=list(all_parts or []),
            error=error,
        )

    def _run_extract_command(
        self,
        cmd: list[str],
        startupinfo,
        runtime_scheduler: ConcurrencyScheduler | None,
        task: ArchiveTask,
    ) -> subprocess.CompletedProcess:
        if runtime_scheduler is None:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                startupinfo=startupinfo,
                stdin=subprocess.DEVNULL,
            )

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            startupinfo=startupinfo,
            stdin=subprocess.DEVNULL,
        )
        stdout, stderr = self._communicate_observed_process(process, runtime_scheduler, task)
        return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)

    def _communicate_observed_process(
        self,
        process: subprocess.Popen,
        runtime_scheduler: ConcurrencyScheduler,
        task: ArchiveTask,
    ) -> tuple[str, str]:
        interval = max(0.1, float(self.scheduler_config.get("process_sample_interval_ms", 500) or 500) / 1000.0)
        profile_key = task_profile_key(task)
        ps_process = None
        last_io_bytes = 0
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
                if ps_process is None:
                    continue
                try:
                    cpu_percent = ps_process.cpu_percent(interval=None)
                    memory_bytes = ps_process.memory_info().rss
                    io_counters = ps_process.io_counters()
                    now_io_bytes = int(io_counters.read_bytes + io_counters.write_bytes)
                    io_delta = max(0, now_io_bytes - last_io_bytes)
                    last_io_bytes = now_io_bytes
                    runtime_scheduler.record_process_sample(
                        cpu_percent=cpu_percent,
                        memory_bytes=memory_bytes,
                        io_bytes=io_delta,
                        profile_key=profile_key,
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    ps_process = None
                except Exception:
                    continue

    def _resolve_split_entry(
        self,
        archive: str,
        all_parts: list[str],
        split_info: Optional[SplitArchiveInfo],
    ) -> tuple[str, list[str], SplitArchiveInfo]:
        split_info = split_info or SplitArchiveInfo()
        all_parts = self._dedupe_paths(list(all_parts or []) + list(split_info.parts or []) + [archive])
        entry = split_info.preferred_entry or ""

        if not entry:
            entry = self._relations.select_first_volume(all_parts)

        if not entry and self._relations.should_scan_split_siblings(
            archive,
            is_split=split_info.is_split,
            is_sfx_stub=split_info.is_sfx_stub,
        ):
            sibling_parts = self._relations.find_standard_split_siblings(archive)
            if sibling_parts:
                all_parts = self._dedupe_paths(all_parts + sibling_parts)
                entry = self._relations.select_first_volume(all_parts)

        if entry and os.path.normcase(os.path.normpath(entry)) != os.path.normcase(os.path.normpath(archive)):
            print(f"[SPLIT] 使用分卷入口: {entry}")
            split_info = SplitArchiveInfo(
                is_split=True,
                is_sfx_stub=split_info.is_sfx_stub or self._looks_like_sfx_stub(archive),
                parts=list(all_parts),
                preferred_entry=entry,
                source=split_info.source or "filename",
            )
            return entry, all_parts, split_info

        if len(all_parts) > 1 and not split_info.is_split:
            split_info = SplitArchiveInfo(
                is_split=True,
                is_sfx_stub=split_info.is_sfx_stub,
                parts=list(all_parts),
                preferred_entry=split_info.preferred_entry,
                source=split_info.source or "filename",
            )

        return archive, all_parts, split_info

    def _looks_like_sfx_stub(self, path: str) -> bool:
        return os.path.splitext(path)[1].lower() == ".exe"

    def _dedupe_paths(self, paths: list[str]) -> list[str]:
        deduped = []
        seen = set()
        for path in paths:
            if not path:
                continue
            key = os.path.normcase(os.path.normpath(path))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(path)
        return deduped
