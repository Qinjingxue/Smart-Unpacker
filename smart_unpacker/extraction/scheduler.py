import os
import shutil
import subprocess
from typing import Callable, Optional

from smart_unpacker.extraction.internal.concurrency import ConcurrencyScheduler, build_scheduler_profile_config, resolve_max_workers
from smart_unpacker.extraction.internal.executor import TaskExecutor
from smart_unpacker.extraction.internal.errors import classify_extract_error
from smart_unpacker.extraction.internal.metadata import ArchiveMetadataScanner
from smart_unpacker.extraction.internal.output_paths import default_output_dir_for_task
from smart_unpacker.extraction.internal.password_manager import PasswordManager
from smart_unpacker.extraction.internal.password_resolution import PasswordResolver
from smart_unpacker.extraction.internal.preflight import PreExtractInspector
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.contracts.tasks import ArchiveTask, SplitArchiveInfo
from smart_unpacker.rename.volume_normalizer import SplitVolumeNormalizer
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder
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
        self.password_manager = PasswordManager(
            cli_passwords=cli_passwords or [],
            builtin_passwords=builtin_passwords or [],
        )
        self.password_resolver = PasswordResolver(self.password_manager)
        self.metadata_scanner = ArchiveMetadataScanner()
        self.seven_z_path = get_7z_path()
        self.volume_normalizer = SplitVolumeNormalizer()
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
        return self.password_manager.recent_passwords

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
        inspector = PreExtractInspector(self.password_resolver, self.volume_normalizer)
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
            lambda task: (task, self.extract(task, output_dir_resolver(task))),
        )

    def extract(
        self,
        task: ArchiveTask,
        out_dir: str,
        split_info: Optional[SplitArchiveInfo] = None,
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

            staged = self.volume_normalizer.normalize(archive, all_parts, startupinfo=startupinfo)
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
                if self.password_manager.passwords:
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

                    run_result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        errors="replace",
                        startupinfo=startupinfo,
                        stdin=subprocess.DEVNULL,
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
                self.volume_normalizer.cleanup(staged)

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
