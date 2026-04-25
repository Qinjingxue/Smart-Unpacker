import os
import re
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
from smart_unpacker.extraction.internal.split_stager import SplitVolumeStager
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.contracts.tasks import ArchiveTask, SplitArchiveInfo
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
        self.split_stager = SplitVolumeStager(self.seven_z_path)
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

        initial_limit = self.scheduler_config.get("initial_concurrency_limit", 4)
        scheduler = ConcurrencyScheduler(
            self.scheduler_config,
            current_limit=initial_limit,
            max_workers=self.max_workers,
        )
        executor = TaskExecutor(scheduler, max_workers=self.max_workers)
        return executor.execute_all(
            tasks,
            lambda task: (task, self.extract(task, output_dir_resolver(task))),
        )

    def extract(
        self,
        task: ArchiveTask,
        out_dir: str,
        split_info: Optional[SplitArchiveInfo] = None,
    ) -> ExtractionResult:
        archive = task.main_path or task.fact_bag.get("file.path")
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

            staged = self.split_stager.stage(archive, all_parts, startupinfo=startupinfo)
            run_archive = staged.archive
            run_parts = staged.all_parts
            run_result = None
            test_result = None
            err = ""
            correct_pwd = None
            selected_codepage = None

            try:
                resolution = self.password_resolver.resolve(run_archive, task.fact_bag)
                correct_pwd = resolution.password
                test_result = resolution.test_result
                test_err = resolution.error_text
                if self.password_manager.passwords:
                    if correct_pwd is None and "wrong password" in test_err:
                        shutil.rmtree(out_dir, ignore_errors=True)
                        return self._failed(archive, out_dir, run_parts, "密码错误或未知密码")

                metadata_scan = self.metadata_scanner.scan(run_archive, password=correct_pwd)
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
                            all_parts=run_parts,
                            password_used=correct_pwd,
                            selected_codepage=selected_codepage,
                        )

                    err = f"{run_result.stdout}\n{run_result.stderr}".lower()
            finally:
                self.split_stager.cleanup(staged)

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
            entry = self._select_first_volume(all_parts)

        if not entry and self._should_scan_split_siblings(archive, split_info):
            sibling_parts = self._find_standard_split_siblings(archive)
            if sibling_parts:
                all_parts = self._dedupe_paths(all_parts + sibling_parts)
                entry = self._select_first_volume(all_parts)

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

    def _select_first_volume(self, paths: list[str]) -> str:
        if not paths:
            return ""

        for path in paths:
            parsed = self._parse_numbered_volume(os.path.normpath(path))
            if parsed and parsed["number"] == 1:
                return path

        lower_names = {os.path.basename(path).lower() for path in paths}
        for path in paths:
            if self._is_legacy_rar_head(path, lower_names):
                return path

        return ""

    def _should_scan_split_siblings(self, archive: str, split_info: SplitArchiveInfo) -> bool:
        if split_info.is_split or split_info.is_sfx_stub:
            return True
        parsed = self._parse_numbered_volume(os.path.normpath(archive))
        if parsed and parsed["number"] == 1:
            return True
        return os.path.splitext(archive)[1].lower() in {".exe", ".rar"}

    def _parse_numbered_volume(self, path: str):
        relations = getattr(self.split_stager, "relations", None)
        if relations is not None:
            parsed = relations.parse_numbered_volume(path)
            if parsed:
                return parsed

        match = re.search(r"^(?P<prefix>.+\.(?:7z|zip|rar))\.(?P<number>\d{3})$", path, re.IGNORECASE)
        if match:
            return {
                "prefix": match.group("prefix"),
                "number": int(match.group("number")),
                "style": "numeric_suffix",
                "width": 3,
            }

        match = re.search(r"^(?P<prefix>.+)\.part(?P<number>\d+)\.rar$", path, re.IGNORECASE)
        if match:
            return {
                "prefix": match.group("prefix"),
                "number": int(match.group("number")),
                "style": "rar_part",
                "width": len(match.group("number")),
            }

        match = re.search(r"^(?P<prefix>.+)\.(?P<number>\d{3})$", path, re.IGNORECASE)
        if match:
            return {
                "prefix": match.group("prefix"),
                "number": int(match.group("number")),
                "style": "plain_numeric_suffix",
                "width": 3,
            }

        return None

    def _find_standard_split_siblings(self, archive: str) -> list[str]:
        directory = os.path.dirname(archive) or "."
        base = os.path.splitext(os.path.basename(archive))[0]
        try:
            names = os.listdir(directory)
        except OSError:
            return []

        lower_names = {name.lower() for name in names}
        expected_heads = {
            f"{base}.7z.001".lower(),
            f"{base}.zip.001".lower(),
            f"{base}.rar.001".lower(),
            f"{base}.001".lower(),
            f"{base}.part1.rar".lower(),
            f"{base}.part01.rar".lower(),
            f"{base}.part001.rar".lower(),
        }
        legacy_rar_head = f"{base}.rar".lower()
        legacy_rar_present = legacy_rar_head in lower_names and any(
            f"{base}.r{number:02d}".lower() in lower_names for number in range(0, 100)
        )
        if legacy_rar_present:
            expected_heads.add(f"{base}.rar".lower())

        if not (expected_heads & lower_names):
            return []

        siblings = []
        for name in names:
            lower = name.lower()
            if self._is_standard_split_sibling(base.lower(), lower, legacy_rar_present):
                siblings.append(os.path.join(directory, name))

        return sorted(siblings, key=self._split_sort_key)

    def _is_standard_split_sibling(self, base: str, lower_name: str, legacy_rar_present: bool) -> bool:
        if re.match(rf"^{re.escape(base)}\.(7z|zip|rar)\.\d{{3}}$", lower_name):
            return True
        if re.match(rf"^{re.escape(base)}\.\d{{3}}$", lower_name):
            return True
        if re.match(rf"^{re.escape(base)}\.part\d+\.rar$", lower_name):
            return True
        if legacy_rar_present and lower_name == f"{base}.rar":
            return True
        if legacy_rar_present and re.match(rf"^{re.escape(base)}\.r\d{{2}}$", lower_name):
            return True
        return False

    def _split_sort_key(self, path: str) -> tuple[int, int, str]:
        parsed = self._parse_numbered_volume(os.path.normpath(path))
        if parsed:
            return (0, parsed["number"], path.lower())

        lower_name = os.path.basename(path).lower()
        match = re.search(r"\.r(\d{2})$", lower_name)
        if match:
            return (1, int(match.group(1)) + 2, path.lower())
        if lower_name.endswith(".rar"):
            return (1, 1, path.lower())
        return (2, 0, path.lower())

    def _is_legacy_rar_head(self, path: str, lower_names: set[str]) -> bool:
        lower_name = os.path.basename(path).lower()
        if not lower_name.endswith(".rar"):
            return False
        base = lower_name[:-4]
        return any(f"{base}.r{number:02d}" in lower_names for number in range(0, 100))

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
