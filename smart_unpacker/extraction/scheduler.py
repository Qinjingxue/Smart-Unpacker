import subprocess
import inspect
from typing import Callable, Optional

from smart_unpacker.extraction.internal.scheduling.concurrency import ConcurrencyScheduler, build_scheduler_profile_config, resolve_max_workers
from smart_unpacker.extraction.internal.scheduling.executor import TaskExecutor
from smart_unpacker.extraction.internal.sevenzip.metadata import ArchiveMetadataScanner
from smart_unpacker.extraction.internal.workflow.output_paths import default_output_dir_for_task
from smart_unpacker.extraction.internal.workflow.preflight import PreExtractInspector
from smart_unpacker.extraction.internal.workflow.retry_policy import ExtractRetryPolicy
from smart_unpacker.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from smart_unpacker.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
from smart_unpacker.extraction.internal.workflow.split_entry import SplitEntryResolver
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.contracts.tasks import ArchiveTask, SplitArchiveInfo
from smart_unpacker.rename.scheduler import RenameScheduler
from smart_unpacker.relations.internal.group_builder import RelationsGroupBuilder
from smart_unpacker.passwords import ArchivePasswordTester, PasswordResolver, PasswordSession, PasswordStore
from smart_unpacker.support.resources import get_7z_path


class ExtractionScheduler:
    def __init__(
        self,
        cli_passwords: list[str] | None = None,
        builtin_passwords: list[str] | None = None,
        ensure_space: Optional[Callable[[int], bool]] = None,
        max_retries: int = 3,
        scheduler_profile: str | None = "auto",
        scheduler_overrides: dict | None = None,
        max_workers: int | None = None,
    ):
        self.password_store = PasswordStore.from_sources(
            cli_passwords=cli_passwords or [],
            builtin_passwords=builtin_passwords or [],
        )
        self.password_session = PasswordSession()
        self.password_tester = ArchivePasswordTester(password_store=self.password_store)
        self.password_resolver = PasswordResolver(self.password_tester, self.password_session)
        self.metadata_scanner = ArchiveMetadataScanner()
        self.seven_z_path = get_7z_path()
        self.rename_scheduler = RenameScheduler()
        self._relations = RelationsGroupBuilder()
        self.split_entry_resolver = SplitEntryResolver(self._relations)
        self.ensure_space = ensure_space or (lambda _required_gb: True)
        self.max_retries = max(1, max_retries)
        self.scheduler_config = build_scheduler_profile_config(scheduler_profile)
        if scheduler_overrides:
            self.scheduler_config.update({
                key: value
                for key, value in scheduler_overrides.items()
                if key != "scheduler_profile" and value is not None
            })
        self.max_workers = max(1, max_workers or resolve_max_workers())
        self.retry_policy = ExtractRetryPolicy(self.max_retries)
        self.sevenzip_runner = SevenZipRunner(self.scheduler_config)

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
        return self._single_archive_extractor().extract(
            task,
            out_dir,
            split_info=split_info,
            runtime_scheduler=runtime_scheduler,
        )

    def _failed(self, archive: str, out_dir: str, all_parts: list[str], error: str) -> ExtractionResult:
        return ExtractionResult(
            success=False,
            archive=archive,
            out_dir=out_dir,
            all_parts=list(all_parts or []),
            error=error,
        )

    def _single_archive_extractor(self) -> SingleArchiveExtractor:
        return SingleArchiveExtractor(
            seven_z_path=self.seven_z_path,
            password_store=self.password_store,
            password_resolver=self.password_resolver,
            metadata_scanner=self.metadata_scanner,
            rename_scheduler=self.rename_scheduler,
            ensure_space=self.ensure_space,
            retry_policy=self.retry_policy,
            split_entry_resolver=self.split_entry_resolver,
            sevenzip_runner=self.sevenzip_runner,
        )

    def _run_extract_command(
        self,
        cmd: list[str],
        startupinfo,
        runtime_scheduler: ConcurrencyScheduler | None,
        task: ArchiveTask,
    ) -> subprocess.CompletedProcess:
        return self.sevenzip_runner.run_extract_command(cmd, startupinfo, runtime_scheduler, task)

    def _communicate_observed_process(
        self,
        process: subprocess.Popen,
        runtime_scheduler: ConcurrencyScheduler,
        task: ArchiveTask,
    ) -> tuple[str, str]:
        return self.sevenzip_runner.communicate_observed_process(process, runtime_scheduler, task)

    def _terminate_observed_process(
        self,
        process: subprocess.Popen,
        returncode: int,
        message: str,
    ) -> tuple[str, str]:
        return self.sevenzip_runner.terminate_observed_process(process, returncode, message)

    def _resolve_split_entry(
        self,
        archive: str,
        all_parts: list[str],
        split_info: Optional[SplitArchiveInfo],
    ) -> tuple[str, list[str], SplitArchiveInfo]:
        return self.split_entry_resolver.resolve(archive, all_parts, split_info)

    def _looks_like_sfx_stub(self, path: str) -> bool:
        return self.split_entry_resolver._looks_like_sfx_stub(path)

    def _dedupe_paths(self, paths: list[str]) -> list[str]:
        return self.split_entry_resolver._dedupe_paths(paths)
