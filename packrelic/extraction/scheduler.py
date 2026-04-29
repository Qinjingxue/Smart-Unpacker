from typing import Any, Callable, Optional

from packrelic.extraction.internal.sevenzip.metadata import ArchiveMetadataScanner
from packrelic.extraction.internal.workflow.output_paths import default_output_dir_for_task
from packrelic.extraction.internal.workflow.preflight import PreExtractInspector
from packrelic.extraction.internal.workflow.retry_policy import ExtractRetryPolicy
from packrelic.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner
from packrelic.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
from packrelic.extraction.internal.workflow.split_entry import SplitEntryResolver
from packrelic.extraction.result import ExtractionResult
from packrelic.contracts.tasks import ArchiveTask, SplitArchiveInfo
from packrelic.rename.scheduler import RenameScheduler
from packrelic.relations import RelationsScheduler
from packrelic.passwords import ArchivePasswordTester, PasswordResolver, PasswordSession, PasswordStore


class ExtractionScheduler:
    def __init__(
        self,
        cli_passwords: list[str] | None = None,
        builtin_passwords: list[str] | None = None,
        ensure_space: Optional[Callable[[int], bool]] = None,
        max_retries: int = 3,
        process_config: dict | None = None,
        output_config: dict | None = None,
    ):
        self.password_store = PasswordStore.from_sources(
            cli_passwords=cli_passwords or [],
            builtin_passwords=builtin_passwords or [],
        )
        self.password_session = PasswordSession()
        self.password_tester = ArchivePasswordTester(password_store=self.password_store)
        self.password_resolver = PasswordResolver(self.password_tester, self.password_session)
        self.metadata_scanner = ArchiveMetadataScanner()
        self.seven_z_path = ""
        self.rename_scheduler = RenameScheduler()
        self._relations = RelationsScheduler()
        self.split_entry_resolver = SplitEntryResolver(self._relations)
        self.ensure_space = ensure_space or (lambda _required_gb: True)
        self.max_retries = max(1, max_retries)
        self.output_config = output_config if isinstance(output_config, dict) else None
        self.process_config = {
            key: value
            for key, value in (process_config or {}).items()
            if key != "scheduler_profile" and value is not None
        }
        self.retry_policy = ExtractRetryPolicy(self.max_retries)
        self.sevenzip_runner = SevenZipRunner(self.process_config)

    @property
    def recent_passwords(self) -> list[str]:
        return self.password_store.recent_passwords

    def default_output_dir_for_task(self, task: ArchiveTask) -> str:
        return default_output_dir_for_task(task, self.output_config)

    def inspect(self, task: ArchiveTask, out_dir: str):
        return PreExtractInspector(self.password_resolver, self.rename_scheduler).inspect(task, out_dir)

    def extract(
        self,
        task: ArchiveTask,
        out_dir: str,
        split_info: Optional[SplitArchiveInfo] = None,
        runtime_scheduler: Any = None,
    ) -> ExtractionResult:
        return self._single_archive_extractor().extract(
            task,
            out_dir,
            split_info=split_info,
            runtime_scheduler=runtime_scheduler,
        )

    def close(self) -> None:
        self.sevenzip_runner.close()

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
            best_effort=True,
        )
