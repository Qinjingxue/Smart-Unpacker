from dataclasses import dataclass

from packrelic.contracts.tasks import ArchiveTask
from packrelic.extraction.result import ExtractionResult


@dataclass(frozen=True)
class PreflightResult:
    task: ArchiveTask
    skip_result: ExtractionResult | None = None


class PreExtractInspector:
    def __init__(self, password_resolver, rename_scheduler):
        self.password_resolver = password_resolver
        self.rename_scheduler = rename_scheduler

    def inspect(self, task: ArchiveTask, output_dir: str) -> PreflightResult:
        return PreflightResult(task=task)

    def _skip(self, task: ArchiveTask, output_dir: str, all_parts: list[str], error: str) -> PreflightResult:
        return PreflightResult(
            task=task,
            skip_result=ExtractionResult(
                success=False,
                archive=task.main_path,
                out_dir=output_dir,
                all_parts=list(all_parts or task.all_parts or []),
                error=error,
            ),
        )
