from dataclasses import dataclass

from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.support.sevenzip_native import (
    cached_check_archive_health,
    cached_test_archive,
)
from smart_unpacker.extraction.internal.workflow.errors import has_archive_damage_signals, has_definite_wrong_password
from smart_unpacker.extraction.result import ExtractionResult


@dataclass(frozen=True)
class PreflightResult:
    task: ArchiveTask
    skip_result: ExtractionResult | None = None


class PreExtractInspector:
    def __init__(self, password_resolver, rename_scheduler):
        self.password_resolver = password_resolver
        self.rename_scheduler = rename_scheduler

    def inspect(self, task: ArchiveTask, output_dir: str) -> PreflightResult:
        staged = self.rename_scheduler.normalize_archive_paths(task.main_path, list(task.all_parts or [task.main_path]))
        try:
            health = cached_check_archive_health(staged.archive, part_paths=staged.run_parts)
            self._record_health(task, health)

            if health.is_missing_volume:
                return self._skip(task, output_dir, staged.cleanup_parts, "分卷缺失或不完整")
            if health.is_broken:
                return self._skip(task, output_dir, staged.cleanup_parts, "压缩包损坏")

            password = ""
            if health.is_encrypted or health.is_wrong_password:
                if not self.password_resolver.password_tester.passwords:
                    if (health.archive_type or "").lower() != "pe":
                        structural_test = cached_test_archive(
                            staged.archive,
                            part_paths=staged.run_parts,
                        )
                        if has_archive_damage_signals(structural_test.message):
                            return self._skip(task, output_dir, staged.cleanup_parts, "压缩包损坏")
                    return self._skip(task, output_dir, staged.cleanup_parts, "密码错误或未知密码")
                resolution = self._resolve_password(task, staged.archive, staged.run_parts)
                if resolution.password is None:
                    error_text = resolution.error_text or ""
                    if has_archive_damage_signals(error_text) and not has_definite_wrong_password(error_text):
                        return self._skip(task, output_dir, staged.cleanup_parts, "压缩包损坏")
                    return self._skip(task, output_dir, staged.cleanup_parts, "密码错误或未知密码")
                password = resolution.password or ""
                task.fact_bag.set("resource.password_resolved", True)
                task.fact_bag.set("resource.password_required", True)
            else:
                task.fact_bag.set("resource.password_required", False)

        finally:
            self.rename_scheduler.cleanup_normalized_split_group(staged)

        return PreflightResult(task=task)

    def _resolve_password(self, task: ArchiveTask, archive_path: str, part_paths: list[str]):
        try:
            return self.password_resolver.resolve(
                archive_path,
                task.fact_bag,
                part_paths=part_paths,
                archive_key=task.key,
            )
        except TypeError:
            return self.password_resolver.resolve(archive_path, task.fact_bag, part_paths=part_paths)

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

    def _record_health(self, task: ArchiveTask, health) -> None:
        task.fact_bag.set("resource.health", {
            "status": health.status,
            "is_archive": health.is_archive,
            "is_encrypted": health.is_encrypted,
            "is_broken": health.is_broken,
            "is_missing_volume": health.is_missing_volume,
            "is_wrong_password": health.is_wrong_password,
            "operation_result": health.operation_result,
            "archive_type": health.archive_type,
            "message": health.message,
        })
