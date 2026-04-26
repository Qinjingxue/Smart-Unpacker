from dataclasses import dataclass

from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.internal.native_password_tester import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_UNSUPPORTED,
    cached_analyze_archive_resources,
    cached_check_archive_health,
    get_native_password_tester,
)
from smart_unpacker.extraction.internal.errors import has_archive_damage_signals, has_definite_wrong_password
from smart_unpacker.extraction.internal.resource_model import estimate_resource_demand
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
                        structural_test = get_native_password_tester().test_archive(
                            staged.archive,
                            part_paths=staged.run_parts,
                        )
                        if has_archive_damage_signals(structural_test.message):
                            return self._skip(task, output_dir, staged.cleanup_parts, "压缩包损坏")
                    return self._skip(task, output_dir, staged.cleanup_parts, "密码错误或未知密码")
                resolution = self.password_resolver.resolve(staged.archive, task.fact_bag, part_paths=staged.run_parts)
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

            if health.status not in {STATUS_BACKEND_UNAVAILABLE, STATUS_UNSUPPORTED}:
                analysis = cached_analyze_archive_resources(staged.archive, password=password, part_paths=staged.run_parts)
                self._record_analysis(task, analysis)
                demand = estimate_resource_demand(analysis)
                task.fact_bag.set("resource.tokens", demand.as_dict())
                task.fact_bag.set("resource.token_cost", demand.scalar_cost)
            else:
                task.fact_bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
                task.fact_bag.set("resource.token_cost", 1)
        finally:
            self.rename_scheduler.cleanup_normalized_split_group(staged)

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

    def _record_analysis(self, task: ArchiveTask, analysis) -> None:
        task.fact_bag.set("resource.analysis", {
            "status": analysis.status,
            "is_archive": analysis.is_archive,
            "is_encrypted": analysis.is_encrypted,
            "is_broken": analysis.is_broken,
            "solid": analysis.solid,
            "item_count": analysis.item_count,
            "file_count": analysis.file_count,
            "dir_count": analysis.dir_count,
            "archive_size": analysis.archive_size,
            "total_unpacked_size": analysis.total_unpacked_size,
            "total_packed_size": analysis.total_packed_size,
            "largest_item_size": analysis.largest_item_size,
            "largest_dictionary_size": analysis.largest_dictionary_size,
            "archive_type": analysis.archive_type,
            "dominant_method": analysis.dominant_method,
            "message": analysis.message,
        })
