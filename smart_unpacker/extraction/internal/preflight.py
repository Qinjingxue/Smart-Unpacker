from dataclasses import dataclass

from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.internal.native_password_tester import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_UNSUPPORTED,
    cached_analyze_archive_resources,
    cached_check_archive_health,
)
from smart_unpacker.extraction.result import ExtractionResult


@dataclass(frozen=True)
class PreflightResult:
    task: ArchiveTask
    skip_result: ExtractionResult | None = None


class PreExtractInspector:
    def __init__(self, password_resolver, split_stager):
        self.password_resolver = password_resolver
        self.split_stager = split_stager

    def inspect(self, task: ArchiveTask, output_dir: str) -> PreflightResult:
        staged = self.split_stager.stage(task.main_path, list(task.all_parts or [task.main_path]))
        try:
            health = cached_check_archive_health(staged.archive)
            self._record_health(task, health)
            is_split_task = bool(task.split_info.is_split or len(task.all_parts or []) > 1)

            if health.is_missing_volume:
                return self._skip(task, output_dir, staged.cleanup_parts, "分卷缺失或不完整")
            if health.is_broken:
                return self._skip(task, output_dir, staged.cleanup_parts, "压缩包损坏")

            password = ""
            if (health.is_encrypted or health.is_wrong_password) and not is_split_task:
                if not self.password_resolver.password_manager.passwords:
                    return self._skip(task, output_dir, staged.cleanup_parts, "密码错误或未知密码")
                resolution = self.password_resolver.resolve(staged.archive, task.fact_bag)
                if resolution.password is None:
                    return self._skip(task, output_dir, staged.cleanup_parts, "密码错误或未知密码")
                password = resolution.password or ""
                task.fact_bag.set("resource.password_resolved", True)
                task.fact_bag.set("resource.password_required", True)
            else:
                task.fact_bag.set("resource.password_required", False)

            if health.status not in {STATUS_BACKEND_UNAVAILABLE, STATUS_UNSUPPORTED} and not is_split_task:
                analysis = cached_analyze_archive_resources(staged.archive, password=password)
                self._record_analysis(task, analysis)
                task.fact_bag.set("resource.token_cost", self._estimate_token_cost(analysis))
            else:
                task.fact_bag.set("resource.token_cost", 1)
        finally:
            self.split_stager.cleanup(staged)

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

    def _estimate_token_cost(self, analysis) -> int:
        if not analysis.ok:
            return 1

        method = (analysis.dominant_method or "").lower()
        unpacked_mb = max(0, analysis.total_unpacked_size) / (1024 * 1024)
        file_count = max(0, analysis.file_count)
        dictionary_mb = max(0, analysis.largest_dictionary_size) / (1024 * 1024)

        cost = 1
        if any(token in method for token in ("lzma", "ppmd", "bzip2", "deflate64")):
            cost += 2
        elif "deflate" in method:
            cost += 1

        if analysis.solid:
            cost += 1
        if dictionary_mb >= 64:
            cost += 1
        if unpacked_mb >= 1024:
            cost += 1
        if file_count >= 10_000:
            cost += 1

        return max(1, min(cost, 6))
