import os

from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.scheduling.resource_model import build_resource_profile_key, estimate_resource_demand
from smart_unpacker.passwords import PasswordSession
from smart_unpacker.rename.scheduler import RenameScheduler
from smart_unpacker.support.sevenzip_native import (
    STATUS_BACKEND_UNAVAILABLE,
    STATUS_UNSUPPORTED,
    cached_analyze_archive_resources,
)


class ResourcePreflightInspector:
    def __init__(
        self,
        password_session: PasswordSession | None = None,
        rename_scheduler: RenameScheduler | None = None,
    ):
        self.password_session = password_session
        self.rename_scheduler = rename_scheduler or RenameScheduler()

    def inspect(self, task: ArchiveTask) -> ArchiveTask:
        health = task.fact_bag.get("resource.health") or {}
        if health.get("status") in {STATUS_BACKEND_UNAVAILABLE, STATUS_UNSUPPORTED}:
            return self._record_unknown(task)

        staged = self.rename_scheduler.normalize_archive_paths(task.main_path, list(task.all_parts or [task.main_path]))
        try:
            password = self._password_for(task)
            analysis = cached_analyze_archive_resources(staged.archive, password=password, part_paths=staged.run_parts)
            self._record_analysis(task, analysis)
            self.record_resource_demand(task, analysis)
        finally:
            self.rename_scheduler.cleanup_normalized_split_group(staged)
        return task

    def record_precise_analysis(self, task: ArchiveTask, analysis) -> ArchiveTask:
        self._record_analysis(task, analysis)
        self.record_resource_demand(task, analysis)
        return task

    def record_resource_demand(self, task: ArchiveTask, analysis) -> None:
        demand = estimate_resource_demand(analysis)
        task.fact_bag.set("resource.tokens", demand.as_dict())
        task.fact_bag.set("resource.token_cost", demand.scalar_cost)
        task.fact_bag.set("resource.profile_key", build_resource_profile_key(analysis))

    def record_estimated_single_task_profile(self, task: ArchiveTask) -> ArchiveTask:
        archive_size = 0
        for path in list(task.all_parts or [task.main_path]):
            try:
                archive_size += os.path.getsize(path)
            except OSError:
                pass

        archive_type = self._archive_type_for(task)
        analysis = {
            "status": 0,
            "is_archive": True,
            "is_encrypted": bool((task.fact_bag.get("resource.health") or {}).get("is_encrypted")),
            "is_broken": False,
            "solid": False,
            "item_count": 0,
            "file_count": 0,
            "dir_count": 0,
            "archive_size": archive_size,
            "total_unpacked_size": 0,
            "total_packed_size": archive_size,
            "largest_item_size": 0,
            "largest_dictionary_size": 0,
            "archive_type": archive_type,
            "dominant_method": "",
            "message": "estimated single-task resource profile",
        }
        task.fact_bag.set("resource.analysis", analysis)
        task.fact_bag.set("resource.tokens", self._estimated_tokens_for_size(archive_size))
        task.fact_bag.set("resource.token_cost", max(task.fact_bag.get("resource.tokens").values()))
        task.fact_bag.set("resource.profile_key", f"{archive_type or 'unknown'}|estimated|single")
        return task

    def _password_for(self, task: ArchiveTask) -> str:
        if self.password_session is None:
            return ""
        return self.password_session.get_resolved(task.key) or ""

    def _record_unknown(self, task: ArchiveTask) -> ArchiveTask:
        task.fact_bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
        task.fact_bag.set("resource.token_cost", 1)
        task.fact_bag.set("resource.profile_key", "unknown")
        return task

    def _archive_type_for(self, task: ArchiveTask) -> str:
        health = task.fact_bag.get("resource.health") or {}
        archive_type = str(health.get("archive_type") or "").strip().lower()
        if archive_type and archive_type != "pe":
            return archive_type
        detected_ext = str(task.fact_bag.get("file.detected_ext") or os.path.splitext(task.main_path)[1]).lower()
        return detected_ext.lstrip(".") or archive_type or "unknown"

    def _estimated_tokens_for_size(self, archive_size: int) -> dict[str, int]:
        archive_mb = max(0, int(archive_size or 0)) / (1024 * 1024)
        io = 1
        if archive_mb >= 4096:
            io = 4
        elif archive_mb >= 1024:
            io = 3
        elif archive_mb >= 256:
            io = 2
        return {"cpu": 1, "io": io, "memory": 1}

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
