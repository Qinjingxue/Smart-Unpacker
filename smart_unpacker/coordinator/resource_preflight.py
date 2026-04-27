import os
from types import SimpleNamespace

from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.scheduling.resource_model import build_resource_profile_key, estimate_resource_demand
from smart_unpacker.passwords import PasswordSession
from smart_unpacker.rename.scheduler import RenameScheduler
from smart_unpacker.support.sevenzip_native import cached_check_archive_health


class ResourcePreflightInspector:
    def __init__(
        self,
        password_session: PasswordSession | None = None,
        rename_scheduler: RenameScheduler | None = None,
        precise_resource_min_size_mb: int = 256,
    ):
        self.password_session = password_session
        self.rename_scheduler = rename_scheduler or RenameScheduler()
        self.precise_resource_min_size_bytes = max(0, int(precise_resource_min_size_mb or 0)) * 1024 * 1024

    def inspect(self, task: ArchiveTask) -> ArchiveTask:
        existing_analysis = task.fact_bag.get("resource.analysis")
        if isinstance(existing_analysis, dict):
            analysis = SimpleNamespace(ok=not bool(existing_analysis.get("is_broken")), **existing_analysis)
            self.record_resource_demand(task, analysis)
            return task
        archive_size = self._archive_size(task)
        reason = (
            "estimated small-archive resource profile"
            if archive_size < self.precise_resource_min_size_bytes
            else "estimated resource profile; archive analysis is owned by analysis layer"
        )
        return self.record_estimated_profile(task, reason=reason, archive_size=archive_size)

    def record_resource_demand(self, task: ArchiveTask, analysis) -> None:
        demand = estimate_resource_demand(analysis)
        task.fact_bag.set("resource.tokens", demand.as_dict())
        task.fact_bag.set("resource.token_cost", demand.scalar_cost)
        task.fact_bag.set("resource.profile_key", build_resource_profile_key(analysis))

    def record_estimated_profile(
        self,
        task: ArchiveTask,
        *,
        reason: str = "estimated resource profile",
        archive_size: int | None = None,
        profile_suffix: str = "estimated",
    ) -> ArchiveTask:
        self._ensure_resource_health(task)
        archive_size = self._archive_size(task) if archive_size is None else archive_size
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
            "message": reason,
        }
        task.fact_bag.set("resource.analysis", analysis)
        task.fact_bag.set("resource.tokens", self._estimated_tokens_for_size(archive_size))
        task.fact_bag.set("resource.token_cost", max(task.fact_bag.get("resource.tokens").values()))
        task.fact_bag.set("resource.profile_key", f"{archive_type or 'unknown'}|{profile_suffix}|size<{self.precise_resource_min_size_bytes // (1024 * 1024)}m")
        return task

    def record_estimated_single_task_profile(self, task: ArchiveTask) -> ArchiveTask:
        return self.record_estimated_profile(
            task,
            reason="estimated single-task resource profile",
            profile_suffix="estimated|single",
        )

    def _ensure_resource_health(self, task: ArchiveTask) -> None:
        if task.fact_bag.has("resource.health"):
            return
        try:
            part_paths = (task.all_parts if task.all_parts and len(task.all_parts) > 1 else None) or None
            health = cached_check_archive_health(task.main_path, part_paths=part_paths)
            if not health.is_archive:
                return
            task.fact_bag.set("resource.health", {
                "is_archive": health.is_archive,
                "is_encrypted": health.is_encrypted,
                "is_broken": health.is_broken,
                "is_wrong_password": health.is_wrong_password,
                "archive_type": health.archive_type,
                "checksum_error": False,
            })
        except Exception:
            pass

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

    def _archive_size(self, task: ArchiveTask) -> int:
        archive_size = 0
        for path in list(task.all_parts or [task.main_path]):
            try:
                archive_size += os.path.getsize(path)
            except OSError:
                pass
        return archive_size

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
