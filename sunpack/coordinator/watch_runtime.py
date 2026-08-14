from __future__ import annotations

from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.service import WatchService


async def run_watch_service(*, tray_enabled: bool = True, once: bool = False) -> int:
    tray_factory = None
    if tray_enabled and not once:
        from sunpack.gui.tray import WindowsTrayIcon

        tray_factory = WindowsTrayIcon
    service = WatchService(
        engine_factory=PipelineEngine,
        tray_factory=tray_factory,
        group_coordinator_factory=WatchGroupCoordinator,
    )
    return await service.run(once=once)
