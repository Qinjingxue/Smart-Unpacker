from __future__ import annotations

import copy

from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.service import WatchService


async def run_watch_service(*, tray_enabled: bool = True, once: bool = False) -> int:
    tray_factory = None
    if tray_enabled and not once:
        from sunpack.gui.tray import WindowsTrayIcon

        tray_factory = WindowsTrayIcon
    def background_engine_factory(config: dict) -> PipelineEngine:
        engine_config = copy.deepcopy(config)
        performance = engine_config.get("performance")
        if not isinstance(performance, dict):
            performance = {}
            engine_config["performance"] = performance
        worker = performance.get("worker")
        if not isinstance(worker, dict):
            worker = {}
            performance["worker"] = worker
        worker["windows_process_mode"] = "background"
        return PipelineEngine(engine_config)

    service = WatchService(
        engine_factory=background_engine_factory,
        tray_factory=tray_factory,
        group_coordinator_factory=WatchGroupCoordinator,
    )
    return await service.run(once=once)
