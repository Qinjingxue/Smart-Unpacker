from __future__ import annotations

import copy

from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.service import WatchService
from sunpack.platform.windows.toast_host import ToastHostManager


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

    def toast_manager_factory(config: dict, _state_dir: str, logger) -> ToastHostManager:
        watch_config = config.get("watch") if isinstance(config.get("watch"), dict) else {}
        return ToastHostManager(
            update_interval_ms=int(watch_config.get("toast_update_interval_ms", 50)),
            logger=logger,
        )

    service = WatchService(
        engine_factory=background_engine_factory,
        tray_factory=tray_factory,
        group_coordinator_factory=WatchGroupCoordinator,
        toast_manager_factory=None if once else toast_manager_factory,
    )
    return await service.run(once=once)
