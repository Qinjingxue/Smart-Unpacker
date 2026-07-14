from __future__ import annotations

import os

from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.filesystem.watcher.service import WatchService
from sunpack.support.runtime_cwd import runtime_working_directory


def run_watch_service(*, tray_enabled: bool = True, once: bool = False) -> int:
    previous_cwd = os.getcwd()
    os.chdir(runtime_working_directory())
    try:
        tray_factory = None
        if tray_enabled and not once:
            from sunpack.gui.tray import WindowsTrayIcon

            tray_factory = WindowsTrayIcon
        service = WatchService(
            engine_factory=PipelineEngine,
            tray_factory=tray_factory,
            group_coordinator_factory=WatchGroupCoordinator,
        )
        return service.run(once=once)
    finally:
        os.chdir(previous_cwd)
