from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable

from sunpack.config.loader import load_config
from sunpack.config.payload_io import read_config_payload, write_config_payload
from sunpack.filesystem.watcher.scheduler import WatchScheduler


SERVICE_LOCK = "watch.lock"
SERVICE_RELOAD = "watch.reload"
SERVICE_STOP = "watch.stop"
SERVICE_STATE = "state.json"


def service_config_from(config: dict) -> dict:
    service = config.get("watch") if isinstance(config.get("watch"), dict) else {}
    return dict(service)


def normalize_root(path: str) -> str:
    return os.path.abspath(os.path.normpath(path))


def existing_roots(roots: list[str]) -> list[str]:
    result = []
    seen = set()
    for root in roots:
        normalized = normalize_root(root)
        key = os.path.normcase(normalized)
        if key in seen or not os.path.isdir(normalized):
            continue
        seen.add(key)
        result.append(normalized)
    return result


def service_state_dir(config: dict) -> str:
    service = service_config_from(config)
    state_dir = str(service.get("state_dir") or "").strip()
    if state_dir:
        return normalize_root(state_dir)
    out_dir = normalize_root(str(service.get("out_dir") or config.get("output", {}).get("root") or "."))
    return os.path.join(out_dir, ".sunpack_watch")


def add_watch_roots(paths: list[str]) -> tuple[Path, list[str]]:
    config_path, payload = read_config_payload()
    service = payload.setdefault("watch", {})
    roots = list(service.get("roots") or [])
    seen = {os.path.normcase(normalize_root(root)) for root in roots}
    added = []
    for path in paths:
        normalized = normalize_root(path)
        key = os.path.normcase(normalized)
        if key in seen:
            continue
        roots.append(normalized)
        seen.add(key)
        added.append(normalized)
    service["roots"] = roots
    service["enabled"] = True
    write_config_payload(config_path, payload)
    return config_path, added


def remove_watch_roots(paths: list[str]) -> tuple[Path, list[str]]:
    config_path, payload = read_config_payload()
    service = payload.setdefault("watch", {})
    expected = {os.path.normcase(normalize_root(path)) for path in paths}
    roots = list(service.get("roots") or [])
    kept = []
    removed = []
    for root in roots:
        normalized = normalize_root(root)
        if os.path.normcase(normalized) in expected:
            removed.append(normalized)
        else:
            kept.append(root)
    service["roots"] = kept
    write_config_payload(config_path, payload)
    return config_path, removed


def list_watch_roots() -> tuple[Path, list[str]]:
    config_path, payload = read_config_payload()
    service = payload.get("watch") if isinstance(payload.get("watch"), dict) else {}
    return config_path, [normalize_root(path) for path in service.get("roots") or []]


def signal_reload(config: dict | None = None) -> str:
    config = config or load_config()
    state_dir = service_state_dir(config)
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    path = os.path.join(state_dir, SERVICE_RELOAD)
    Path(path).write_text(str(time.time()), encoding="utf-8")
    return path


def signal_stop(config: dict | None = None) -> str:
    config = config or load_config()
    state_dir = service_state_dir(config)
    Path(state_dir).mkdir(parents=True, exist_ok=True)
    path = os.path.join(state_dir, SERVICE_STOP)
    Path(path).write_text(str(time.time()), encoding="utf-8")
    return path


class WatchService:
    def __init__(self, *, runner_factory=None, tray_factory=None):
        if runner_factory is None:
            raise ValueError("WatchService requires a runner_factory.")
        self.runner_factory = runner_factory
        self.tray_factory = tray_factory
        self.config = load_config()
        self.service_config = service_config_from(self.config)
        self.state_dir = service_state_dir(self.config)
        self.lock_path = os.path.join(self.state_dir, SERVICE_LOCK)
        self.reload_path = os.path.join(self.state_dir, SERVICE_RELOAD)
        self.stop_path = os.path.join(self.state_dir, SERVICE_STOP)
        self.scheduler: WatchScheduler | None = None
        self.tray = None
        self._stop_requested = False
        self._lock_handle = None

    @property
    def roots(self) -> list[str]:
        return existing_roots(list(self.service_config.get("roots") or []))

    def run(self, *, once: bool = False) -> int:
        Path(self.state_dir).mkdir(parents=True, exist_ok=True)
        if not self._acquire_lock():
            return 2
        try:
            self._start_scheduler()
            self._start_tray()
            if once:
                if self.scheduler is None:
                    return 0
                self.scheduler.run_once()
                return 0
            while not self._stop_requested:
                self._handle_signals()
                if self.scheduler is not None:
                    self.scheduler.run_once()
                    sleep_seconds = self.scheduler.interval_seconds
                else:
                    sleep_seconds = float(self.service_config.get("reload_poll_seconds", 1.0))
                time.sleep(max(0.2, min(float(self.service_config.get("reload_poll_seconds", 1.0)), sleep_seconds)))
            return 0
        finally:
            self._stop_tray()
            self._stop_scheduler()
            self._release_lock()

    def request_stop(self) -> None:
        self._stop_requested = True

    def request_reload(self) -> None:
        self._reload_config()

    def add_clipboard_path(self, read_clipboard_text: Callable[[], list[str]]) -> list[str]:
        added_paths = []
        for value in read_clipboard_text():
            path = normalize_root(value)
            if os.path.isdir(path):
                added_paths.append(path)
        if not added_paths:
            return []
        _, added = add_watch_roots(added_paths)
        if added:
            self.request_reload()
        return added

    def _start_scheduler(self) -> None:
        self._stop_scheduler()
        roots = self.roots
        if not roots:
            return
        out_dir = normalize_root(str(self.service_config.get("out_dir") or self.config.get("output", {}).get("root") or "."))
        state_path = os.path.join(self.state_dir, SERVICE_STATE)
        run_config = dict(self.config)
        watch_config = dict(run_config.get("watch") if isinstance(run_config.get("watch"), dict) else {})
        watch_config["clipboard_monitor_enabled"] = bool(self.service_config.get("clipboard_monitor_enabled", True))
        run_config["watch"] = watch_config
        self.scheduler = WatchScheduler(
            run_config,
            roots,
            out_dir=out_dir,
            state_path=state_path,
            interval_seconds=float(watch_config.get("interval_seconds", 5.0)),
            stable_seconds=float(watch_config.get("stable_seconds", 10.0)),
            recursive=bool(watch_config.get("recursive", True)),
            initial_scan=bool(watch_config.get("initial_scan", True)),
            observer_stop_timeout_seconds=float(watch_config.get("observer_stop_timeout_seconds", 5.0)),
            runner_factory=self.runner_factory,
        )
        self.scheduler.start()

    def _stop_scheduler(self) -> None:
        if self.scheduler is not None:
            self.scheduler.stop()
        self.scheduler = None

    def _start_tray(self) -> None:
        if not self.service_config.get("tray_enabled", True) or self.tray_factory is None:
            return
        try:
            self.tray = self.tray_factory(self)
            self.tray.start()
        except Exception:
            self.tray = None

    def _stop_tray(self) -> None:
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass
        self.tray = None

    def _handle_signals(self) -> None:
        if os.path.exists(self.stop_path):
            try:
                os.remove(self.stop_path)
            except OSError:
                pass
            self.request_stop()
            return
        if os.path.exists(self.reload_path):
            try:
                os.remove(self.reload_path)
            except OSError:
                pass
            self._reload_config()

    def _reload_config(self) -> None:
        self.config = load_config()
        self.service_config = service_config_from(self.config)
        self.state_dir = service_state_dir(self.config)
        self.reload_path = os.path.join(self.state_dir, SERVICE_RELOAD)
        self.stop_path = os.path.join(self.state_dir, SERVICE_STOP)
        self._start_scheduler()

    def _acquire_lock(self) -> bool:
        try:
            self._lock_handle = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(self._lock_handle, str(os.getpid()).encode("ascii", errors="ignore"))
            return True
        except FileExistsError:
            return False

    def _release_lock(self) -> None:
        if self._lock_handle is not None:
            try:
                os.close(self._lock_handle)
            except OSError:
                pass
            self._lock_handle = None
        try:
            os.remove(self.lock_path)
        except OSError:
            pass
