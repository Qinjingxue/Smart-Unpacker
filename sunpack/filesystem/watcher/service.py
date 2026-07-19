from __future__ import annotations

import ctypes
import hashlib
import os
import time
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path

from sunpack.config.fields.watch import DEFAULT_WATCH_CONFIG
from sunpack.config.loader import load_config
from sunpack.filesystem.watcher.log import WatchLogStore
from sunpack.filesystem.watcher.scheduler import WatchScheduler
from sunpack.support.resources import get_resource_path


SERVICE_STATE = "state.json"
WATCH_ROOTS_FILENAME = "sunpack_watch_roots.txt"
CONTROL_EVENT_PREFIX = "Local\\SunPackWatchControl"
ROOTS_MUTEX_PREFIX = "Local\\SunPackWatchRoots"
SERVICE_MUTEX_PREFIX = "Local\\SunPackWatchService"
CONTROL_STOP = "stop"
CONTROL_RELOAD = "reload"
CONTROL_SCHEDULER_WAKEUP = "scheduler_wakeup"

MUTEX_ALL_ACCESS = 0x001F0001
WAIT_ABANDONED = 0x00000080
EVENT_MODIFY_STATE = 0x0002
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF


def service_config_from(config: dict) -> dict:
    service = config.get("watch") if isinstance(config.get("watch"), dict) else {}
    result = dict(service)
    result["roots"] = read_watch_roots()
    return result


def normalize_root(path: str) -> str:
    return os.path.abspath(os.path.normpath(path))


def resolve_service_path(path: str) -> str:
    """Resolve service metadata paths without depending on the process cwd."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = watch_roots_path().resolve().parent / candidate
    return normalize_root(str(candidate))


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
        return resolve_service_path(state_dir)
    return os.path.join(normalize_root(str(watch_roots_path().resolve().parent)), ".sunpack_watch")


def watch_roots_path() -> Path:
    return get_resource_path(WATCH_ROOTS_FILENAME)


def read_watch_roots(path: Path | None = None) -> list[str]:
    roots_path = path or watch_roots_path()
    try:
        lines = roots_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    roots = []
    seen = set()
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        normalized = normalize_root(value)
        key = os.path.normcase(normalized)
        if key in seen:
            continue
        roots.append(normalized)
        seen.add(key)
    return roots


def write_watch_roots(roots: list[str], path: Path | None = None) -> Path:
    roots_path = path or watch_roots_path()
    with _watch_roots_mutex(roots_path):
        return _write_watch_roots_unlocked(roots, roots_path)


def _write_watch_roots_unlocked(roots: list[str], roots_path: Path) -> Path:
    normalized_roots = []
    seen = set()
    for root in roots:
        normalized = normalize_root(root)
        key = os.path.normcase(normalized)
        if key in seen:
            continue
        normalized_roots.append(normalized)
        seen.add(key)
    roots_path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(f"{root}\n" for root in normalized_roots)
    roots_path.write_text(text, encoding="utf-8")
    return roots_path


def add_watch_roots(paths: list[str]) -> tuple[Path, list[str]]:
    roots_path = watch_roots_path()
    with _watch_roots_mutex(roots_path):
        roots = read_watch_roots(roots_path)
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
        _write_watch_roots_unlocked(roots, roots_path)
    return roots_path, added


def remove_watch_roots(paths: list[str]) -> tuple[Path, list[str]]:
    roots_path = watch_roots_path()
    with _watch_roots_mutex(roots_path):
        expected = {os.path.normcase(normalize_root(path)) for path in paths}
        roots = read_watch_roots(roots_path)
        kept = []
        removed = []
        for root in roots:
            normalized = normalize_root(root)
            if os.path.normcase(normalized) in expected:
                removed.append(normalized)
            else:
                kept.append(root)
        _write_watch_roots_unlocked(kept, roots_path)
    return roots_path, removed


def list_watch_roots() -> tuple[Path, list[str]]:
    roots_path = watch_roots_path()
    return roots_path, read_watch_roots(roots_path)


def signal_reload(config: dict | None = None) -> str:
    config = config or load_config()
    return _signal_control_event(config, CONTROL_RELOAD)


def signal_stop(config: dict | None = None) -> str:
    config = config or load_config()
    return _signal_control_event(config, CONTROL_STOP)


def is_watch_lock_active(config: dict) -> bool:
    handle = _open_named_mutex(watch_service_mutex_name(config))
    if not handle:
        return False
    kernel32 = _kernel32()
    try:
        result = kernel32.WaitForSingleObject(handle, 0)
        if result == WAIT_TIMEOUT:
            return True
        if result in {WAIT_OBJECT_0, WAIT_ABANDONED}:
            kernel32.ReleaseMutex(handle)
            return False
        if result == WAIT_FAILED:
            return False
        return False
    finally:
        kernel32.CloseHandle(handle)


class WatchService:
    def __init__(self, *, engine_factory=None, tray_factory=None, group_coordinator_factory=None):
        if engine_factory is None:
            raise ValueError("WatchService requires an engine_factory.")
        self.engine_factory = engine_factory
        self.group_coordinator_factory = group_coordinator_factory
        self.tray_factory = tray_factory
        self.config = load_config()
        self.service_config = service_config_from(self.config)
        self.state_dir = service_state_dir(self.config)
        self.lock_name = watch_service_mutex_name(self.config)
        self.control_events = WatchControlEvents(self.config)
        self.scheduler: WatchScheduler | None = None
        self.pipeline_engine = None
        self.tray = None
        self._stop_requested = False
        self._lock_handle = None
        self._last_idle_tick_signature = None
        self.log = WatchLogStore(os.path.join(self.state_dir, "events.jsonl"))

    @property
    def roots(self) -> list[str]:
        return existing_roots(list(self.service_config.get("roots") or []))

    def run(self, *, once: bool = False) -> int:
        Path(self.state_dir).mkdir(parents=True, exist_ok=True)
        if not self._acquire_lock():
            self.log.write("service_lock_busy", lock_name=self.lock_name)
            return 2
        self.log.write("service_started", state_dir=self.state_dir, roots=self.roots, once=once)
        try:
            self.control_events.start()
            self._start_scheduler()
            self._start_tray()
            if once:
                if self.scheduler is None:
                    return 0
                self.scheduler.run_once()
                return 0
            next_scheduler_run = 0.0
            active_scheduler = None
            while not self._stop_requested:
                now = time.monotonic()
                if self.scheduler is not None:
                    if self.scheduler is not active_scheduler:
                        active_scheduler = self.scheduler
                        next_scheduler_run = 0.0
                        self._last_idle_tick_signature = None
                    if now >= next_scheduler_run:
                        try:
                            result = self.scheduler.run_once()
                            if self._should_log_scheduler_tick(result):
                                self.log.write(
                                    "scheduler_tick",
                                    processed=result.processed,
                                    succeeded=result.succeeded,
                                    failed=result.failed,
                                    pending=result.pending,
                                    errors=result.errors,
                                )
                        except Exception as exc:
                            self.log.write("scheduler_error", error=str(exc), error_type=type(exc).__name__)
                        next_scheduler_run = now + self._scheduler_next_delay()
                    sleep_seconds = max(0.0, next_scheduler_run - now)
                else:
                    sleep_seconds = None
                control_event = self.control_events.wait(sleep_seconds)
                if control_event == CONTROL_SCHEDULER_WAKEUP and self.scheduler is not None:
                    next_scheduler_run = time.monotonic() + self._scheduler_next_delay()
                else:
                    self._handle_control_event(control_event)
            return 0
        except Exception as exc:
            self.log.write("service_error", error=str(exc), error_type=type(exc).__name__)
            raise
        finally:
            self._stop_tray()
            self._stop_scheduler()
            self.control_events.close()
            self._release_lock()
            self.log.write("service_stopped", state_dir=self.state_dir)

    def request_stop(self) -> None:
        self._stop_requested = True

    def request_reload(self) -> None:
        self._reload_config()

    def _start_scheduler(self) -> None:
        self._stop_scheduler()
        roots = self.roots
        if not roots:
            self.log.write("scheduler_not_started", reason="no_existing_roots", configured_roots=list(self.service_config.get("roots") or []))
            return
        configured_out_dir = str(self.service_config.get("out_dir") or self.config.get("output", {}).get("root") or ".")
        out_dir = resolve_service_path(configured_out_dir) if Path(configured_out_dir).expanduser().is_absolute() else configured_out_dir
        state_path = os.path.join(self.state_dir, SERVICE_STATE)
        run_config = dict(self.config)
        watch_config = dict(run_config.get("watch") if isinstance(run_config.get("watch"), dict) else {})
        watch_config["clipboard_monitor_enabled"] = bool(self.service_config.get("clipboard_monitor_enabled", True))
        run_config["watch"] = watch_config
        self.pipeline_engine = self.engine_factory(run_config)
        self.pipeline_engine.start()
        self.scheduler = WatchScheduler(
            run_config,
            roots,
            out_dir=out_dir,
            state_path=state_path,
            interval_seconds=float(watch_config.get("interval_seconds", 1.0)),
            quiet_seconds=float(
                watch_config.get(
                    "cold_start_seconds",
                    watch_config.get("quiet_seconds", DEFAULT_WATCH_CONFIG["cold_start_seconds"]),
                )
            ),
            initial_scan=bool(watch_config.get("initial_scan", True)),
            observer_stop_timeout_seconds=float(watch_config.get("observer_stop_timeout_seconds", 5.0)),
            pipeline_engine=self.pipeline_engine,
            group_coordinator=(self.group_coordinator_factory(run_config) if self.group_coordinator_factory else None),
            wake_callback=self._wake_scheduler,
        )
        self.scheduler.start()
        self.log.write("scheduler_attached", roots=roots, out_dir=out_dir, state_path=state_path)

    def _stop_scheduler(self) -> None:
        if self.scheduler is not None:
            self.scheduler.stop()
        self.scheduler = None
        if self.pipeline_engine is not None:
            self.pipeline_engine.close(graceful=True)
        self.pipeline_engine = None
        self._last_idle_tick_signature = None

    def _start_tray(self) -> None:
        if not self.service_config.get("tray_enabled", True) or self.tray_factory is None:
            return
        try:
            self.tray = self.tray_factory(self)
            self.tray.start()
        except Exception as exc:
            self.tray = None
            self.log.write("tray_start_error", error=str(exc), error_type=type(exc).__name__)

    def _stop_tray(self) -> None:
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass
        self.tray = None

    def _handle_control_event(self, event: str | None) -> None:
        if event == CONTROL_STOP:
            self.request_stop()
            return
        if event == CONTROL_RELOAD:
            self._reload_config()

    def _should_log_scheduler_tick(self, result) -> bool:
        if result.processed or result.failed or result.errors:
            self._last_idle_tick_signature = None
            return True
        pending = int(getattr(result, "pending", 0) or 0)
        if pending <= 0:
            self._last_idle_tick_signature = None
            return False
        signature = ("pending", pending)
        if signature == self._last_idle_tick_signature:
            return False
        self._last_idle_tick_signature = signature
        return True

    def _scheduler_next_delay(self) -> float:
        if self.scheduler is None:
            return 0.0
        if hasattr(self.scheduler, "next_delay_seconds"):
            try:
                return max(0.0, float(self.scheduler.next_delay_seconds()))
            except Exception:
                pass
        return max(0.0, float(getattr(self.scheduler, "interval_seconds", 1.0)))

    def _wake_scheduler(self) -> None:
        self.control_events.wake_scheduler()

    def _reload_config(self) -> None:
        self.config = load_config()
        self.service_config = service_config_from(self.config)
        self.state_dir = service_state_dir(self.config)
        self.control_events.close()
        self.control_events = WatchControlEvents(self.config)
        self.control_events.start()
        self.log = WatchLogStore(os.path.join(self.state_dir, "events.jsonl"))
        self.log.write("service_reloaded", state_dir=self.state_dir, roots=self.roots)
        self._start_scheduler()

    def _acquire_lock(self) -> bool:
        kernel32 = _kernel32()
        handle = kernel32.CreateMutexW(None, False, self.lock_name)
        if not handle:
            raise OSError(ctypes.GetLastError(), f"CreateMutexW failed for {self.lock_name}")
        result = kernel32.WaitForSingleObject(handle, 0)
        if result in {WAIT_OBJECT_0, WAIT_ABANDONED}:
            self._lock_handle = handle
            return True
        kernel32.CloseHandle(handle)
        if result == WAIT_TIMEOUT:
            return False
        if result == WAIT_FAILED:
            raise OSError(ctypes.GetLastError(), f"WaitForSingleObject failed for {self.lock_name}")
        raise OSError(result, f"Unexpected WaitForSingleObject result for {self.lock_name}")

    def _release_lock(self) -> None:
        if self._lock_handle is not None:
            kernel32 = _kernel32()
            kernel32.ReleaseMutex(self._lock_handle)
            kernel32.CloseHandle(self._lock_handle)
            self._lock_handle = None


class WatchControlEvents:
    def __init__(self, config: dict):
        self.names = watch_control_event_names(config)
        self._kernel32 = _kernel32()
        self._handles: list[int] = []

    def start(self) -> None:
        if self._handles:
            return
        self._handles = [
            _create_named_event(self._kernel32, self.names[CONTROL_STOP]),
            _create_named_event(self._kernel32, self.names[CONTROL_RELOAD]),
            _create_named_event(self._kernel32, self.names[CONTROL_SCHEDULER_WAKEUP]),
        ]

    def wake_scheduler(self) -> bool:
        return _set_named_event(self.names[CONTROL_SCHEDULER_WAKEUP])

    def wait(self, timeout_seconds: float | None) -> str | None:
        if not self._handles:
            return None
        timeout_ms = INFINITE if timeout_seconds is None else max(0, int(float(timeout_seconds) * 1000))
        handle_array = (wintypes.HANDLE * len(self._handles))(*self._handles)
        result = self._kernel32.WaitForMultipleObjects(len(self._handles), handle_array, False, timeout_ms)
        if result == WAIT_OBJECT_0:
            return CONTROL_STOP
        if result == WAIT_OBJECT_0 + 1:
            return CONTROL_RELOAD
        if result == WAIT_OBJECT_0 + 2:
            return CONTROL_SCHEDULER_WAKEUP
        if result == WAIT_TIMEOUT:
            return None
        if result == WAIT_FAILED:
            raise OSError(ctypes.GetLastError(), "WaitForMultipleObjects failed")
        return None

    def close(self) -> None:
        for handle in self._handles:
            if handle:
                self._kernel32.CloseHandle(handle)
        self._handles = []


def watch_control_event_names(config: dict | None = None) -> dict[str, str]:
    identity = os.path.abspath(str(watch_roots_path())).lower()
    digest = hashlib.sha256(identity.encode("utf-8", errors="ignore")).hexdigest()[:24]
    return {
        CONTROL_STOP: f"{CONTROL_EVENT_PREFIX}-{digest}-stop",
        CONTROL_RELOAD: f"{CONTROL_EVENT_PREFIX}-{digest}-reload",
        CONTROL_SCHEDULER_WAKEUP: f"{CONTROL_EVENT_PREFIX}-{digest}-scheduler-wakeup",
    }


def watch_roots_mutex_name(path: Path | None = None) -> str:
    roots_path = path or watch_roots_path()
    identity = os.path.abspath(str(roots_path)).lower()
    digest = hashlib.sha256(identity.encode("utf-8", errors="ignore")).hexdigest()[:24]
    return f"{ROOTS_MUTEX_PREFIX}-{digest}"


def watch_service_mutex_name(config: dict | None = None) -> str:
    identity = os.path.abspath(str(watch_roots_path())).lower()
    digest = hashlib.sha256(identity.encode("utf-8", errors="ignore")).hexdigest()[:24]
    return f"{SERVICE_MUTEX_PREFIX}-{digest}"


@contextmanager
def _watch_roots_mutex(path: Path | None = None):
    kernel32 = _kernel32()
    handle = kernel32.CreateMutexW(None, False, watch_roots_mutex_name(path))
    if not handle:
        raise OSError(ctypes.GetLastError(), "CreateMutexW failed for watch roots")
    try:
        result = kernel32.WaitForSingleObject(handle, INFINITE)
        if result not in {WAIT_OBJECT_0, WAIT_ABANDONED}:
            if result == WAIT_FAILED:
                raise OSError(ctypes.GetLastError(), "WaitForSingleObject failed for watch roots")
            raise OSError(result, "Unexpected WaitForSingleObject result for watch roots")
        try:
            yield
        finally:
            kernel32.ReleaseMutex(handle)
    finally:
        kernel32.CloseHandle(handle)


def _signal_control_event(config: dict, event: str) -> str:
    name = watch_control_event_names(config)[event]
    _set_named_event(name)
    return name


def _create_named_event(kernel32, name: str) -> int:
    handle = kernel32.CreateEventW(None, False, False, name)
    if not handle:
        raise OSError(ctypes.GetLastError(), f"CreateEventW failed for {name}")
    return handle


def _set_named_event(name: str) -> bool:
    kernel32 = _kernel32()
    handle = kernel32.OpenEventW(EVENT_MODIFY_STATE, False, name)
    if not handle:
        return False
    try:
        if not kernel32.SetEvent(handle):
            raise OSError(ctypes.GetLastError(), f"SetEvent failed for {name}")
        return True
    finally:
        kernel32.CloseHandle(handle)


def _open_named_mutex(name: str) -> int:
    kernel32 = _kernel32()
    return kernel32.OpenMutexW(MUTEX_ALL_ACCESS, False, name)


def _kernel32():
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.OpenEventW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenEventW.restype = wintypes.HANDLE
    kernel32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenMutexW.restype = wintypes.HANDLE
    kernel32.SetEvent.argtypes = [wintypes.HANDLE]
    kernel32.SetEvent.restype = wintypes.BOOL
    kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel32.ReleaseMutex.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.WaitForMultipleObjects.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    kernel32.WaitForMultipleObjects.restype = wintypes.DWORD
    return kernel32
