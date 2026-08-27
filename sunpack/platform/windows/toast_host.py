from __future__ import annotations

import ctypes
import os
import secrets
import threading
import time
from ctypes import wintypes
from functools import lru_cache
from pathlib import Path
from typing import Callable

from sunpack.platform.windows.process_launch import launch_unelevated
from sunpack.platform.windows.toast_protocol import (
    ToastMessageType,
    ToastSnapshot,
    ToastSnapshotKind,
    encode_frame,
    encode_hello,
    encode_snapshot,
)
from sunpack.support.resources import get_toast_host_path


GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_FILE_NOT_FOUND = 2
ERROR_PIPE_BUSY = 231
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
SDDL_REVISION_1 = 1


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _ToastHostStopping(RuntimeError):
    pass


class ToastHostManager:
    """Non-blocking, restartable controller for the ordinary-user Toast Host."""

    def __init__(
        self,
        *,
        host_path: str | None = None,
        diagnostic_log_path: str | None = None,
        update_interval_ms: int = 50,
        logger=None,
        launcher: Callable = launch_unelevated,
    ):
        self._host_path = str(host_path) if host_path else None
        self._diagnostic_log_path = str(diagnostic_log_path) if diagnostic_log_path else None
        self._update_interval = max(0.01, min(1.0, int(update_interval_ms) / 1000.0))
        self._logger = logger
        self._launcher = launcher
        self._session = secrets.token_hex(16)
        self._pipe_name = rf"\\.\pipe\SunPackToast-{os.getpid()}-{secrets.token_hex(8)}"
        self._condition = threading.Condition()
        self._snapshot: ToastSnapshot | None = None
        self._snapshot_expires_at = 0.0
        self._revision = 0
        self._stopping = False
        self._thread: threading.Thread | None = None
        self._process = None
        self._process_generation = 0
        self._process_exit_generation = -1
        self._process_exit_code: int | None = None
        self._process_waiter: threading.Thread | None = None
        self._pipe_handle: int | None = None
        self._stop_handle: int | None = None
        self._sequence = 0

    @property
    def pipe_name(self) -> str:
        return self._pipe_name

    def start(self) -> None:
        with self._condition:
            if self._thread is not None:
                return
            self._stopping = False
            self._stop_handle = _create_event()
            self._thread = threading.Thread(
                target=self._supervise,
                name="sunpack-toast-host-supervisor",
                daemon=True,
            )
            self._thread.start()

    def publish(self, snapshot: ToastSnapshot) -> None:
        with self._condition:
            if self._stopping:
                return
            self._snapshot = snapshot
            # The native host owns the visible TTL and starts it only after
            # ToastNotifier.Show succeeds. This deadline merely bounds how
            # long a delivered terminal snapshot is retained for reconnects.
            self._snapshot_expires_at = 0.0
            self._revision += 1
            self._condition.notify()

    def clear(self) -> None:
        with self._condition:
            if self._stopping:
                return
            self._snapshot = None
            self._snapshot_expires_at = 0.0
            self._revision += 1
            self._condition.notify()

    def stop(self, *, timeout: float = 2.0) -> None:
        with self._condition:
            thread = self._thread
            if thread is None:
                return
            self._stopping = True
            if self._stop_handle is not None:
                _kernel32().SetEvent(self._stop_handle)
            self._condition.notify_all()
        thread.join(timeout=max(0.0, timeout))
        if thread.is_alive():
            self._terminate_process()
            thread.join(timeout=0.5)
        with self._condition:
            self._thread = None

    def _supervise(self) -> None:
        failures = 0
        connected_at = 0.0
        sent_revision = -1
        next_progress_send = 0.0
        try:
            while True:
                if self._is_stopping():
                    break
                if self._pipe_handle is None:
                    try:
                        self._start_and_connect()
                        connected_at = time.monotonic()
                        sent_revision = -1
                    except _ToastHostStopping:
                        break
                    except Exception as exc:
                        failures += 1
                        self._log("toast_host_start_error", error=str(exc), attempt=failures)
                        self._disconnect(terminate=True)
                        self._wait_for_stop(min(30.0, 0.25 * (2 ** min(failures - 1, 7))))
                        continue

                with self._condition:
                    now = time.monotonic()
                    self._forget_expired_snapshot_locked(now)
                    snapshot = self._snapshot
                    revision = self._revision
                    stopping = self._stopping
                    generation = self._process_generation
                    process_exited = self._process_exit_generation == generation
                    exit_code = self._process_exit_code
                if stopping:
                    break

                if process_exited:
                    self._log("toast_host_exited", exit_code=exit_code)
                    failures = 0 if time.monotonic() - connected_at >= 10.0 else failures + 1
                    self._disconnect(terminate=False)
                    self._wait_for_stop(min(30.0, 0.25 * (2 ** min(max(0, failures - 1), 7))))
                    continue

                if revision != sent_revision:
                    now = time.monotonic()
                    terminal = snapshot is not None and snapshot.kind != ToastSnapshotKind.PROGRESS
                    if terminal or snapshot is None or now >= next_progress_send:
                        try:
                            if snapshot is None:
                                self._send(ToastMessageType.CLEAR)
                            else:
                                self._send_snapshot(snapshot)
                            sent_revision = revision
                            if terminal:
                                self._retain_terminal_after_send(snapshot, revision)
                            else:
                                next_progress_send = now + self._update_interval
                        except ValueError as exc:
                            self._log("toast_snapshot_rejected", error=str(exc))
                            with self._condition:
                                if revision == self._revision:
                                    self._snapshot = None
                                    self._snapshot_expires_at = 0.0
                                    self._revision += 1
                                    self._condition.notify_all()
                            continue
                        except Exception as exc:
                            self._log("toast_host_pipe_error", error=str(exc))
                            failures = 0 if time.monotonic() - connected_at >= 10.0 else failures + 1
                            self._disconnect(terminate=True)
                            self._wait_for_stop(min(30.0, 0.25 * (2 ** min(max(0, failures - 1), 7))))
                            continue

                with self._condition:
                    now = time.monotonic()
                    deadlines: list[float] = []
                    if self._snapshot_expires_at:
                        deadlines.append(self._snapshot_expires_at)
                    if (
                        self._revision != sent_revision
                        and self._snapshot is not None
                        and self._snapshot.kind == ToastSnapshotKind.PROGRESS
                        and next_progress_send > now
                    ):
                        deadlines.append(next_progress_send)
                    deadline = min(deadlines) if deadlines else None
                    wait_for = None if deadline is None else max(0.0, deadline - now)
                    observed_revision = self._revision
                    self._condition.wait_for(
                        lambda: (
                            self._stopping
                            or self._revision != observed_revision
                            or self._process_exit_generation == generation
                        ),
                        timeout=wait_for,
                    )
        finally:
            try:
                if self._pipe_handle is not None:
                    self._send(ToastMessageType.CLEAR)
                    self._send(ToastMessageType.SHUTDOWN)
            except Exception:
                pass
            handle, self._pipe_handle = self._pipe_handle, None
            if handle is not None:
                _kernel32().CloseHandle(handle)
            process = self._process
            if process is not None:
                try:
                    result = process.wait(timeout=0.75)
                    if result is None:
                        process.terminate()
                except Exception:
                    self._terminate_process()
            self._close_process()
            stop_handle, self._stop_handle = self._stop_handle, None
            if stop_handle is not None:
                _kernel32().CloseHandle(stop_handle)

    def _start_and_connect(self) -> None:
        host_path = self._host_path or get_toast_host_path()
        host_path = os.path.abspath(host_path)
        if not os.path.isfile(host_path):
            raise FileNotFoundError(host_path)
        ready_name = rf"Local\SunPackToastReady-{os.getpid()}-{secrets.token_hex(8)}"
        ready_handle = _create_event(ready_name, cross_integrity=True)
        try:
            arguments = [
                host_path,
                "--pipe",
                self._pipe_name,
                "--session",
                self._session,
                "--parent-pid",
                str(os.getpid()),
                "--ready-event",
                ready_name,
            ]
            if self._diagnostic_log_path:
                arguments.extend(("--diagnostic-log", os.path.abspath(self._diagnostic_log_path)))
            process = self._launcher(
                arguments,
                cwd=str(Path(host_path).parent),
            )
            from sunpack.platform.windows.process_job import assign_child_process

            assign_child_process(getattr(process, "pid", 0))
            with self._condition:
                self._process = process
                self._process_generation += 1
                generation = self._process_generation
                self._process_exit_generation = -1
                self._process_exit_code = None
            self._start_process_waiter(process, generation)
            stop_handle = self._stop_handle
            if stop_handle is None:
                raise _ToastHostStopping("Toast Host manager is stopping")
            _wait_for_host_ready(ready_handle, process, stop_handle, timeout_ms=5_000)
            handle = _open_pipe(self._pipe_name, 5_000)
            if handle is None:
                raise TimeoutError("Toast Host named pipe was signaled ready but could not be opened")
            self._pipe_handle = handle
            self._sequence = 0
            self._write(encode_hello(self._session, self._next_sequence()))
            self._log("toast_host_connected", pid=getattr(process, "pid", 0))
        finally:
            _kernel32().CloseHandle(ready_handle)

    def _start_process_waiter(self, process, generation: int) -> None:
        def wait_for_exit() -> None:
            try:
                exit_code = process.wait(timeout=None)
            except Exception as exc:
                self._log("toast_host_wait_error", error=str(exc))
                exit_code = -1
            with self._condition:
                if self._process is process and self._process_generation == generation:
                    self._process_exit_generation = generation
                    self._process_exit_code = None if exit_code is None else int(exit_code)
                    self._condition.notify_all()

        waiter = threading.Thread(
            target=wait_for_exit,
            name=f"sunpack-toast-host-exit-{generation}",
            daemon=True,
        )
        self._process_waiter = waiter
        waiter.start()

    def _send_snapshot(self, snapshot: ToastSnapshot) -> None:
        self._write(encode_snapshot(snapshot, self._next_sequence()))

    def _retain_terminal_after_send(self, snapshot: ToastSnapshot, revision: int) -> None:
        if snapshot.ttl_ms <= 0:
            return
        with self._condition:
            if revision == self._revision and snapshot is self._snapshot:
                self._snapshot_expires_at = time.monotonic() + snapshot.ttl_ms / 1000.0

    def _forget_expired_snapshot_locked(self, now: float) -> None:
        if self._snapshot_expires_at and now >= self._snapshot_expires_at:
            self._snapshot = None
            self._snapshot_expires_at = 0.0

    def _send(self, message_type: ToastMessageType) -> None:
        self._write(encode_frame(message_type, b"", self._next_sequence()))

    def _write(self, frame: bytes) -> None:
        handle = self._pipe_handle
        if handle is None:
            raise BrokenPipeError("Toast Host pipe is not connected")
        _write_all(handle, frame)

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def _disconnect(self, *, terminate: bool) -> None:
        handle, self._pipe_handle = self._pipe_handle, None
        if handle is not None:
            _kernel32().CloseHandle(handle)
        if terminate:
            self._terminate_process()
        self._close_process()

    def _terminate_process(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            process.terminate()
        except Exception:
            pass

    def _close_process(self) -> None:
        process, self._process = self._process, None
        waiter, self._process_waiter = self._process_waiter, None
        close = getattr(process, "close", None)
        if not callable(close):
            return

        def close_resource() -> None:
            try:
                close()
            except Exception:
                pass

        if waiter is None or waiter is threading.current_thread():
            close_resource()
            return
        waiter.join(timeout=0.75)
        if not waiter.is_alive():
            close_resource()
            return

        def close_after_wait() -> None:
            waiter.join()
            close_resource()

        threading.Thread(
            target=close_after_wait,
            name="sunpack-toast-host-handle-close",
            daemon=True,
        ).start()

    def _is_stopping(self) -> bool:
        with self._condition:
            return self._stopping

    def _wait_for_stop(self, seconds: float) -> None:
        with self._condition:
            self._condition.wait_for(lambda: self._stopping, timeout=max(0.0, seconds))

    def _log(self, event: str, **payload) -> None:
        try:
            if self._logger is not None:
                self._logger.write(event, **payload)
        except Exception:
            pass


def _create_event(name: str | None = None, *, cross_integrity: bool = False) -> int:
    security_attributes = None
    security_descriptor = ctypes.c_void_p()
    if cross_integrity:
        # The controller may be elevated while the Toast Host deliberately runs
        # at medium integrity.  Give the same-session child permission to signal
        # this unguessable, one-shot readiness event.
        sddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)S:(ML;;NW;;;ME)"
        if not _advapi32().ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1,
            ctypes.byref(security_descriptor),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        security_attributes = SECURITY_ATTRIBUTES(
            nLength=ctypes.sizeof(SECURITY_ATTRIBUTES),
            lpSecurityDescriptor=security_descriptor,
            bInheritHandle=False,
        )
    try:
        handle = _kernel32().CreateEventW(
            ctypes.byref(security_attributes) if security_attributes is not None else None,
            True,
            False,
            name,
        )
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(handle)
    finally:
        if security_descriptor:
            _kernel32().LocalFree(security_descriptor)


def _process_handle(process) -> int:
    handle = getattr(process, "handle", None)
    if handle is None:
        handle = getattr(process, "_handle", None)
    if not handle:
        raise RuntimeError("Toast Host process does not expose a waitable handle")
    return int(handle)


def _wait_for_host_ready(ready_handle: int, process, stop_handle: int, *, timeout_ms: int) -> None:
    handles = (wintypes.HANDLE * 3)(ready_handle, _process_handle(process), stop_handle)
    result = _kernel32().WaitForMultipleObjects(3, handles, False, max(1, int(timeout_ms)))
    if result == WAIT_OBJECT_0:
        return
    if result == WAIT_OBJECT_0 + 1:
        try:
            exit_code = process.wait(timeout=0)
        except Exception:
            exit_code = None
        raise RuntimeError(f"Toast Host exited before becoming ready (code {exit_code})")
    if result == WAIT_OBJECT_0 + 2:
        raise _ToastHostStopping("Toast Host manager stopped during startup")
    if result == WAIT_TIMEOUT:
        raise TimeoutError("Toast Host named pipe did not become ready")
    raise ctypes.WinError(ctypes.get_last_error())


def _open_pipe(pipe_name: str, timeout_ms: int) -> int | None:
    kernel32 = _kernel32()
    if not kernel32.WaitNamedPipeW(pipe_name, max(1, int(timeout_ms))):
        error = ctypes.get_last_error()
        if error in {ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY}:
            return None
        raise ctypes.WinError(error)
    handle = kernel32.CreateFileW(
        pipe_name,
        GENERIC_WRITE,
        0,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        if error in {ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY}:
            return None
        raise ctypes.WinError(error)
    return int(handle)


def _write_all(handle: int, data: bytes) -> None:
    kernel32 = _kernel32()
    offset = 0
    while offset < len(data):
        chunk = data[offset:]
        written = wintypes.DWORD()
        buffer = ctypes.create_string_buffer(chunk)
        if not kernel32.WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if not written.value:
            raise BrokenPipeError("Toast Host pipe accepted zero bytes")
        offset += int(written.value)


@lru_cache(maxsize=1)
def _kernel32():
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    dll.CreateEventW.restype = wintypes.HANDLE
    dll.SetEvent.argtypes = [wintypes.HANDLE]
    dll.SetEvent.restype = wintypes.BOOL
    dll.WaitForMultipleObjects.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    dll.WaitForMultipleObjects.restype = wintypes.DWORD
    dll.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    dll.WaitNamedPipeW.restype = wintypes.BOOL
    dll.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    dll.CreateFileW.restype = wintypes.HANDLE
    dll.WriteFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    dll.WriteFile.restype = wintypes.BOOL
    dll.CloseHandle.argtypes = [wintypes.HANDLE]
    dll.CloseHandle.restype = wintypes.BOOL
    dll.LocalFree.argtypes = [ctypes.c_void_p]
    dll.LocalFree.restype = ctypes.c_void_p
    return dll


@lru_cache(maxsize=1)
def _advapi32():
    dll = ctypes.WinDLL("advapi32", use_last_error=True)
    dll.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    dll.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    return dll
