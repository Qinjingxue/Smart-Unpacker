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
        self._pipe_handle: int | None = None
        self._sequence = 0

    @property
    def pipe_name(self) -> str:
        return self._pipe_name

    def start(self) -> None:
        with self._condition:
            if self._thread is not None:
                return
            self._stopping = False
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
            while not self._is_stopping():
                if self._pipe_handle is None:
                    try:
                        self._start_and_connect()
                        connected_at = time.monotonic()
                        sent_revision = -1
                    except Exception as exc:
                        failures += 1
                        self._log("toast_host_start_error", error=str(exc), attempt=failures)
                        self._disconnect(terminate=True)
                        self._wait(min(30.0, 0.25 * (2 ** min(failures - 1, 7))))
                        continue

                with self._condition:
                    self._forget_expired_snapshot_locked(time.monotonic())
                    snapshot = self._snapshot
                    revision = self._revision
                    stopping = self._stopping
                if stopping:
                    break

                process = self._process
                if process is not None and process.poll() is not None:
                    self._log("toast_host_exited", exit_code=process.poll())
                    failures = 0 if time.monotonic() - connected_at >= 10.0 else failures + 1
                    self._disconnect(terminate=False)
                    self._wait(min(30.0, 0.25 * (2 ** min(max(0, failures - 1), 7))))
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
                        except Exception as exc:
                            self._log("toast_host_pipe_error", error=str(exc))
                            failures = 0 if time.monotonic() - connected_at >= 10.0 else failures + 1
                            self._disconnect(terminate=True)
                            self._wait(min(30.0, 0.25 * (2 ** min(max(0, failures - 1), 7))))
                            continue

                wait_for = (
                    0.25
                    if revision == sent_revision
                    else max(0.005, min(0.25, next_progress_send - time.monotonic()))
                )
                self._wait(wait_for)
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

    def _start_and_connect(self) -> None:
        host_path = self._host_path or get_toast_host_path()
        host_path = os.path.abspath(host_path)
        if not os.path.isfile(host_path):
            raise FileNotFoundError(host_path)
        arguments = [
            host_path,
            "--pipe",
            self._pipe_name,
            "--session",
            self._session,
            "--parent-pid",
            str(os.getpid()),
        ]
        if self._diagnostic_log_path:
            arguments.extend(("--diagnostic-log", os.path.abspath(self._diagnostic_log_path)))
        self._process = self._launcher(
            arguments,
            cwd=str(Path(host_path).parent),
        )
        deadline = time.monotonic() + 5.0
        while not self._is_stopping() and time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise RuntimeError(f"Toast Host exited with code {self._process.poll()}")
            handle = _open_pipe(self._pipe_name, 100)
            if handle is not None:
                self._pipe_handle = handle
                self._sequence = 0
                self._write(encode_hello(self._session, self._next_sequence()))
                self._log("toast_host_connected", pid=getattr(self._process, "pid", 0))
                return
            self._wait(0.01)
        raise TimeoutError("Toast Host named pipe did not become ready")

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
            if process.poll() is None:
                process.terminate()
        except Exception:
            pass

    def _close_process(self) -> None:
        process, self._process = self._process, None
        close = getattr(process, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass

    def _is_stopping(self) -> bool:
        with self._condition:
            return self._stopping

    def _wait(self, seconds: float) -> None:
        with self._condition:
            if not self._stopping:
                self._condition.wait(timeout=max(0.0, seconds))

    def _log(self, event: str, **payload) -> None:
        try:
            if self._logger is not None:
                self._logger.write(event, **payload)
        except Exception:
            pass


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
    return dll
