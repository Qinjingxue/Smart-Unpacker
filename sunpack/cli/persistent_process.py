from __future__ import annotations

import asyncio
import os
import struct
import sys
import time
from typing import Any

from sunpack.support.runtime_cwd import runtime_working_directory
from sunpack.config.cli_settings import load_cli_language_from_config
from sunpack.i18n import I18nContext


SERVER_ARG = "--persistent-server"
SHUTDOWN_ARG = "--persistent-shutdown"
_REQUEST_MAGIC = b"SPK1"
_STREAM_MAGIC = b"SPS1"
_MAX_FIELD_BYTES = 16 * 1024 * 1024
_TERMINAL_COLUMNS_ARG = "--_sunpack-terminal-columns="


def handle_early_argv(argv: list[str]) -> int | None:
    if not argv:
        return None
    if argv[0] == SERVER_ARG:
        return asyncio.run(run_server())
    if argv[0] == SHUTDOWN_ARG:
        return submit_request([], shutdown=True)
    return None


def state_path() -> str:
    import tempfile

    executable_dir = os.path.normcase(os.path.dirname(os.path.abspath(sys.executable)))
    digest = 0xCBF29CE484222325
    for byte in executable_dir.encode("utf-8", "surrogatepass"):
        digest ^= byte
        digest = (digest * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    root = os.path.join(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir(), "SunPack")
    return os.path.join(root, f"runtime-{digest:016x}.state")


def server_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, SERVER_ARG]
    entry = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sunpack.py"))
    if os.path.isfile(entry):
        return [sys.executable, entry, SERVER_ARG]
    return [sys.executable, "-m", "sunpack", SERVER_ARG]


def submit_request(argv: list[str], *, shutdown: bool = False) -> int:
    i18n = I18nContext(load_cli_language_from_config())
    request_cwd = os.getcwd()
    request_argv = list(argv)
    pause = "--pause" in request_argv
    if pause:
        request_argv = [item for item in request_argv if item != "--pause"]
        if "--no-pause" not in request_argv:
            request_argv.append("--no-pause")
    supports_terminal_updates = _client_supports_terminal_updates(sys.stdout)
    payload = {
        "argv": request_argv,
        "cwd": request_cwd,
        "shutdown": bool(shutdown),
        "stdout_tty": supports_terminal_updates,
        "stdout_columns": _client_terminal_columns(sys.stdout) if supports_terminal_updates else 0,
        "stdin_tty": bool(sys.stdin is not None and sys.stdin.isatty()),
    }
    response = _send_or_start(payload)
    stdout = str(response.get("stdout") or "")
    stderr = str(response.get("stderr") or "")
    if stdout:
        print(stdout, end="", file=sys.stdout)
    if stderr:
        print(stderr, end="", file=sys.stderr)
    if pause and sys.stdin is not None and sys.stdin.isatty():
        try:
            input(i18n.t("cli.press_enter"))
        except (EOFError, KeyboardInterrupt):
            pass
    return int(response.get("exit_code", 1))


def _client_supports_terminal_updates(stream) -> bool:
    if stream is None:
        return False
    # This runs in the foreground client, where the real console handle lives.
    # The persistent server has no console of its own and therefore cannot
    # validate or enable Windows virtual-terminal processing on our behalf.
    from sunpack.coordinator.reporting import _terminal_supports_updates

    return _terminal_supports_updates(stream)


def _client_terminal_columns(stream) -> int:
    try:
        columns = int(os.get_terminal_size(stream.fileno()).columns)
    except (AttributeError, OSError, TypeError, ValueError):
        return 80
    return max(20, min(1000, columns))


def _send_or_start(payload: dict[str, Any]) -> dict[str, Any]:
    response = _try_send(payload)
    if response is not None:
        return response
    if payload.get("shutdown"):
        return {"exit_code": 0, "stdout": "", "stderr": ""}
    import subprocess
    import time

    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    subprocess.Popen(
        server_command(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creationflags,
        cwd=runtime_working_directory(),
    )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        response = _try_send(payload)
        if response is not None:
            return response
        time.sleep(0.025)
    return {"exit_code": 1, "stdout": "", "stderr": I18nContext(load_cli_language_from_config()).t("cli.persistent_start_timeout") + "\n"}


def _try_send(payload: dict[str, Any]) -> dict[str, Any] | None:
    import socket
    import struct

    try:
        with open(state_path(), "r", encoding="ascii") as stream:
            port_text, token_hex = stream.read().splitlines()[:2]
        port = int(port_text)
        token = bytes.fromhex(token_hex)
        connection = socket.create_connection(("127.0.0.1", port), timeout=2.0)
    except (FileNotFoundError, ConnectionError, OSError, ValueError):
        return None
    try:
        cwd = str(payload.get("cwd") or "").encode("utf-8", "surrogatepass")
        argv_values = [str(item) for item in payload.get("argv") or []]
        try:
            stdout_columns = int(payload.get("stdout_columns") or 0)
        except (TypeError, ValueError):
            stdout_columns = 0
        if stdout_columns > 0:
            argv_values.append(f"{_TERMINAL_COLUMNS_ARG}{max(20, min(1000, stdout_columns))}")
        argv = [item.encode("utf-8", "surrogatepass") for item in argv_values]
        flags = ((1 if payload.get("shutdown") else 0)
                 | (2 if payload.get("stdout_tty") else 0)
                 | (4 if payload.get("stdin_tty") else 0))
        body = [token, struct.pack("!III", flags, len(cwd), len(argv)), cwd]
        for item in argv:
            body.extend((struct.pack("!I", len(item)), item))
        connection.sendall(_REQUEST_MAGIC + b"".join(body))
        connection.settimeout(None)
        if _recv_exact(connection, 4) != _STREAM_MAGIC:
            return None
        return _recv_stream(connection)
    except (EOFError, OSError, ValueError):
        return None
    finally:
        connection.close()


async def run_server() -> int:
    import secrets

    lock_stream = _acquire_server_lock()
    if lock_stream is None:
        return 0
    token = secrets.token_bytes(32)
    from sunpack.cli.persistent_runtime import (
        close_persistent_runtime,
        enable_persistent_runtime,
        persistent_runtime_is_idle,
        persistent_server_idle_seconds,
    )

    enable_persistent_runtime()
    shutdown = asyncio.Event()
    state = {"served": False, "last_completed": time.monotonic(), "active": 0}
    port = 0

    async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        state["active"] += 1
        try:
            payload = await _recv_request_async(reader, token)
            if payload is None:
                return
            writer.write(_STREAM_MAGIC)
            await writer.drain()
            if payload.get("shutdown"):
                writer.write(struct.pack("!BIi", 0, 4, 0))
                await writer.drain()
                shutdown.set()
                return
            exit_code = await _execute_streaming_request_async(payload, reader, writer)
            writer.write(struct.pack("!BIi", 0, 4, exit_code))
            await writer.drain()
            state["served"] = True
            state["last_completed"] = time.monotonic()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            state["active"] -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    server = await asyncio.start_server(handle_connection, "127.0.0.1", 0, backlog=64)
    port = int(server.sockets[0].getsockname()[1])
    _write_state(port, token)

    async def monitor_idle() -> None:
        while not shutdown.is_set():
            await asyncio.sleep(0.25)
            if state["active"]:
                continue
            if _idle_shutdown_due(
                served_request=bool(state["served"]),
                last_completed_at=float(state["last_completed"]),
                idle_seconds=persistent_server_idle_seconds(),
                runtime_idle=persistent_runtime_is_idle(),
            ):
                shutdown.set()

    monitor = asyncio.create_task(monitor_idle(), name="persistent-idle-monitor")
    try:
        await shutdown.wait()
        return 0
    finally:
        monitor.cancel()
        await asyncio.gather(monitor, return_exceptions=True)
        server.close()
        await server.wait_closed()
        _remove_state_if_owned(port, token)
        await close_persistent_runtime()
        lock_stream.close()


def _idle_shutdown_due(
    *,
    served_request: bool,
    last_completed_at: float,
    idle_seconds: float,
    runtime_idle: bool,
    now: float | None = None,
) -> bool:
    if not served_request or not runtime_idle:
        return False
    if now is None:
        import time

        now = time.monotonic()
    return now - last_completed_at >= max(0.0, float(idle_seconds))


def _recv_exact(connection, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise EOFError("persistent connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


def _recv_request(connection, token: bytes) -> dict[str, Any] | None:
    import struct

    if _recv_exact(connection, 4) != _REQUEST_MAGIC or _recv_exact(connection, len(token)) != token:
        return None
    flags, cwd_size, argc = struct.unpack("!III", _recv_exact(connection, 12))
    if cwd_size > _MAX_FIELD_BYTES or argc > 4096:
        return None
    cwd = _recv_exact(connection, cwd_size).decode("utf-8", "surrogatepass")
    argv = []
    for _ in range(argc):
        size = struct.unpack("!I", _recv_exact(connection, 4))[0]
        if size > _MAX_FIELD_BYTES:
            return None
        argv.append(_recv_exact(connection, size).decode("utf-8", "surrogatepass"))
    return {
        "cwd": cwd,
        "argv": argv,
        "shutdown": bool(flags & 1),
        "stdout_tty": bool(flags & 2),
        "stdin_tty": bool(flags & 4),
    }


async def _recv_request_async(reader: asyncio.StreamReader, token: bytes) -> dict[str, Any] | None:
    if await reader.readexactly(4) != _REQUEST_MAGIC or await reader.readexactly(len(token)) != token:
        return None
    flags, cwd_size, argc = struct.unpack("!III", await reader.readexactly(12))
    if cwd_size > _MAX_FIELD_BYTES or argc > 4096:
        return None
    cwd = (await reader.readexactly(cwd_size)).decode("utf-8", "surrogatepass")
    argv = []
    for _ in range(argc):
        size = struct.unpack("!I", await reader.readexactly(4))[0]
        if size > _MAX_FIELD_BYTES:
            return None
        argv.append((await reader.readexactly(size)).decode("utf-8", "surrogatepass"))
    return {
        "cwd": cwd,
        "argv": argv,
        "shutdown": bool(flags & 1),
        "stdout_tty": bool(flags & 2),
        "stdin_tty": bool(flags & 4),
    }


def _recv_stream(connection, input_stream=None) -> dict[str, Any]:
    import struct

    input_stream = sys.stdin if input_stream is None else input_stream
    while True:
        kind, size = struct.unpack("!BI", _recv_exact(connection, 5))
        if size > _MAX_FIELD_BYTES:
            raise ValueError("persistent stream frame is too large")
        payload = _recv_exact(connection, size)
        if kind == 0:
            if size != 4:
                raise ValueError("invalid persistent final frame")
            return {"exit_code": struct.unpack("!i", payload)[0], "stdout": "", "stderr": ""}
        if kind == 3:
            line = input_stream.readline() if input_stream is not None else ""
            encoded = line.encode("utf-8", "surrogatepass")
            connection.sendall(struct.pack("!I", len(encoded)) + encoded)
        else:
            stream = sys.stdout if kind == 1 else sys.stderr
            stream.write(payload.decode("utf-8", "replace"))
            stream.flush()


class _AsyncConnectionTextStream:
    encoding = "utf-8"
    errors = "replace"

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        queue: asyncio.Queue,
        kind: int,
        *,
        is_tty: bool = False,
        terminal_columns: int | None = None,
    ):
        self.loop = loop
        self.queue = queue
        self.kind = kind
        self._is_tty = is_tty
        self.supports_terminal_updates = is_tty
        self.terminal_columns = terminal_columns

    def write(self, text: str) -> int:
        value = str(text)
        data = value.encode("utf-8", "surrogatepass")
        if data:
            frame = struct.pack("!BI", self.kind, len(data)) + data
            self.loop.call_soon_threadsafe(self.queue.put_nowait, frame)
        return len(value)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return self._is_tty


async def _execute_streaming_request_async(
    payload: dict[str, Any],
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> int:
    from sunpack.cli.cli import async_main

    loop = asyncio.get_running_loop()
    output_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
    write_lock = asyncio.Lock()

    async def send_frame(frame: bytes) -> None:
        async with write_lock:
            writer.write(frame)
            await writer.drain()

    async def pump_output() -> None:
        while True:
            frame = await output_queue.get()
            try:
                if frame is None:
                    return
                await send_frame(frame)
            finally:
                output_queue.task_done()

    async def read_input(prompt: str = "") -> str:
        if prompt:
            stdout.write(prompt)
        await asyncio.sleep(0)
        await output_queue.join()
        await send_frame(struct.pack("!BI", 3, 0))
        size = struct.unpack("!I", await reader.readexactly(4))[0]
        if size > _MAX_FIELD_BYTES:
            raise ValueError("persistent input frame is too large")
        return (await reader.readexactly(size)).decode("utf-8", "replace")

    argv = []
    terminal_columns = None
    for item in payload.get("argv") or []:
        value = str(item)
        if value.startswith(_TERMINAL_COLUMNS_ARG):
            try:
                terminal_columns = max(20, min(1000, int(value[len(_TERMINAL_COLUMNS_ARG):])))
            except ValueError:
                terminal_columns = None
            continue
        argv.append(value)

    stdout = _AsyncConnectionTextStream(
        loop,
        output_queue,
        1,
        is_tty=bool(payload.get("stdout_tty")),
        terminal_columns=terminal_columns,
    )
    stderr = _AsyncConnectionTextStream(loop, output_queue, 2, is_tty=False)
    pump = asyncio.create_task(pump_output(), name="persistent-output-pump")
    try:
        return int(
            await async_main(
                argv,
                cwd=str(payload.get("cwd") or runtime_working_directory()),
                stdout=stdout,
                stderr=stderr,
                input_reader=read_input,
            )
            or 0
        )
    except BaseException as exc:
        print(I18nContext(load_cli_language_from_config()).t("cli.persistent_request_failed", error=exc), file=stderr)
        return 1
    finally:
        await asyncio.sleep(0)
        await output_queue.join()
        await output_queue.put(None)
        await pump


def _write_state(port: int, token: bytes) -> None:
    path = state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.{os.getpid()}.tmp"
    with open(temporary, "w", encoding="ascii", newline="\n") as stream:
        stream.write(f"{port}\n{token.hex()}\n")
    os.replace(temporary, path)


def _remove_state_if_owned(port: int, token: bytes) -> bool:
    path = state_path()
    try:
        with open(path, "r", encoding="ascii") as stream:
            port_text, token_hex = stream.read().splitlines()[:2]
        if int(port_text) != int(port) or bytes.fromhex(token_hex) != token:
            return False
        os.remove(path)
        return True
    except (FileNotFoundError, OSError, ValueError):
        return False


def _acquire_server_lock():
    import msvcrt

    path = state_path() + ".lock"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    stream = open(path, "a+b")
    if stream.tell() == 0:
        stream.write(b"0")
        stream.flush()
    stream.seek(0)
    try:
        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        stream.close()
        return None
    return stream
