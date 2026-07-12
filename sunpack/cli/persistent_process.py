from __future__ import annotations

import os
import sys


SERVER_ARG = "--persistent-server"
SHUTDOWN_ARG = "--persistent-shutdown"
_REQUEST_MAGIC = b"SPK1"
_STREAM_MAGIC = b"SPS1"
_MAX_FIELD_BYTES = 16 * 1024 * 1024


def handle_early_argv(argv: list[str]) -> int | None:
    if not argv:
        return None
    if argv[0] == SERVER_ARG:
        return run_server()
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
    request_argv = list(argv)
    pause = "--pause" in request_argv
    if pause:
        request_argv = [item for item in request_argv if item != "--pause"]
        if "--no-pause" not in request_argv:
            request_argv.append("--no-pause")
    payload = {
        "argv": request_argv,
        "cwd": os.getcwd(),
        "shutdown": bool(shutdown),
        "stdout_tty": bool(sys.stdout is not None and sys.stdout.isatty()),
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
            input("Press Enter to continue...")
        except (EOFError, KeyboardInterrupt):
            pass
    return int(response.get("exit_code", 1))


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
    )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        response = _try_send(payload)
        if response is not None:
            return response
        time.sleep(0.025)
    return {"exit_code": 1, "stdout": "", "stderr": "SunPack persistent process did not start in time.\n"}


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
        argv = [str(item).encode("utf-8", "surrogatepass") for item in payload.get("argv") or []]
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


def run_server() -> int:
    import secrets
    import socket
    import struct

    lock_stream = _acquire_server_lock()
    if lock_stream is None:
        return 0
    token = secrets.token_bytes(32)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    from sunpack.cli.cli import main
    from sunpack.cli.persistent_runtime import close_persistent_runtime, enable_persistent_runtime

    enable_persistent_runtime()
    _write_state(listener.getsockname()[1], token)

    try:
        while True:
            connection, _ = listener.accept()
            try:
                payload = _recv_request(connection, token)
                if payload is None:
                    continue
                connection.sendall(_STREAM_MAGIC)
                if payload.get("shutdown"):
                    try:
                        os.remove(state_path())
                    except OSError:
                        pass
                    lock_stream.close()
                    lock_stream = None
                    connection.sendall(struct.pack("!BIi", 0, 4, 0))
                    return 0
                exit_code = _execute_streaming_request(main, payload, connection)
                connection.sendall(struct.pack("!BIi", 0, 4, exit_code))
            except (EOFError, OSError):
                continue
            finally:
                connection.close()
    finally:
        close_persistent_runtime()
        listener.close()
        if lock_stream is not None:
            lock_stream.close()
        try:
            os.remove(state_path())
        except OSError:
            pass


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


class _ConnectionTextStream:
    encoding = "utf-8"
    errors = "replace"

    def __init__(self, connection, kind: int, *, is_tty: bool = False):
        self.connection = connection
        self.kind = kind
        self._is_tty = is_tty
        self.supports_terminal_updates = is_tty

    def write(self, text: str) -> int:
        import struct

        value = str(text)
        data = value.encode("utf-8", "surrogatepass")
        if data:
            self.connection.sendall(struct.pack("!BI", self.kind, len(data)) + data)
        return len(value)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return self._is_tty


class _ConnectionInputStream:
    encoding = "utf-8"
    errors = "replace"

    def __init__(self, connection, *, is_tty: bool = False):
        self.connection = connection
        self._is_tty = is_tty

    def readline(self, _size: int = -1) -> str:
        import struct

        self.connection.sendall(struct.pack("!BI", 3, 0))
        size = struct.unpack("!I", _recv_exact(self.connection, 4))[0]
        if size > _MAX_FIELD_BYTES:
            raise ValueError("persistent input frame is too large")
        return _recv_exact(self.connection, size).decode("utf-8", "replace")

    def isatty(self) -> bool:
        return self._is_tty


def _execute_streaming_request(main, payload: dict[str, Any], connection) -> int:
    import contextlib

    stdout = _ConnectionTextStream(connection, 1, is_tty=bool(payload.get("stdout_tty")))
    stderr = _ConnectionTextStream(connection, 2, is_tty=False)
    stdin = _ConnectionInputStream(connection, is_tty=bool(payload.get("stdin_tty")))
    previous_cwd = os.getcwd()
    previous_stdin = sys.stdin
    try:
        os.chdir(str(payload.get("cwd") or previous_cwd))
        argv = [str(item) for item in payload.get("argv") or []]
        sys.stdin = stdin
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            return int(main(argv) or 0)
    except BaseException as exc:
        print(f"SunPack persistent request failed: {exc}", file=stderr)
        return 1
    finally:
        sys.stdin = previous_stdin
        os.chdir(previous_cwd)


def _write_state(port: int, token: bytes) -> None:
    path = state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = f"{path}.{os.getpid()}.tmp"
    with open(temporary, "w", encoding="ascii", newline="\n") as stream:
        stream.write(f"{port}\n{token.hex()}\n")
    os.replace(temporary, path)


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
