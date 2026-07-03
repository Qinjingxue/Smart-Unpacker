from __future__ import annotations

import os
import sys


SERVER_ARG = "--persistent-server"
REUSE_ARG = "--reuse"
SHUTDOWN_ARG = "--persistent-shutdown"
_REQUEST_MAGIC = b"SPK1"
_RESPONSE_MAGIC = b"SPR1"
_MAX_FIELD_BYTES = 16 * 1024 * 1024


def handle_early_argv(argv: list[str]) -> int | None:
    if not argv:
        return None
    if argv[0] == SERVER_ARG:
        return run_server()
    if argv[0] == SHUTDOWN_ARG:
        return submit_request([], shutdown=True)
    if argv[0] == REUSE_ARG:
        return submit_request(argv[1:])
    return None


def pipe_address() -> str:
    import getpass
    import hashlib

    executable_dir = os.path.dirname(os.path.abspath(sys.executable))
    identity = f"{getpass.getuser()}|{executable_dir}".encode("utf-8", "surrogatepass")
    suffix = hashlib.sha256(identity).hexdigest()[:16]
    return rf"\\.\pipe\sunpack-batch-{suffix}"


def auth_key() -> bytes:
    import getpass
    import hashlib

    executable_dir = os.path.dirname(os.path.abspath(sys.executable))
    seed = f"sunpack|{getpass.getuser()}|{executable_dir}".encode("utf-8", "surrogatepass")
    return hashlib.sha256(seed).digest()


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
        flags = 1 if payload.get("shutdown") else 0
        body = [token, struct.pack("!III", flags, len(cwd), len(argv)), cwd]
        for item in argv:
            body.extend((struct.pack("!I", len(item)), item))
        connection.sendall(_REQUEST_MAGIC + b"".join(body))
        header = _recv_exact(connection, 16)
        if header[:4] != _RESPONSE_MAGIC:
            return None
        exit_code, stdout_size, stderr_size = struct.unpack("!iII", header[4:])
        if stdout_size > _MAX_FIELD_BYTES or stderr_size > _MAX_FIELD_BYTES:
            return None
        stdout = _recv_exact(connection, stdout_size).decode("utf-8", "replace")
        stderr = _recv_exact(connection, stderr_size).decode("utf-8", "replace")
        return {"exit_code": exit_code, "stdout": stdout, "stderr": stderr}
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
                    _send_response(connection, {"exit_code": 2, "stdout": "", "stderr": "Invalid request.\n"})
                    continue
                if payload.get("shutdown"):
                    try:
                        os.remove(state_path())
                    except OSError:
                        pass
                    lock_stream.close()
                    lock_stream = None
                    _send_response(connection, {"exit_code": 0, "stdout": "", "stderr": ""})
                    return 0
                _send_response(connection, _execute_request(main, payload))
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
    return {"cwd": cwd, "argv": argv, "shutdown": bool(flags & 1)}


def _send_response(connection, response: dict[str, Any]) -> None:
    import struct

    stdout = str(response.get("stdout") or "").encode("utf-8", "surrogatepass")
    stderr = str(response.get("stderr") or "").encode("utf-8", "surrogatepass")
    header = _RESPONSE_MAGIC + struct.pack("!iII", int(response.get("exit_code", 1)), len(stdout), len(stderr))
    connection.sendall(header + stdout + stderr)


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


def _execute_request(main, payload: dict[str, Any]) -> dict[str, Any]:
    import contextlib
    import io

    stdout = io.StringIO()
    stderr = io.StringIO()
    previous_cwd = os.getcwd()
    try:
        cwd = str(payload.get("cwd") or previous_cwd)
        os.chdir(cwd)
        argv = [str(item) for item in payload.get("argv") or []]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = int(main(argv) or 0)
    except BaseException as exc:
        exit_code = 1
        print(f"SunPack persistent request failed: {exc}", file=stderr)
    finally:
        os.chdir(previous_cwd)
    return {"exit_code": exit_code, "stdout": stdout.getvalue(), "stderr": stderr.getvalue()}
