from __future__ import annotations

import contextlib
import getpass
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


SERVER_ARG = "--persistent-server"
REUSE_ARG = "--reuse"
SHUTDOWN_ARG = "--persistent-shutdown"


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
    identity = f"{getpass.getuser()}|{Path(sys.executable).resolve().parent}".encode("utf-8", "surrogatepass")
    suffix = hashlib.sha256(identity).hexdigest()[:16]
    return rf"\\.\pipe\sunpack-batch-{suffix}"


def auth_key() -> bytes:
    seed = f"sunpack|{getpass.getuser()}|{Path(sys.executable).resolve().parent}".encode("utf-8", "surrogatepass")
    return hashlib.sha256(seed).digest()


def server_command() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, SERVER_ARG]
    entry = Path(__file__).resolve().parents[2] / "sunpack.py"
    if entry.is_file():
        return [sys.executable, str(entry), SERVER_ARG]
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
    from multiprocessing.connection import Client

    try:
        connection = Client(pipe_address(), family="AF_PIPE", authkey=auth_key())
    except (FileNotFoundError, ConnectionError, OSError):
        return None
    try:
        connection.send(payload)
        response = connection.recv()
        return response if isinstance(response, dict) else None
    except (EOFError, OSError):
        return None
    finally:
        connection.close()


def run_server() -> int:
    from multiprocessing.connection import Listener

    try:
        listener = Listener(pipe_address(), family="AF_PIPE", authkey=auth_key())
    except OSError:
        return 0
    from sunpack.cli.cli import main

    try:
        while True:
            connection = listener.accept()
            try:
                payload = connection.recv()
                if not isinstance(payload, dict):
                    connection.send({"exit_code": 2, "stdout": "", "stderr": "Invalid request.\n"})
                    continue
                if payload.get("shutdown"):
                    connection.send({"exit_code": 0, "stdout": "", "stderr": ""})
                    return 0
                connection.send(_execute_request(main, payload))
            except (EOFError, OSError):
                continue
            finally:
                connection.close()
    finally:
        listener.close()


def _execute_request(main, payload: dict[str, Any]) -> dict[str, Any]:
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
