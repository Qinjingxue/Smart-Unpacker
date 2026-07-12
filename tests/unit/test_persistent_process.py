import io
import os
import socket
import threading

from sunpack.cli import persistent_process


def test_streaming_execute_restores_cwd_and_forwards_output(tmp_path):
    original = os.getcwd()
    server, client = socket.socketpair()

    def fake_main(argv):
        print(f"cwd={os.getcwd()}")
        print("warning", file=__import__("sys").stderr)
        assert argv == ["config", "validate"]
        return 7

    try:
        exit_code = persistent_process._execute_streaming_request(
            fake_main,
            {"cwd": str(tmp_path), "argv": ["config", "validate"]},
            server,
        )
        server.shutdown(socket.SHUT_WR)
        wire = bytearray()
        while chunk := client.recv(4096):
            wire.extend(chunk)
    finally:
        server.close()
        client.close()

    assert exit_code == 7
    assert f"cwd={tmp_path}".encode() in wire
    assert b"warning" in wire and wire.endswith(b"\n")
    assert os.getcwd() == original


def test_submit_request_strips_server_side_pause(monkeypatch):
    captured = {}

    def fake_send(payload):
        captured.update(payload)
        return {"exit_code": 0, "stdout": "done\n", "stderr": ""}

    monkeypatch.setattr(persistent_process, "_send_or_start", fake_send)
    monkeypatch.setattr(persistent_process.sys, "stdout", io.StringIO())
    monkeypatch.setattr(persistent_process.sys.stdin, "isatty", lambda: False)

    assert persistent_process.submit_request(["extract", "sample.zip", "--pause"]) == 0
    assert "--pause" not in captured["argv"]
    assert "--no-pause" in captured["argv"]
    assert persistent_process.sys.stdout.getvalue() == "done\n"


def test_extract_is_submitted_to_persistent_server_by_default(monkeypatch):
    from sunpack.cli import cli
    from sunpack.cli import persistent_runtime

    submitted = []
    monkeypatch.setattr(persistent_runtime, "server_runtime_active", lambda: False)
    monkeypatch.setattr(persistent_process, "submit_request", lambda argv: submitted.append(argv) or 6)

    assert cli.main(["extract", "sample.zip"]) == 6
    assert submitted == [["extract", "sample.zip"]]


def test_extract_help_stays_local_and_does_not_start_server(monkeypatch):
    from sunpack.cli import cli

    monkeypatch.setattr(persistent_process, "submit_request", lambda _argv: (_ for _ in ()).throw(AssertionError()))

    assert cli.main(["extract", "--help"]) == 0


def test_streaming_request_forwards_output_before_final_result(monkeypatch):
    server, client = socket.socketpair()
    output = io.StringIO()
    error = io.StringIO()
    monkeypatch.setattr(persistent_process.sys, "stdout", output)
    monkeypatch.setattr(persistent_process.sys, "stderr", error)

    def send_frames():
        import struct

        server.sendall(struct.pack("!BI", 1, 4) + b"25%\n")
        server.sendall(struct.pack("!BI", 2, 5) + b"warn\n")
        server.sendall(struct.pack("!BIi", 0, 4, 7))
        server.close()

    thread = threading.Thread(target=send_frames)
    thread.start()
    try:
        response = persistent_process._recv_stream(client)
    finally:
        client.close()
        thread.join()

    assert response["exit_code"] == 7
    assert output.getvalue() == "25%\n"
    assert error.getvalue() == "warn\n"


def test_connection_stream_preserves_client_tty_capability():
    server, client = socket.socketpair()
    try:
        stream = persistent_process._ConnectionTextStream(server, 1, is_tty=True)
        assert stream.isatty()
        assert stream.supports_terminal_updates
        assert stream.write("progress") == 8
        import struct

        kind, size = struct.unpack("!BI", persistent_process._recv_exact(client, 5))
        assert (kind, size) == (1, 8)
        assert persistent_process._recv_exact(client, size) == b"progress"
    finally:
        server.close()
        client.close()


def test_streaming_request_round_trips_interactive_input():
    server, client = socket.socketpair()
    result = {}

    def execute():
        result["code"] = persistent_process._execute_streaming_request(
            lambda _argv: 0 if input("password: ") == "secret" else 1,
            {"argv": ["extract"], "stdin_tty": True},
            server,
        )
        import struct

        server.sendall(struct.pack("!BIi", 0, 4, result["code"]))
        server.close()

    thread = threading.Thread(target=execute)
    thread.start()
    try:
        response = persistent_process._recv_stream(client, io.StringIO("secret\n"))
    finally:
        client.close()
        thread.join()

    assert response["exit_code"] == 0


def test_shutdown_does_not_start_a_missing_server(monkeypatch):
    monkeypatch.setattr(persistent_process, "_try_send", lambda payload: None)

    response = persistent_process._send_or_start({"shutdown": True})

    assert response["exit_code"] == 0


def test_persistent_runtime_reuses_engine_for_request_only_config(monkeypatch):
    from sunpack.cli import persistent_runtime

    events = []

    class FakeEngine:
        def __init__(self, config):
            events.append(("init", config["output"]["root"]))

        def start(self):
            events.append(("start",))
            return self

        def reconfigure_request(self, config):
            events.append(("reconfigure", config["output"]["root"]))

        def close(self, *, graceful=True):
            events.append(("close", graceful))

    monkeypatch.setattr(persistent_runtime, "PipelineEngine", FakeEngine)
    monkeypatch.setattr(persistent_runtime, "config_cache_token", lambda: ("same",))
    persistent_runtime.enable_persistent_runtime()
    first = {"output": {"root": "one", "common_root": "a"}, "cli": {"quiet": True}}
    second = {"output": {"root": "two", "common_root": "b"}, "cli": {"quiet": False}}
    try:
        with persistent_runtime.pipeline_engine(first) as first_engine:
            pass
        with persistent_runtime.pipeline_engine(second) as second_engine:
            pass
        assert first_engine is second_engine
        assert events[:2] == [("init", "one"), ("start",)]
        assert ("reconfigure", "two") in events
    finally:
        persistent_runtime.close_persistent_runtime()
