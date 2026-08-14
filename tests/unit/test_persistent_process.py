import io
import asyncio
import os
import socket
import struct
import threading

from sunpack.cli import persistent_process


class _AsyncWriter:
    def __init__(self, reader=None, input_line: bytes = b""):
        self.wire = bytearray()
        self.reader = reader
        self.input_line = input_line

    def write(self, data):
        self.wire.extend(data)
        if self.reader is not None and data[:1] == b"\x03":
            self.reader.feed_data(struct.pack("!I", len(self.input_line)) + self.input_line)

    async def drain(self):
        pass


def test_streaming_execute_uses_request_local_cwd_and_streams(tmp_path, monkeypatch):
    from sunpack.cli import cli

    async def fake_main(argv, **context):
        assert argv == ["config", "validate"]
        assert context["cwd"] == str(tmp_path)
        print(f"cwd={context['cwd']}", file=context["stdout"])
        print("warning", file=context["stderr"])
        return 7

    monkeypatch.setattr(cli, "async_main", fake_main)

    async def scenario():
        writer = _AsyncWriter()
        code = await persistent_process._execute_streaming_request_async(
            {"cwd": str(tmp_path), "argv": ["config", "validate"]},
            asyncio.StreamReader(),
            writer,
        )
        return code, bytes(writer.wire)

    exit_code, wire = asyncio.run(scenario())
    assert exit_code == 7
    assert f"cwd={tmp_path}".encode() in wire
    assert b"warning" in wire


def test_submit_request_strips_server_side_pause(tmp_path, monkeypatch):
    captured = {}
    request_cwd = os.getcwd()

    def fake_send(payload):
        captured.update(payload)
        captured["client_cwd"] = os.getcwd()
        return {"exit_code": 0, "stdout": "done\n", "stderr": ""}

    monkeypatch.setattr(persistent_process, "_send_or_start", fake_send)
    monkeypatch.setattr(persistent_process, "runtime_working_directory", lambda: str(tmp_path))
    monkeypatch.setattr(persistent_process.sys, "stdout", io.StringIO())
    monkeypatch.setattr(persistent_process.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(persistent_process, "_client_supports_terminal_updates", lambda _stream: True)
    monkeypatch.setattr(persistent_process, "_client_terminal_columns", lambda _stream: 93)

    assert persistent_process.submit_request(["extract", "sample.zip", "--pause"]) == 0
    assert "--pause" not in captured["argv"]
    assert "--no-pause" in captured["argv"]
    assert captured["cwd"] == request_cwd
    assert captured["client_cwd"] == request_cwd
    assert captured["stdout_tty"] is True
    assert captured["stdout_columns"] == 93
    assert os.getcwd() == request_cwd
    assert persistent_process.sys.stdout.getvalue() == "done\n"


def test_submit_request_does_not_claim_unverified_terminal_updates(tmp_path, monkeypatch):
    captured = {}

    def fake_send(payload):
        captured.update(payload)
        return {"exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(persistent_process, "_send_or_start", fake_send)
    monkeypatch.setattr(persistent_process, "_client_supports_terminal_updates", lambda _stream: False)
    monkeypatch.setattr(persistent_process.sys.stdin, "isatty", lambda: False)

    assert persistent_process.submit_request(["extract", str(tmp_path / "sample.zip")]) == 0
    assert captured["stdout_tty"] is False


def test_extract_is_submitted_to_persistent_server_by_default(monkeypatch):
    from sunpack.cli import cli
    from sunpack.cli import runtime_state

    submitted = []
    monkeypatch.setattr(runtime_state, "server_runtime_active", lambda: False)
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
    async def scenario():
        queue = asyncio.Queue()
        stream = persistent_process._AsyncConnectionTextStream(
            asyncio.get_running_loop(), queue, 1, is_tty=True, terminal_columns=93
        )
        assert stream.isatty()
        assert stream.supports_terminal_updates
        assert stream.terminal_columns == 93
        assert stream.write("progress") == 8
        await asyncio.sleep(0)
        frame = await queue.get()
        kind, size = struct.unpack("!BI", frame[:5])
        assert (kind, size) == (1, 8)
        assert frame[5:] == b"progress"
    asyncio.run(scenario())


def test_streaming_request_strips_terminal_columns_metadata(monkeypatch):
    from sunpack.cli import cli

    async def fake_main(argv, **context):
        assert argv == ["extract", "sample.zip"]
        assert context["stdout"].terminal_columns == 79
        return 0

    monkeypatch.setattr(cli, "async_main", fake_main)

    async def scenario():
        return await persistent_process._execute_streaming_request_async(
            {
                "argv": ["extract", "sample.zip", "--_sunpack-terminal-columns=79"],
                "stdout_tty": True,
            },
            asyncio.StreamReader(),
            _AsyncWriter(),
        )

    assert asyncio.run(scenario()) == 0


def test_streaming_request_round_trips_interactive_input(monkeypatch):
    from sunpack.cli import cli

    async def fake_main(_argv, **context):
        return 0 if (await context["input_reader"]("password: ")).strip() == "secret" else 1

    monkeypatch.setattr(cli, "async_main", fake_main)

    async def scenario():
        reader = asyncio.StreamReader()
        writer = _AsyncWriter(reader, b"secret\n")
        return await persistent_process._execute_streaming_request_async(
            {"argv": ["extract"], "stdin_tty": True}, reader, writer
        )

    assert asyncio.run(scenario()) == 0


def test_shutdown_does_not_start_a_missing_server(monkeypatch):
    monkeypatch.setattr(persistent_process, "_try_send", lambda payload: None)

    response = persistent_process._send_or_start({"shutdown": True})

    assert response["exit_code"] == 0


def test_server_idle_shutdown_requires_completed_request_and_idle_runtime():
    assert not persistent_process._idle_shutdown_due(
        served_request=False,
        last_completed_at=10.0,
        idle_seconds=5.0,
        runtime_idle=True,
        now=20.0,
    )
    assert not persistent_process._idle_shutdown_due(
        served_request=True,
        last_completed_at=10.0,
        idle_seconds=5.0,
        runtime_idle=False,
        now=20.0,
    )
    assert not persistent_process._idle_shutdown_due(
        served_request=True,
        last_completed_at=10.0,
        idle_seconds=5.0,
        runtime_idle=True,
        now=14.9,
    )
    assert persistent_process._idle_shutdown_due(
        served_request=True,
        last_completed_at=10.0,
        idle_seconds=5.0,
        runtime_idle=True,
        now=15.0,
    )


def test_state_cleanup_only_removes_owned_server_state(tmp_path, monkeypatch):
    state = tmp_path / "runtime.state"
    token = b"a" * 32
    monkeypatch.setattr(persistent_process, "state_path", lambda: str(state))

    persistent_process._write_state(1234, token)
    assert not persistent_process._remove_state_if_owned(9999, token)
    assert state.exists()
    assert not persistent_process._remove_state_if_owned(1234, b"b" * 32)
    assert state.exists()
    assert persistent_process._remove_state_if_owned(1234, token)
    assert not state.exists()


def test_server_process_starts_in_neutral_working_directory(tmp_path, monkeypatch):
    captured = {}
    attempts = iter([None, {"exit_code": 0, "stdout": "", "stderr": ""}])

    monkeypatch.setattr(persistent_process, "_try_send", lambda _payload: next(attempts))
    monkeypatch.setattr(persistent_process, "runtime_working_directory", lambda: str(tmp_path))
    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: captured.update(kwargs))

    response = persistent_process._send_or_start({"argv": ["extract", "sample.zip"]})

    assert response["exit_code"] == 0
    assert captured["cwd"] == str(tmp_path)


def test_persistent_runtime_reuses_engine_for_request_only_config(monkeypatch):
    from sunpack.cli import persistent_runtime

    events = []

    class FakeEngine:
        def __init__(self, config):
            self.config = config
            events.append(("init", config["output"]["root"]))

        async def __aenter__(self):
            events.append(("start",))
            return self

        def is_idle(self):
            return True

        async def aclose(self, *, graceful=True):
            events.append(("close", graceful))

    monkeypatch.setattr(persistent_runtime, "PipelineEngine", FakeEngine)
    monkeypatch.setattr(persistent_runtime, "config_cache_token", lambda: ("same",))
    persistent_runtime.enable_persistent_runtime()
    first = {
        "output": {"root": "one", "common_root": "a"},
        "cli": {"quiet": True},
        "performance": {"persistent_server_idle_seconds": 3},
    }
    second = {
        "output": {"root": "two", "common_root": "b"},
        "cli": {"quiet": False},
        "performance": {"persistent_server_idle_seconds": 9},
    }
    async def scenario():
        await persistent_runtime.close_persistent_runtime()
        persistent_runtime.enable_persistent_runtime()
        async with persistent_runtime.pipeline_engine(first) as first_engine:
            pass
        async with persistent_runtime.pipeline_engine(second) as second_engine:
            pass
        assert first_engine is second_engine
        assert events[:2] == [("init", "one"), ("start",)]
        assert persistent_runtime.persistent_runtime_is_idle()
        assert persistent_runtime.persistent_server_idle_seconds() == 9
        await persistent_runtime.close_persistent_runtime()

    asyncio.run(scenario())
