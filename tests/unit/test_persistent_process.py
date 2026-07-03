import io
import os

from sunpack.cli import persistent_process


def test_execute_request_restores_cwd_and_captures_output(tmp_path):
    original = os.getcwd()

    def fake_main(argv):
        print(f"cwd={os.getcwd()}")
        print("warning", file=__import__("sys").stderr)
        assert argv == ["config", "validate"]
        return 7

    response = persistent_process._execute_request(
        fake_main,
        {"cwd": str(tmp_path), "argv": ["config", "validate"]},
    )

    assert response["exit_code"] == 7
    assert f"cwd={tmp_path}" in response["stdout"]
    assert response["stderr"] == "warning\n"
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


def test_pipe_address_is_stable_and_user_scoped():
    assert persistent_process.pipe_address() == persistent_process.pipe_address()
    assert persistent_process.pipe_address().startswith(r"\\.\pipe\sunpack-batch-")


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
