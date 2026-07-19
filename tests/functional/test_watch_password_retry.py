from __future__ import annotations

import subprocess
import uuid

import pytest

import sunpack.passwords.internal.builtin as builtin_module
import sunpack.passwords.internal.clipboard_monitor as clipboard_monitor_module
from sunpack.config.loader import load_config
from sunpack.coordinator.engine import PipelineEngine
from sunpack.filesystem.watcher.scheduler import WatchScheduler
from tests.helpers.tool_config import get_test_tools


@pytest.mark.parametrize("source", ["directory", "watch_clipboard"])
def test_watch_retries_real_encrypted_zip_after_password_source_update(tmp_path, monkeypatch, source):
    seven_zip = get_test_tools().get("seven_zip")
    if seven_zip is None or not seven_zip.is_file():
        pytest.skip("7z.exe is required for encrypted watch retry coverage")

    watch_root = tmp_path / "watch"
    source_dir = tmp_path / "source"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    source_dir.mkdir()
    output_root.mkdir()
    payload = "watch password retry payload"
    (source_dir / "payload.txt").write_text(payload, encoding="utf-8")
    # A per-test password prevents a prior run, clipboard entry, or configured
    # password source from turning the intended first failure into a success.
    password = f"watch-retry-secret-{uuid.uuid4().hex}"
    archive = watch_root / "encrypted.zip"
    completed = subprocess.run(
        [
            str(seven_zip),
            "a",
            "-tzip",
            f"-p{password}",
            "-mem=ZipCrypto",
            str(archive),
            "payload.txt",
            "-y",
        ],
        cwd=str(source_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        pytest.skip(f"encrypted ZIP fixture could not be created: {completed.stderr or completed.stdout}")

    builtin_path = tmp_path / "builtin_passwords.txt"
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    directory_password_file = watch_root / ".sunpack-passwords.txt"
    if source == "directory":
        directory_password_file.write_text("wrong-password\n", encoding="utf-8")

    config = load_config()
    config["cli"] = {**(config.get("cli") or {}), "quiet": True}
    config["filesystem"] = {**config.get("filesystem", {}), "scan_filters": []}
    config["post_extract"] = {**config.get("post_extract", {}), "archive_cleanup_mode": "keep"}
    config["watch"] = {
        **config.get("watch", {}),
        "clipboard_monitor_enabled": source == "watch_clipboard",
        "password_retry_debounce_seconds": 0,
    }
    engine = PipelineEngine(config).start()
    watcher = WatchScheduler(
        config,
        [str(watch_root)],
        out_dir=str(output_root),
        state_path=str(tmp_path / "state.json"),
        quiet_seconds=0,
        initial_scan=False,
        pipeline_engine=engine,
    )
    try:
        watcher.enqueue(str(archive))
        first = watcher.run_once()
        assert first.failed == 1, first
        first_entries = list(watcher.state.entries.values())
        assert len(first_entries) == 1, first_entries
        assert first_entries[0].status == "failed_password"

        if source == "directory":
            directory_password_file.write_text(password + "\n", encoding="utf-8")
            watcher.notify_password_table_changed(str(directory_password_file))
        else:
            monkeypatch.setattr(clipboard_monitor_module, "read_clipboard_passwords", lambda: [password])
            watcher._clipboard_monitor._handle_clipboard_update()
        second = watcher.run_once()
        extracted = list(output_root.rglob("payload.txt"))
    finally:
        engine.close()

    assert second.succeeded == 1
    assert not watcher.state.entries
    assert len(extracted) == 1
    assert extracted[0].read_text(encoding="utf-8") == payload
    if source == "watch_clipboard":
        assert password in builtin_path.read_text(encoding="utf-8")
