from __future__ import annotations

import zipfile
from pathlib import Path

from sunpack.contracts.failures import FailureKind
from tests.helpers.real_archives import (
    ArchiveFixtureFactory,
    create_encrypted_zip_archive,
)
from tests.real.plan1_real_archives.plan1_support import run_plan1_pipeline
from tests.real.plan7_watch_downloads.plan7_support import (
    arrive_slowly,
    drive_watch_until,
    start_watch,
)


FACTORY = ArchiveFixtureFactory()
INNER_PASSWORD = "nested-inner-password-only-fixture"


def _write_outer_zip(path: Path, entries: list[tuple[str, bytes]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return path


def _nested_encrypted_outer(tmp_path: Path) -> Path:
    inner = create_encrypted_zip_archive(
        tmp_path / "fixtures",
        "nested-inner-encrypted",
        password=INNER_PASSWORD,
        encryption="ZipCrypto",
        payload_size=32 * 1024,
    )
    return _write_outer_zip(
        tmp_path / "archives" / "nested-outer-encrypted.zip",
        [
            ("outer-note.txt", b"outer is not encrypted"),
            ("nested-inner-encrypted.zip", inner.entry_path.read_bytes()),
        ],
    )


def _nested_missing_volume_outer(tmp_path: Path) -> Path:
    inner = FACTORY.create(
        tmp_path / "fixtures",
        "nested-inner-split",
        "7z",
        split=True,
        payload_size=620 * 1024,
        split_volume_size=80 * 1024,
    )
    parts = sorted(path for path in inner.archive_dir.iterdir() if path.is_file())
    assert len(parts) >= 3
    missing = next(
        path for path in parts if path.name.casefold().endswith(".002")
    )
    return _write_outer_zip(
        tmp_path / "archives" / "nested-outer-missing-volume.zip",
        [
            (path.name, path.read_bytes())
            for path in parts
            if path != missing
        ],
    )


def _failure_kinds(summary) -> list[FailureKind]:
    return [failure.kind for failure in list(summary.failures or [])]


def _settle_watch(harness):
    return drive_watch_until(
        harness.watcher,
        lambda: bool(harness.run_durations),
    )


def test_plan7_nested_inner_unknown_password_normal_mode(tmp_path, plan7_error):
    """外层无密码、内层密码未知时，普通模式只把内层报为密码错误。"""
    outer = _nested_encrypted_outer(tmp_path)
    summary = run_plan1_pipeline(outer, passwords=["definitely-wrong"])

    plan7_error.update({
        "case": "nested_outer_plain_inner_encrypted_normal",
        "outer": str(outer),
        "failure_kinds": [kind.value for kind in _failure_kinds(summary)],
        "failed_tasks": [str(item) for item in summary.failed_tasks],
    })
    assert summary.success_count == 1
    assert summary.partial_success_count == 0
    assert any(kind == FailureKind.WRONG_PASSWORD for kind in _failure_kinds(summary))
    assert any("nested-inner-encrypted.zip" in str(item) for item in summary.failed_tasks)


def test_plan7_nested_inner_missing_volume_normal_mode(tmp_path, plan7_error):
    """外层无密码、内层缺分卷时，普通模式只把内层报为缺分卷。"""
    outer = _nested_missing_volume_outer(tmp_path)
    summary = run_plan1_pipeline(outer, passwords=[])

    plan7_error.update({
        "case": "nested_outer_plain_inner_missing_volume_normal",
        "outer": str(outer),
        "failure_kinds": [kind.value for kind in _failure_kinds(summary)],
        "failed_tasks": [str(item) for item in summary.failed_tasks],
    })
    assert summary.success_count == 1
    assert summary.partial_success_count == 0
    assert any(kind == FailureKind.MISSING_VOLUME for kind in _failure_kinds(summary))
    assert any("nested-inner-split.7z.001" in str(item) for item in summary.failed_tasks)


def test_plan7_nested_inner_unknown_password_watch_is_password_blocked(
    tmp_path,
    plan7_error,
):
    """watch 模式下，内层未知密码应阻塞密码而不是缺分卷。"""
    outer = _nested_encrypted_outer(tmp_path)
    harness = start_watch(tmp_path, "nested-inner-password-watch", passwords=[])
    try:
        arrive_slowly(harness, outer)
        result = _settle_watch(harness)
        entry = next(iter(harness.watcher.state.entries.values()))
        plan7_error.update({
            "case": "nested_outer_plain_inner_encrypted_watch",
            "result": result.__dict__,
            "entry_status": entry.status,
            "failure_kind": entry.failure_kind,
            "blockers": list((entry.failure_payload or {}).get("blockers") or []),
        })
        assert result.failed == 1
        assert entry.status == "failed_password"
        assert entry.failure_kind == FailureKind.WRONG_PASSWORD.value
        assert (entry.failure_payload or {}).get("blockers") == ["password"]
    finally:
        harness.close()


def test_plan7_nested_inner_missing_volume_watch_is_not_outer_volume_blocked(
    tmp_path,
    plan7_error,
):
    """watch 模式下，内层缺分卷不得把外层 ZIP 放入缺分卷队列。"""
    outer = _nested_missing_volume_outer(tmp_path)
    harness = start_watch(tmp_path, "nested-inner-missing-volume-watch", passwords=[])
    try:
        arrive_slowly(harness, outer)
        result = _settle_watch(harness)
        events = (tmp_path / "nested-inner-missing-volume-watch" / "events.jsonl").read_text(
            encoding="utf-8"
        )
        plan7_error.update({
            "case": "nested_outer_plain_inner_missing_volume_watch",
            "result": result.__dict__,
            "state_entries": list(harness.watcher.state.entries),
            "state_groups": list(harness.watcher.state.groups),
            "failed_nested_missing_volume_logged": '"event":"failed_nested_missing_volume"' in events,
            "suspended_missing_volume_logged": '"event":"suspended_missing_volume"' in events,
        })
        assert result.failed == 1
        assert not harness.watcher.state.entries
        assert not harness.watcher.state.groups
        assert '"event":"failed_nested_missing_volume"' in events
        assert '"event":"suspended_missing_volume"' not in events
        assert any("嵌套压缩包内层分卷缺失" in error for error in result.errors)
        assert any("nested-inner-split.7z.001" in error for error in result.errors)
    finally:
        harness.close()
