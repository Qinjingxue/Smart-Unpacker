from sunpack.filesystem.watcher.group_models import (
    BLOCKER_PASSWORD,
    WatchGroupSnapshot,
    WatchGroupState,
)


def _snapshot(fingerprint: str) -> WatchGroupSnapshot:
    return WatchGroupSnapshot(
        group_id="group",
        directory="/downloads",
        logical_name="archive",
        split_family="7z_numbered",
        head_path="/downloads/archive.7z.001",
        member_paths=("/downloads/archive.7z.001",),
        fingerprint=fingerprint,
        complete=None,
    )


def test_password_blocker_retries_when_split_group_input_changes():
    state = WatchGroupState(
        group_id="group",
        directory="/downloads",
        logical_name="archive",
        split_family="7z_numbered",
        head_path="/downloads/archive.7z.001",
        blockers=[BLOCKER_PASSWORD],
        last_attempted_fingerprint="old",
        password_generation=4,
    )

    assert state.retry_ready(_snapshot("new"), password_generation=4) is True
    assert state.retry_ready(_snapshot("old"), password_generation=4) is False
    assert state.retry_ready(_snapshot("old"), password_generation=5) is True
