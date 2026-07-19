from pathlib import Path

import pytest

from sunpack.config.fields.coordinator import normalize_nested_extraction_policy
from sunpack.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.coordinator.nested_extraction_policy import NestedExtractionPolicy
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.coordinator.task_scan import direct_file_task


def _config(**overrides):
    return {
        "nested_extraction_policy": {
            "enabled": True,
            "minimum_archive_byte_ratio": 0.5,
            "maximum_other_projects": 2,
            **overrides,
        }
    }


def _authorize(root: Path, entries: list[FileEntry], archives: list[Path], *, round_index=2):
    snapshot = DirectorySnapshot.from_entries(root, entries, raw_entries=entries)
    session = DetectionScanSession(config=_config())
    session.prime_snapshot(str(root), snapshot)
    tasks = [direct_file_task(str(path)) for path in archives]
    return NestedExtractionPolicy(_config()).authorize_batch(
        tasks,
        [str(root)],
        session,
        round_index=round_index,
    )


def test_first_round_bypasses_policy_for_the_user_requested_scope(tmp_path):
    wrapper = tmp_path / "game"
    archive = wrapper / "wanted.rar"
    task = direct_file_task(str(archive))
    result = NestedExtractionPolicy(_config()).authorize_batch(
        [task],
        [str(tmp_path)],
        None,
        round_index=1,
    )

    assert [task.main_path for task in result.allowed_tasks] == [str(archive)]
    assert result.skipped == []


def test_removed_initial_root_setting_is_rejected():
    with pytest.raises(ValueError, match="allow_initial_root_archives"):
        normalize_nested_extraction_policy({"allow_initial_root_archives": True})


def test_normal_detection_session_does_not_collect_raw_snapshots():
    assert DetectionScanSession(config=_config()).include_raw_snapshots is False


def test_second_round_root_child_has_no_special_privilege(tmp_path):
    archive = tmp_path / "nested.zip"
    entries = [
        FileEntry(archive, False, 10),
        *[FileEntry(tmp_path / f"asset_{index}", False, 100) for index in range(10)],
    ]

    result = _authorize(tmp_path, entries, [archive], round_index=2)

    assert result.allowed_tasks == []
    assert result.skipped[0]["reason"] == "nested_context_not_archive_dominant"


def test_nested_archive_mixed_with_game_payload_is_skipped(tmp_path):
    wrapper = tmp_path / "dlc003_rocket_launcher_unit_pack"
    archive = wrapper / "dlc003.zip"
    entries = [FileEntry(wrapper, True)]
    entries.extend(FileEntry(wrapper / f"asset_{index}.bin", False, 270_000) for index in range(28))
    entries.extend(FileEntry(wrapper / f"dir_{index}", True) for index in range(9))
    entries.append(FileEntry(archive, False, 2_461_198))

    result = _authorize(tmp_path, entries, [archive])

    assert result.allowed_tasks == []
    assert result.skipped[0]["reason"] == "nested_context_not_archive_dominant"
    assert result.skipped[0]["other_project_count"] == 37
    assert result.skipped[0]["collective_candidate_byte_ratio"] < 0.5


def test_nested_archive_dominating_its_semantic_subtree_is_allowed(tmp_path):
    wrapper = tmp_path / "wrapper"
    archive = wrapper / "inner.zip"
    entries = [
        FileEntry(wrapper, True),
        FileEntry(archive, False, 900),
        FileEntry(wrapper / "readme.txt", False, 100),
    ]

    result = _authorize(tmp_path, entries, [archive])

    assert [task.main_path for task in result.allowed_tasks] == [str(archive)]
    assert result.skipped == []


def test_candidates_in_same_scope_are_aggregated_once(tmp_path):
    wrapper = tmp_path / "archives"
    first = wrapper / "one.zip"
    second = wrapper / "two.zip"
    entries = [
        FileEntry(wrapper, True),
        FileEntry(first, False, 300),
        FileEntry(second, False, 300),
        FileEntry(wrapper / "payload.dat", False, 400),
    ]

    result = _authorize(tmp_path, entries, [first, second])

    assert [task.main_path for task in result.allowed_tasks] == [str(first), str(second)]
    assert result.skipped == []
