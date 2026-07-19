from pathlib import Path

from sunpack.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.coordinator.nested_extraction_policy import NestedExtractionPolicy
from sunpack.coordinator.scan_session import DetectionScanSession
from sunpack.coordinator.task_scan import direct_file_task


def _config(**overrides):
    return {
        "nested_extraction_policy": {
            "enabled": True,
            "allow_initial_root_archives": True,
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
        direct_initial=False,
    )


def test_initial_archive_directly_under_selected_directory_is_allowed(tmp_path):
    archive = tmp_path / "wanted.rar"
    entries = [
        FileEntry(archive, False, 10),
        *[FileEntry(tmp_path / f"game_{index}", True) for index in range(50)],
    ]

    result = _authorize(tmp_path, entries, [archive], round_index=1)

    assert [task.main_path for task in result.allowed_tasks] == [str(archive)]
    assert result.skipped == []


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
