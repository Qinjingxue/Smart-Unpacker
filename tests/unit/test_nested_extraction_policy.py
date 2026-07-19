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
            "other_project_tolerance": 2,
            "byte_ratio_weight": 0.5,
            "minimum_authorization_score": 0.65,
            "minimum_archive_byte_ratio": 0.1,
            "hard_maximum_other_projects": 64,
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


def test_removed_or_rule_setting_is_rejected():
    with pytest.raises(ValueError, match="maximum_other_projects"):
        normalize_nested_extraction_policy({"maximum_other_projects": 2})


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
    assert result.skipped[0]["reason"] == "archive_byte_ratio_below_floor"


def test_nested_archive_mixed_with_game_payload_is_skipped(tmp_path):
    wrapper = tmp_path / "dlc003_rocket_launcher_unit_pack"
    archive = wrapper / "dlc003.zip"
    entries = [FileEntry(wrapper, True)]
    entries.extend(FileEntry(wrapper / f"asset_{index}.bin", False, 270_000) for index in range(28))
    entries.extend(FileEntry(wrapper / f"dir_{index}", True) for index in range(9))
    entries.append(FileEntry(archive, False, 2_461_198))

    result = _authorize(tmp_path, entries, [archive])

    assert result.allowed_tasks == []
    assert result.skipped[0]["reason"] == "authorization_score_below_threshold"
    assert result.skipped[0]["local_other_project_count"] == 37
    assert result.skipped[0]["local_candidate_byte_ratio"] < 0.5
    assert result.skipped[0]["authorization_score"] < 0.01


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


def test_large_game_resource_is_rejected_despite_dominating_bytes(tmp_path):
    archive = tmp_path / "resource.zip"
    entries = [FileEntry(archive, False, 90_000)]
    entries.extend(
        FileEntry(tmp_path / f"asset_{index}.bin", False, 100)
        for index in range(100)
    )

    result = _authorize(tmp_path, entries, [archive])

    assert result.allowed_tasks == []
    row = result.skipped[0]
    assert row["local_candidate_byte_ratio"] == pytest.approx(0.9)
    assert row["local_other_project_count"] == 100
    assert row["reason"] == "too_many_other_projects"


def test_repository_root_can_veto_clean_release_subdirectory(tmp_path):
    release = tmp_path / "release"
    source = tmp_path / "src"
    archive = release / "build.zip"
    entries = [
        FileEntry(release, True),
        FileEntry(source, True),
        FileEntry(archive, False, 90_000),
    ]
    entries.extend(
        FileEntry(source / f"module_{index}.py", False, 10)
        for index in range(100)
    )

    result = _authorize(tmp_path, entries, [archive])

    assert result.allowed_tasks == []
    row = result.skipped[0]
    assert row["local_authorization_score"] == pytest.approx(1.0)
    assert row["limiting_context"] == "root"
    assert row["root_foreign_branch_count"] == 1
    assert row["root_other_project_count"] == 101
    assert row["reason"] == "too_many_other_projects"


def test_deep_single_directory_wrapper_does_not_add_project_burden(tmp_path):
    wrapper = tmp_path / "B"
    middle = wrapper / "C"
    deepest = middle / "D"
    archive = deepest / "large.zip"
    entries = [
        FileEntry(wrapper, True),
        FileEntry(middle, True),
        FileEntry(deepest, True),
        FileEntry(archive, False, 990),
        FileEntry(tmp_path / "readme.txt", False, 10),
    ]

    result = _authorize(tmp_path, entries, [archive])

    assert [task.main_path for task in result.allowed_tasks] == [str(archive)]
    assert result.skipped == []


def test_high_byte_ratio_with_three_other_files_falls_below_score(tmp_path):
    archive = tmp_path / "large.zip"
    entries = [FileEntry(archive, False, 9_970)]
    entries.extend(
        FileEntry(tmp_path / f"note_{index}.txt", False, 10)
        for index in range(3)
    )

    result = _authorize(tmp_path, entries, [archive])

    assert result.allowed_tasks == []
    row = result.skipped[0]
    assert row["reason"] == "authorization_score_below_threshold"
    assert row["authorization_score"] == pytest.approx(0.469, abs=0.002)
