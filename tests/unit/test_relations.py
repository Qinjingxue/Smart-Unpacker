from pathlib import Path

from sunpack.relations.scheduler import RelationsScheduler
from sunpack.filesystem.directory_scanner import DirectoryScanner


def test_relation_group_builder_groups_split_volumes(tmp_path):
    first = tmp_path / "game.part1.rar"
    second = tmp_path / "game.part2.rar"
    orphan = tmp_path / "orphan.002"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    orphan.write_bytes(b"alone")

    snapshot = DirectoryScanner(str(tmp_path)).scan()
    groups = RelationsScheduler().build_candidate_groups(snapshot)

    split_group = next(group for group in groups if group.logical_name == "game")
    orphan_group = next(group for group in groups if Path(group.head_path).name == "orphan.002")

    assert split_group.head_path == str(first)
    assert split_group.member_paths == [str(second)]
    assert split_group.is_split_candidate is True
    assert orphan_group.relation.is_split_related is False


def test_relation_group_builder_groups_rar_sfx_split_volumes(tmp_path):
    first = tmp_path / "installer.part1.exe"
    second = tmp_path / "installer.part2.rar"
    third = tmp_path / "installer.part3.rar"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    third.write_bytes(b"three")

    snapshot = DirectoryScanner(str(tmp_path)).scan()
    groups = RelationsScheduler().build_candidate_groups(snapshot)

    split_group = next(group for group in groups if group.logical_name == "installer")

    assert Path(split_group.head_path).name == "installer.part1.exe"
    assert [Path(path).name for path in split_group.member_paths] == [
        "installer.part2.rar",
        "installer.part3.rar",
    ]
    assert split_group.is_split_candidate is True
    assert split_group.relation.split_role == "first"


def test_relation_group_builder_keeps_same_stem_archives_separate(tmp_path):
    seven_zip = tmp_path / "collision.7z"
    zip_file = tmp_path / "collision.zip"
    seven_zip.write_bytes(b"seven")
    zip_file.write_bytes(b"zip")

    snapshot = DirectoryScanner(str(tmp_path)).scan()
    groups = RelationsScheduler().build_candidate_groups(snapshot)
    collision_groups = [group for group in groups if group.logical_name == "collision"]

    assert sorted(Path(group.head_path).name for group in collision_groups) == ["collision.7z", "collision.zip"]
    assert all(group.member_paths == [] for group in collision_groups)
    assert all(group.is_split_candidate is False for group in collision_groups)


def test_relation_public_helpers_parse_split_names():
    scheduler = RelationsScheduler()

    assert scheduler.detect_split_role("game.part01.rar") == "first"
    assert scheduler.detect_split_role("game.part02.rar") == "member"
    assert scheduler.detect_split_role("payload.zip.0000") == "first"
    assert scheduler.detect_split_role("payload.zip.0001") == "member"
    assert scheduler.logical_name_for_archive("game.7z.001") == "game"
    assert scheduler.logical_name_for_archive("payload.zip.0000") == "payload"
    assert scheduler.logical_name_for_archive("payload.bin") == "payload"
    assert scheduler.parse_numbered_volume(r"C:\tmp\game.part001.rar") == {
        "prefix": r"C:\tmp\game",
        "number": 1,
        "style": "rar_part",
        "width": 3,
    }
    assert scheduler.parse_numbered_volume(r"C:\tmp\classic.z01") == {
        "prefix": r"C:\tmp\classic",
        "number": 1,
        "style": "zip_spanned",
        "width": 2,
    }
    assert scheduler.parse_numbered_volume(r"C:\tmp\payload.zip.0000") == {
        "prefix": r"C:\tmp\payload.zip",
        "number": 1,
        "style": "zip_zero_numbered",
        "width": 4,
    }
    assert scheduler.parse_numbered_volume(r"C:\tmp\payload.zip.0002") == {
        "prefix": r"C:\tmp\payload.zip",
        "number": 3,
        "style": "zip_zero_numbered",
        "width": 4,
    }


def test_relation_group_builder_groups_classic_zip_spanned_volumes(tmp_path):
    first = tmp_path / "classic.z01"
    second = tmp_path / "classic.z02"
    terminal = tmp_path / "classic.zip"
    for path in (first, second, terminal):
        path.write_bytes(b"volume")

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "classic")

    assert Path(split_group.head_path).name == "classic.z01"
    assert [Path(path).name for path in split_group.all_paths] == ["classic.z01", "classic.z02", "classic.zip"]
    assert split_group.split_group_complete is True


def test_relation_group_builder_reports_classic_zip_middle_gap(tmp_path):
    for name in ("classic.z01", "classic.z03", "classic.zip"):
        (tmp_path / name).write_bytes(b"volume")

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "classic")

    assert split_group.split_group_complete is False
    assert split_group.split_missing_reason == "missing_middle"
    assert split_group.split_missing_indices == [2]


def test_relation_group_builder_reports_missing_classic_zip_terminal_volume(tmp_path):
    for name in ("classic.z01", "classic.z02"):
        (tmp_path / name).write_bytes(b"volume")

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "classic")

    assert [Path(path).name for path in split_group.all_paths] == ["classic.z01", "classic.z02"]
    assert split_group.split_group_complete is False
    assert split_group.split_missing_reason == "missing_tail"
    assert split_group.split_missing_indices == [3]


def test_relation_group_builder_groups_zero_based_zip_numbered_volumes(tmp_path):
    first = tmp_path / "payload.zip.0000"
    second = tmp_path / "payload.zip.0001"
    third = tmp_path / "payload.zip.0002"
    for path in (first, second, third):
        path.write_bytes(b"volume")

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "payload")

    assert Path(split_group.head_path).name == "payload.zip.0000"
    assert [Path(path).name for path in split_group.all_paths] == [
        "payload.zip.0000",
        "payload.zip.0001",
        "payload.zip.0002",
    ]
    assert [(volume.number, Path(volume.path).name) for volume in split_group.split_volumes] == [
        (1, "payload.zip.0000"),
        (2, "payload.zip.0001"),
        (3, "payload.zip.0002"),
    ]
    assert split_group.split_group_complete is True
