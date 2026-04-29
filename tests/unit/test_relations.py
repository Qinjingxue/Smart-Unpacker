from pathlib import Path

from packrelic.relations.scheduler import RelationsScheduler
from packrelic.filesystem.directory_scanner import DirectoryScanner


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
    assert scheduler.logical_name_for_archive("game.7z.001") == "game"
    assert scheduler.logical_name_for_archive("payload.bin") == "payload"
    assert scheduler.parse_numbered_volume(r"C:\tmp\game.part001.rar") == {
        "prefix": r"C:\tmp\game",
        "number": 1,
        "style": "rar_part",
        "width": 3,
    }
