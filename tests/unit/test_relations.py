from pathlib import Path

from smart_unpacker.relations.scheduler import RelationsScheduler
from smart_unpacker.filesystem.directory_scanner import DirectoryScanner


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


def test_relation_group_builder_reuses_snapshot_metadata_for_split_expansion(tmp_path, monkeypatch):
    first = tmp_path / "payload.7z.001"
    second = tmp_path / "payload.7z.002"
    first.write_bytes(b"one")
    second.write_bytes(b"two")

    snapshot = DirectoryScanner(str(tmp_path)).scan()

    def fail_filesystem_scan(*_args, **_kwargs):
        raise AssertionError("relation grouping should reuse the directory snapshot")

    monkeypatch.setattr("smart_unpacker.relations.scheduler.os.listdir", fail_filesystem_scan)
    monkeypatch.setattr("smart_unpacker.relations.scheduler.os.stat", fail_filesystem_scan)

    groups = RelationsScheduler().build_candidate_groups(snapshot)

    split_group = next(group for group in groups if group.logical_name == "payload")
    assert split_group.head_path == str(first)
    assert split_group.member_paths == [str(second)]
