from pathlib import Path

import pytest

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


def test_later_orphan_volume_does_not_invent_a_fuzzy_head(tmp_path):
    orphan = tmp_path / "other.7z.005"
    real_head = tmp_path / "archive.7z.001"
    disguised_part = tmp_path / "archive"
    for path in (orphan, real_head, disguised_part):
        path.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * (1024 * 1024))

    snapshot = DirectoryScanner(str(tmp_path)).scan()
    groups = RelationsScheduler().build_candidate_groups(snapshot)

    orphan_group = next(group for group in groups if group.head_path == str(orphan))
    real_group = next(group for group in groups if str(real_head) in group.all_paths)

    assert orphan_group.head_path == str(orphan)
    assert orphan_group.all_paths == [str(orphan)]
    assert orphan_group.split_group_complete is False
    assert orphan_group.split_missing_reason == "missing_head"
    assert real_group.head_path == str(real_head)
    assert str(disguised_part) in real_group.all_paths


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


def test_relation_group_builder_keeps_same_stem_split_archive_formats_separate(tmp_path):
    seven_zip_first = tmp_path / "collision.7z.001"
    seven_zip_second = tmp_path / "collision.7z.002"
    zip_file = tmp_path / "collision.zip"
    seven_zip_first.write_bytes(b"seven-first")
    seven_zip_second.write_bytes(b"seven-second")
    zip_file.write_bytes(b"zip")

    snapshot = DirectoryScanner(str(tmp_path)).scan()
    groups = RelationsScheduler().build_candidate_groups(snapshot)
    collision_groups = [group for group in groups if group.logical_name == "collision"]

    assert sorted(Path(group.head_path).name for group in collision_groups) == [
        "collision.7z.001",
        "collision.zip",
    ]
    split_group = next(group for group in collision_groups if group.is_split_candidate)
    assert [Path(path).name for path in split_group.all_paths] == [
        "collision.7z.001",
        "collision.7z.002",
    ]
    zip_group = next(group for group in collision_groups if not group.is_split_candidate)
    assert zip_group.member_paths == []


def test_relation_group_builder_attaches_sfx_companion_without_merging_formats(tmp_path):
    names = [
        "bundle.exe",
        "bundle.7z.001.camouflage",
        "bundle.7z.002.camouflage",
        "bundle.zip.001.camouflage",
        "bundle.zip.002.camouflage",
    ]
    for name in names:
        (tmp_path / name).write_bytes(name.encode("ascii"))

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    bundle_groups = [group for group in groups if group.logical_name == "bundle"]
    part_sets = {
        frozenset(Path(path).name for path in group.all_paths)
        for group in bundle_groups
    }

    assert part_sets == {
        frozenset({"bundle.exe", "bundle.7z.001.camouflage", "bundle.7z.002.camouflage"}),
        frozenset({"bundle.exe", "bundle.zip.001.camouflage", "bundle.zip.002.camouflage"}),
    }


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


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            r"C:\tmp\bundle.AA中part-01尾ZZ.BB前rar后CC",
            {
                "prefix": r"C:\tmp\bundle",
                "number": 1,
                "style": "rar_part",
                "width": 2,
                "decorated": True,
            },
        ),
        (
            r"C:\tmp\bundle.AAvolume_2尾ZZ.BB7zCC",
            {
                "prefix": r"C:\tmp\bundle.7z",
                "number": 2,
                "style": "numeric_suffix",
                "width": 3,
                "decorated": True,
            },
        ),
        (
            r"C:\tmp\bundle.AAzipZZ.BB0000CC.camouflage.more",
            {
                "prefix": r"C:\tmp\bundle.zip",
                "number": 1,
                "style": "zip_zero_numbered",
                "width": 4,
                "decorated": True,
            },
        ),
        (
            r"C:\tmp\classic.[z-02]~",
            {
                "prefix": r"C:\tmp\classic",
                "number": 2,
                "style": "zip_spanned",
                "width": 2,
                "decorated": True,
            },
        ),
        (
            r"C:\tmp\legacy.[r-00]~",
            {
                "prefix": r"C:\tmp\legacy",
                "number": 2,
                "style": "rar_oldstyle",
                "width": 2,
                "decorated": True,
            },
        ),
        (
            r"C:\tmp\setup.AApart-01ZZ.BBexeCC",
            {
                "prefix": r"C:\tmp\setup",
                "number": 1,
                "style": "rar_sfx_part",
                "width": 2,
                "decorated": True,
            },
        ),
    ],
)
def test_relation_public_helpers_parse_decorated_split_names(name, expected):
    scheduler = RelationsScheduler()

    assert scheduler.parse_numbered_volume(name) == expected
    assert scheduler.detect_split_role(name) == ("first" if expected["number"] == 1 else "member")
    assert scheduler.logical_name_for_archive(name) in {
        r"C:\tmp\bundle",
        r"C:\tmp\classic",
        r"C:\tmp\legacy",
        r"C:\tmp\setup",
    }


def test_relation_volume_parser_does_not_match_tokens_in_parent_directories():
    scheduler = RelationsScheduler()
    probe_payload = (
        r"C:\watch\.sunpack_watch_probes\326f50021e731b520ffa"
        r"\work\encrypted\payload.txt"
    )

    assert scheduler.parse_numbered_volume(probe_payload) is None
    assert scheduler.detect_split_role(probe_payload) is None

    decorated_volume = (
        r"C:\watch\.sunpack_watch_probes\r-noise-32"
        r"\work\bundle.AApart-01ZZ.BBexeCC"
    )
    assert scheduler.parse_numbered_volume(decorated_volume) == {
        "prefix": r"C:\watch\.sunpack_watch_probes\r-noise-32\work\bundle",
        "number": 1,
        "style": "rar_sfx_part",
        "width": 2,
        "decorated": True,
    }


def test_relation_group_builder_groups_decorated_formats_without_cross_merging(tmp_path):
    names = [
        "bundle.AApart-01ZZ.BBrarCC",
        "bundle.AApart-02ZZ.BBrarCC",
        "bundle.AAzipZZ.BB001CC",
        "bundle.AAzipZZ.BB002CC",
        "bundle.AA7zZZ.BB001CC",
        "bundle.AA7zZZ.BB002CC",
    ]
    for name in names:
        (tmp_path / name).write_bytes(name.encode("ascii"))

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    bundle_groups = [group for group in groups if group.logical_name == "bundle"]

    assert {
        group.relation.split_family: {Path(path).name for path in group.all_paths}
        for group in bundle_groups
    } == {
        "rar_part": {"bundle.AApart-01ZZ.BBrarCC", "bundle.AApart-02ZZ.BBrarCC"},
        "zip_numbered": {"bundle.AAzipZZ.BB001CC", "bundle.AAzipZZ.BB002CC"},
        "7z_numbered": {"bundle.AA7zZZ.BB001CC", "bundle.AA7zZZ.BB002CC"},
    }
    assert all(
        volume.source == "candidate"
        for group in bundle_groups
        for volume in group.split_volumes
    )


def test_relation_group_builder_groups_decorated_sfx_with_rar_members(tmp_path):
    names = [
        "installer.AApart-01ZZ.BBexeCC",
        "installer.AApart-02ZZ.BBrarCC",
        "installer.AApart-03ZZ.BBrarCC",
    ]
    for name in names:
        (tmp_path / name).write_bytes(name.encode("ascii"))

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "installer")

    assert Path(split_group.head_path).name == "installer.AApart-01ZZ.BBexeCC"
    assert {Path(path).name for path in split_group.all_paths} == set(names)
    assert split_group.relation.split_family == "rar_part"
    assert split_group.relation.split_role == "first"


def test_relation_group_builder_groups_oldstyle_rar_volumes(tmp_path):
    names = ["legacy.rar", "legacy.r00", "legacy.r01"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode("ascii"))

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "legacy")

    assert Path(split_group.head_path).name == "legacy.rar"
    assert [Path(path).name for path in split_group.all_paths] == names
    assert split_group.relation.split_family == "rar_oldstyle"
    assert split_group.split_group_complete is True


@pytest.mark.parametrize(
    ("names", "complete", "missing_reason", "missing_indices", "all_paths"),
    [
        (("classic.z01", "classic.z02", "classic.zip"), True, "", [], True),
        (("classic.z01", "classic.z03", "classic.zip"), False, "missing_middle", [2], False),
        (("classic.z01", "classic.z02"), False, "missing_tail", [3], False),
    ],
    ids=["complete", "missing-middle", "missing-tail"],
)
def test_relation_group_builder_reports_classic_zip_volume_contract(
    tmp_path, names, complete, missing_reason, missing_indices, all_paths
):
    for name in names:
        (tmp_path / name).write_bytes(b"volume")

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "classic")

    assert split_group.split_group_complete is complete
    assert split_group.split_missing_reason == missing_reason
    assert split_group.split_missing_indices == missing_indices
    if all_paths:
        assert [Path(path).name for path in split_group.all_paths] == list(names)


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
