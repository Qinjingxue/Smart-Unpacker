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


def test_filename_only_grouping_does_not_claim_unmarked_sibling(tmp_path):
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
    assert real_group.all_paths == [str(real_head)]
    disguised_group = next(group for group in groups if group.head_path == str(disguised_part))
    assert disguised_group.all_paths == [str(disguised_part)]


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


def test_relation_group_builder_keeps_ambiguous_sfx_companion_separate_from_formats(tmp_path):
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
        frozenset({"bundle.exe"}),
        frozenset({"bundle.7z.001.camouflage", "bundle.7z.002.camouflage"}),
        frozenset({"bundle.zip.001.camouflage", "bundle.zip.002.camouflage"}),
    }
    assert sum("bundle.exe" in paths for paths in part_sets) == 1


def test_relation_group_builder_groups_unambiguous_generic_sfx_sequence(tmp_path):
    names = ["setup.exe", "setup.001", "setup.002"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode("ascii"))

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "setup")

    assert [Path(path).name for path in split_group.all_paths] == names
    assert [volume.number for volume in split_group.split_volumes] == [1, 2, 3]
    assert {volume.style for volume in split_group.split_volumes} == {"sfx_numeric_suffix"}
    assert split_group.split_group_complete is True


def test_relation_group_builder_arbitrates_mixed_standard_volume_formats_by_name(tmp_path):
    families = {
        "7z_numbered": ["X.7z.001", "X.7z.002"],
        "zip_numbered": ["X.zip.001", "X.zip.002"],
        "zip_spanned": ["X.z01", "X.z02", "X.zip"],
        "rar_part": ["X.part01.rar", "X.part02.rar"],
        "rar_numbered": ["X.rar.001", "X.rar.002"],
    }
    for names in families.values():
        for name in names:
            (tmp_path / name).write_bytes(name.encode("ascii"))

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    x_groups = [group for group in groups if group.logical_name == "X"]
    actual = {
        group.relation.split_family: {Path(path).name for path in group.all_paths}
        for group in x_groups
    }

    assert actual == {family: set(names) for family, names in families.items()}
    claimed = [path for group in x_groups for path in group.all_paths]
    assert len(claimed) == len(set(claimed)) == sum(map(len, families.values()))


def test_relation_group_builder_groups_noisy_declared_formats_without_cross_pollution(tmp_path):
    families = {
        "rar_part": [
            "X.AApart01tail.BBrarCC",
            "X.DDpart02more.EErarFF",
            "X.GGpart03noise.HHrarII",
        ],
        "7z_numbered": [
            "X.AA7zZZ.BB001CC",
            "X.DD7zYY.EE002FF",
            "X.GG7zXX.HH003II",
        ],
        "zip_numbered": [
            "X.AAzipZZ.BB001CC",
            "X.DDzipYY.EE002FF",
            "X.GGzipXX.HH003II",
        ],
    }
    for names in families.values():
        for name in names:
            (tmp_path / name).write_bytes(name.encode("ascii"))

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    x_groups = [group for group in groups if group.logical_name == "X"]
    actual = {
        group.relation.split_family: {Path(path).name for path in group.all_paths}
        for group in x_groups
    }

    assert actual == {family: set(names) for family, names in families.items()}
    assert all(group.split_group_complete is True for group in x_groups)
    assert all(
        volume.source == "candidate"
        for group in x_groups
        for volume in group.split_volumes
    )


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


@pytest.mark.parametrize(
    ("name", "prefix", "number", "style", "width"),
    [
        ("payload.part1.123", "payload", 1, "part_numbered", 1),
        ("payload.part-0002.photo", "payload", 2, "part_numbered", 4),
        ("payload.volume_03.any.thing", "payload", 3, "part_numbered", 2),
        ("payload.7z.part0004.jpg", "payload", 4, "part_numbered", 4),
        ("payload.part0005.zip.png", "payload", 5, "part_numbered", 4),
        ("payload.7z.1", "payload.7z", 1, "numeric_suffix", 1),
        ("payload.z0012", "payload", 12, "zip_spanned", 4),
        ("payload.r001", "payload", 3, "rar_oldstyle", 3),
    ],
)
def test_relation_parser_understands_human_obvious_camouflaged_volume_markers(
    name, prefix, number, style, width
):
    parsed = RelationsScheduler().parse_numbered_volume(name)

    assert parsed == {
        "prefix": prefix,
        "number": number,
        "style": style,
        "width": width,
        **({"decorated": True} if ".part" in name or ".volume" in name else {}),
    }


def test_part_markers_outrank_unrelated_numeric_camouflage_suffixes(tmp_path):
    names = ["payload.part1.123", "payload.part2.456", "payload.part3.789"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "payload")

    assert {Path(path).name for path in split_group.all_paths} == set(names)
    assert [(volume.number, Path(volume.path).name) for volume in split_group.split_volumes] == [
        (1, names[0]),
        (2, names[1]),
        (3, names[2]),
    ]
    assert split_group.relation.split_family == "generic_part"
    assert split_group.split_missing_indices == []
    assert split_group.split_observed_missing_ranges == []
    assert split_group.split_layout_status == "coherent"


@pytest.mark.parametrize(
    "names",
    [
        ("bundle.part1.photo", "bundle.part2.document", "bundle.part3.random"),
        ("bundle.part-01.hidden.zip", "bundle.part-02.hidden.zip", "bundle.part-03.hidden.zip"),
        ("bundle.7z.part001.jpg", "bundle.7z.part002.png", "bundle.7z.part003.txt"),
        ("bundle.part001.7z.jpg", "bundle.part002.7z.png", "bundle.part003.7z.txt"),
        ("bundle.volume_1.aaa", "bundle.volume_2.bbb", "bundle.volume_3.ccc"),
    ],
)
def test_relation_group_builder_groups_varied_marker_camouflage(tmp_path, names):
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "bundle")

    assert {Path(path).name for path in split_group.all_paths} == set(names)
    assert [volume.number for volume in split_group.split_volumes] == [1, 2, 3]
    assert split_group.split_layout_status == "coherent"


def test_unknown_part_camouflage_joins_only_one_concrete_format_family(tmp_path):
    names = ["archive.part1.123", "archive.part2.rar", "archive.part3.rar.hidden"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "archive")

    assert {Path(path).name for path in split_group.all_paths} == set(names)
    assert split_group.relation.split_family == "rar_part"
    assert [volume.number for volume in split_group.split_volumes] == [1, 2, 3]


def test_unknown_part_with_duplicate_index_does_not_override_concrete_volume(tmp_path):
    names = ["archive.part1.rar", "archive.part1.123", "archive.part2.rar"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    archive_groups = [group for group in groups if group.logical_name == "archive"]

    rar_group = next(group for group in archive_groups if group.relation.split_family == "rar_part")
    numeric_decoy = next(group for group in archive_groups if Path(group.head_path).name == "archive.part1.123")
    assert {Path(path).name for path in rar_group.all_paths} == {
        "archive.part1.rar",
        "archive.part2.rar",
    }
    assert numeric_decoy.kind == "file"


def test_conflicting_part_format_families_are_not_cross_merged(tmp_path):
    names = [
        "collision.part1.rar",
        "collision.part2.rar",
        "collision.part1.7z",
        "collision.part2.7z",
        "collision.part3.999",
    ]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    collision_groups = [group for group in groups if group.logical_name == "collision"]
    members_by_family = {
        group.relation.split_family: {Path(path).name for path in group.all_paths}
        for group in collision_groups
    }

    assert members_by_family["rar_part"] == {"collision.part1.rar", "collision.part2.rar"}
    assert members_by_family["7z_part"] == {"collision.part1.7z", "collision.part2.7z"}
    assert members_by_family["generic_part"] == {"collision.part3.999"}


def test_different_trailing_numbered_formats_with_same_stem_remain_separate(tmp_path):
    names = ["mix.7z.001.jpg", "mix.7z.002.png", "mix.zip.001.txt", "mix.zip.002.dat"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    mix_groups = [group for group in groups if group.logical_name == "mix"]

    assert {
        group.relation.split_family: {Path(path).name for path in group.all_paths}
        for group in mix_groups
    } == {
        "7z_numbered": {"mix.7z.001.jpg", "mix.7z.002.png"},
        "zip_numbered": {"mix.zip.001.txt", "mix.zip.002.dat"},
    }


def test_camouflaged_zip_segments_and_terminal_form_one_group(tmp_path):
    names = ["photos.z1.jpg", "photos.z02.png", "photos.zip.document"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "photos")

    assert [Path(path).name for path in split_group.all_paths] == names
    assert [volume.role for volume in split_group.split_volumes] == ["first", "member", "terminal"]
    assert split_group.relation.split_family == "zip_spanned"


@pytest.mark.parametrize(
    "names",
    [
        ("report.2023", "report.2024", "report.2025"),
        ("chapter.001", "chapter.003", "chapter.005"),
        ("report.partition1.2024", "report.partition2.2025"),
        ("build.version1.001", "build.version2.002"),
    ],
)
def test_plain_or_incidental_numbers_do_not_become_split_groups(tmp_path, names):
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())

    assert all(group.kind == "file" for group in groups)
    assert {Path(group.head_path).name for group in groups} == set(names)


def test_large_fake_numeric_suffix_does_not_expand_missing_volume_list(tmp_path):
    names = ["huge.part1.999999998", "huge.part3.999999999"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "huge")

    assert split_group.split_missing_indices == [2]
    assert split_group.split_observed_missing_ranges == [(2, 2)]
    assert split_group.split_layout_status == "observed_gap"
    assert split_group.split_completeness_status == "middle_gap"
    assert split_group.split_completeness_confidence == "hint"
    assert "bracketed_number_gap" in split_group.split_completeness_basis


def test_standard_middle_gap_has_strong_structured_completeness_evidence(tmp_path):
    for name in ("archive.7z.001", "archive.7z.003"):
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "archive")

    assert split_group.split_completeness_status == "middle_gap"
    assert split_group.split_completeness_confidence == "strong"
    assert set(split_group.split_completeness_basis) == {"canonical_scheme", "bracketed_number_gap"}


def test_classic_zip_without_terminal_is_proven_only_for_canonical_scheme(tmp_path):
    for name in ("archive.z01", "archive.z02"):
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "archive")

    assert split_group.split_completeness_status == "tail_missing"
    assert split_group.split_completeness_confidence == "proven"
    assert "required_terminal_absent" in split_group.split_completeness_basis


def test_plain_numeric_sequence_requires_archive_magic_before_grouping(tmp_path):
    names = ["raw.001", "raw.002", "raw.003"]
    for index, name in enumerate(names):
        payload = b"7z\xbc\xaf\x27\x1c" + b"head" if index == 0 else name.encode()
        (tmp_path / name).write_bytes(payload)

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "raw")

    assert split_group.kind == "split_archive"
    assert [Path(path).name for path in split_group.all_paths] == names


def test_format_token_anywhere_before_part_marker_is_preserved_as_evidence(tmp_path):
    names = ["movie.7z.camouflage.part1.jpg", "movie.7z.camouflage.part2.png"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    split_group = next(group for group in groups if group.logical_name == "movie.7z.camouflage")

    assert split_group.relation.split_family == "7z_part"
    assert {Path(path).name for path in split_group.all_paths} == set(names)
