from pathlib import Path

import pytest

from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.relations import RelationsScheduler


def _groups(tmp_path: Path):
    return RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())


def test_strict_standard_numbered_7z_is_grouped(tmp_path):
    names = ["archive.7z.001", "archive.7z.002", "archive.7z.003"]
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    group = next(group for group in _groups(tmp_path) if group.logical_name == "archive")

    assert group.kind == "split_archive"
    assert [Path(path).name for path in group.all_paths] == names
    assert [volume.number for volume in group.split_volumes] == [1, 2, 3]


def test_strict_formats_with_same_stem_never_cross_merge(tmp_path):
    families = {
        "7z_numbered": ["same.7z.001", "same.7z.002"],
        "zip_numbered": ["same.zip.001", "same.zip.002"],
        "rar_part": ["same.part1.rar", "same.part2.rar"],
    }
    for names in families.values():
        for name in names:
            (tmp_path / name).write_bytes(name.encode())

    actual = {
        group.relation.split_family: {Path(path).name for path in group.all_paths}
        for group in _groups(tmp_path)
        if group.logical_name == "same"
    }

    assert actual == {family: set(names) for family, names in families.items()}


@pytest.mark.parametrize(
    "names",
    [
        ["movie.part1.photo", "movie.part2.document"],
        ["movie.7z.001.noise.bin", "movie.7z.002.noise.bin"],
        ["movie.volume_1.fake", "movie.volume_2.fake"],
        ["movie.z01", "movie.z02", "movie.zip"],
        ["setup.exe", "setup.001", "setup.002"],
    ],
)
def test_filename_camouflage_without_structure_never_builds_a_group(tmp_path, names):
    for name in names:
        (tmp_path / name).write_bytes(name.encode())

    groups = _groups(tmp_path)

    if names[0] == "setup.exe":
        exe_group = next(group for group in groups if Path(group.head_path).name == "setup.exe")
        assert exe_group.all_paths == [str(tmp_path / "setup.exe")]
        numeric_group = next(group for group in groups if Path(group.head_path).name == "setup.001")
        assert {Path(path).name for path in numeric_group.all_paths} == {"setup.001", "setup.002"}
    else:
        assert all(len(group.all_paths) == 1 for group in groups)


@pytest.mark.parametrize(
    ("name", "number", "style"),
    [
        ("archive.7z.001", 1, "numeric_suffix"),
        ("archive.zip.002", 2, "numeric_suffix"),
        ("archive.part03.rar", 3, "rar_part"),
        ("archive.part1.exe", 1, "rar_sfx_part"),
        ("archive.r00", 2, "rar_oldstyle"),
        ("archive.001", 1, "plain_numeric_suffix"),
    ],
)
def test_public_parser_exposes_only_strict_names(name, number, style):
    parsed = RelationsScheduler().parse_numbered_volume(name)

    assert parsed is not None
    assert parsed["number"] == number
    assert parsed["style"] == style


@pytest.mark.parametrize(
    "name",
    [
        "archive.7z.001.noise.bin",
        "archive.part1.rar.hidden",
        "archive.volume_1.fake",
        "archive.z01",
        "archive.[z-02]~",
    ],
)
def test_public_parser_rejects_camouflage_and_ancient_zip_spanned(name):
    scheduler = RelationsScheduler()

    assert scheduler.parse_numbered_volume(name) is None
    assert scheduler.detect_split_role(name) is None


def test_standalone_tbz2_cannot_become_zip_volume_two(tmp_path):
    (tmp_path / "payload.tbz2").write_bytes(b"BZh9" + b"standalone")
    (tmp_path / "payload.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)

    groups = _groups(tmp_path)
    by_name = {Path(group.head_path).name: group for group in groups}

    assert set(by_name) == {"payload.tbz2", "payload.zip"}
    assert by_name["payload.tbz2"].kind == "file"
    assert by_name["payload.tbz2"].head_metadata["format"] == "bzip2"
    assert by_name["payload.tbz2"].head_metadata["standalone"] is True


def test_middle_gap_keeps_structured_missing_index(tmp_path):
    for name in ("gap.7z.001", "gap.7z.003"):
        (tmp_path / name).write_bytes(name.encode())

    group = next(group for group in _groups(tmp_path) if group.logical_name == "gap")

    assert group.split_group_complete is False
    assert group.split_missing_reason == "missing_middle"
    assert group.split_missing_indices == [2]
