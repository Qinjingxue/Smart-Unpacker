from pathlib import Path
import struct

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
        "archive.volume_1.fake",
        "archive.[z-02]~",
    ],
)
def test_public_parser_rejects_camouflage(name):
    scheduler = RelationsScheduler()

    assert scheduler.parse_numbered_volume(name) is None
    assert scheduler.detect_split_role(name) is None


def test_public_parser_accepts_modern_split_zip_members():
    scheduler = RelationsScheduler()

    first = scheduler.parse_numbered_volume("archive.z01")
    later = scheduler.parse_numbered_volume("archive.z12")

    assert first is not None
    assert first["number"] == 1
    assert first["style"] == "zip_spanned"
    assert later is not None
    assert later["number"] == 12
    assert later["style"] == "zip_spanned"


@pytest.mark.parametrize(
    ("name", "number"),
    [
        ("archive.part1.rar.hidden", 1),
        ("archive.part2.rar123", 2),
    ],
)
def test_public_parser_accepts_decorated_rar_part_marker(name, number):
    parsed = RelationsScheduler().parse_numbered_volume(name)

    assert parsed is not None
    assert parsed["number"] == number
    assert parsed["style"] == "rar_part"
    assert parsed["decorated"] is True


def test_split_zip_structure_anchor_recovers_decorated_middle_member(tmp_path):
    first = tmp_path / "modern.z01"
    disguised_second = tmp_path / "modern.z02.useless.bin"
    terminal = tmp_path / "modern.zip"
    first.write_bytes(_split_zip_first_bytes())
    disguised_second.write_bytes(b"opaque-middle-volume")
    terminal.write_bytes(_split_zip_terminal_bytes(disk=2, cd_disk=2))

    group = next(group for group in _groups(tmp_path) if group.logical_name == "modern")

    assert [Path(path).name for path in group.all_paths] == [
        first.name,
        disguised_second.name,
        terminal.name,
    ]
    assert [volume.number for volume in group.split_volumes] == [1, 2, 3]
    assert [volume.role for volume in group.split_volumes] == ["first", "member", "terminal"]
    assert all(volume.style == "zip_spanned" for volume in group.split_volumes)
    assert group.split_missing_indices == []
    assert group.split_completeness_status == "retry_pending_validation"


def test_split_zip_without_terminal_reports_strong_missing_tail(tmp_path):
    first = tmp_path / "modern.z01"
    second = tmp_path / "modern.z02"
    first.write_bytes(_split_zip_first_bytes())
    second.write_bytes(b"opaque-middle-volume")

    group = next(group for group in _groups(tmp_path) if group.logical_name == "modern")

    assert group.split_group_complete is False
    assert group.split_missing_reason == "missing_tail"
    assert group.split_missing_indices == [3]
    assert group.split_completeness_status == "tail_missing"
    assert group.split_completeness_confidence == "strong"


def _split_zip_first_bytes() -> bytes:
    name = b"x"
    local = struct.pack(
        "<4s5H3L2H",
        b"PK\x03\x04",
        20,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        len(name),
        0,
    )
    return b"PK\x07\x08" + local + name


def _split_zip_terminal_bytes(*, disk: int, cd_disk: int) -> bytes:
    return struct.pack(
        "<4s4H2LH",
        b"PK\x05\x06",
        disk,
        cd_disk,
        0,
        0,
        0,
        0,
        0,
    )


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
