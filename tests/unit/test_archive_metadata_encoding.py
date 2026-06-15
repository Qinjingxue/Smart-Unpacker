import binascii
import struct

from sunpack.extraction.internal.sevenzip.metadata import ArchiveMetadataScanner


def test_shift_jis_kanji_only_name_is_not_misclassified_as_gbk():
    scanner = ArchiveMetadataScanner()

    selected = scanner._select_codepage(["日本語.txt".encode("cp932")])

    assert selected["codepage"] == "932"


def test_shift_jis_kanji_directory_name_is_not_misclassified_as_gbk():
    scanner = ArchiveMetadataScanner()

    selected = scanner._select_codepage(["説明書/第一章.txt".encode("cp932")])

    assert selected["codepage"] == "932"


def test_gbk_chinese_name_remains_cp936():
    scanner = ArchiveMetadataScanner()

    selected = scanner._select_codepage(["中文说明资料.txt".encode("cp936")])

    assert selected["codepage"] == "936"


def test_shift_jis_zip_scan_returns_decoded_item_paths(tmp_path):
    archive = tmp_path / "shift-jis.zip"
    expected_name = "日本語/説明.txt"
    _write_stored_zip(archive, expected_name.encode("cp932"), b"payload")

    result = ArchiveMetadataScanner().scan(str(archive))

    assert result.selected_codepage == "932"
    assert result.decoded_names == [expected_name]
    assert result.confidence > 0.5


def _write_stored_zip(path, raw_name: bytes, payload: bytes) -> None:
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name), 0,
    ) + raw_name + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name),
        0, 0, 0, 0, 0, 0,
    ) + raw_name
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50, 0, 0, 1, 1, len(central), len(local), 0,
    )
    path.write_bytes(local + central + eocd)
