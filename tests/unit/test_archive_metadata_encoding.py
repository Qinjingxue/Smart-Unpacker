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
