from types import SimpleNamespace

import pytest

from smart_unpacker.extraction.internal.errors import (
    classify_extract_error,
    has_archive_damage_signals,
    has_definite_wrong_password,
)


@pytest.mark.parametrize(
    ("text", "archive", "is_split", "expected"),
    [
        ("ERROR: Missing volume : demo.7z.002", "demo.7z.001", True, "分卷缺失或不完整"),
        ("Unexpected end of archive", "demo.7z.001", False, "分卷缺失或不完整"),
        ("Unexpected end of archive", "demo.zip", False, "压缩包损坏"),
        ("Unexpected end of data", "demo.rar", False, "压缩包损坏"),
        ("CRC Failed : payload.bin", "demo.7z.001", True, "压缩包损坏"),
        ("CRC Failed : payload.bin", "demo.7z", False, "压缩包损坏"),
        ("ERROR: Data Error in encrypted file. Wrong password? : demo.txt", "demo.7z", False, "密码错误"),
        ("Cannot open encrypted archive. Wrong password?", "demo.zip", False, "密码错误"),
        ("Enter password (will not be echoed):", "demo.rar", False, "密码错误"),
        ("Headers Error", "demo.rar", False, "压缩包损坏"),
        ("Data Error : payload.bin", "demo.7z", False, "压缩包损坏"),
        ("Can not open the file as archive", "demo.zip", False, "压缩包损坏"),
        ("Can not open the file as archive", "demo.zip.001", False, "分卷缺失或不完整"),
        ("Is not archive", "demo.bin", False, "压缩包损坏"),
        ("Archive is corrupted", "demo.7z", False, "压缩包损坏"),
        ("Unsupported compression method", "demo.zip", False, "致命错误 (文件损坏或格式不支持)"),
    ],
)
def test_classify_7z_error_texts(text, archive, is_split, expected):
    assert classify_extract_error(None, text, archive=archive, is_split_archive=is_split) == expected


@pytest.mark.parametrize(
    ("returncode", "expected"),
    [
        (1, "警告 (文件被占用或部分失败)"),
        (2, "致命错误 (文件损坏或格式不支持)"),
        (7, "命令行参数错误"),
        (8, "内存/磁盘空间不足"),
        (255, "用户中断"),
    ],
)
def test_classify_7z_return_codes_when_text_has_no_stronger_signal(returncode, expected):
    result = SimpleNamespace(returncode=returncode)

    assert classify_extract_error(result, "", archive="demo.7z") == expected


def test_text_signal_beats_7z_return_code():
    result = SimpleNamespace(returncode=255)

    assert classify_extract_error(result, "Enter password:", archive="demo.7z") == "密码错误"


@pytest.mark.parametrize(
    "text",
    [
        "wrong password",
        "Wrong password?",
        "Cannot open encrypted archive. Wrong password?",
        "ERROR: Wrong Password : payload.txt",
        "Enter password:",
        "password is incorrect",
        "incorrect password",
    ],
)
def test_definite_wrong_password_signals(text):
    assert has_definite_wrong_password(text)


@pytest.mark.parametrize(
    "text",
    [
        "Unexpected end of archive",
        "Missing volume",
        "CRC Failed",
        "Data Error in encrypted file",
        "Headers Error",
        "Can not open the file as archive",
        "Unsupported compression method",
    ],
)
def test_archive_damage_signals(text):
    assert has_archive_damage_signals(text)
