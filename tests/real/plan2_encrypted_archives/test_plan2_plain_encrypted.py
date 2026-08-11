from __future__ import annotations

import pytest

from tests.helpers.real_archives import (
    create_encrypted_7z_archive,
    create_encrypted_rar_archive,
    create_encrypted_zip_archive,
)
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan2_encrypted_archives.plan2_support import (
    assert_plan2_success,
    encrypted_password_list,
)


RAR_AVAILABLE = get_optional_rar() is not None

ZIP_CASES = [
    pytest.param("zipcrypto", "ZipCrypto", None, id="zipcrypto"),
    pytest.param("aes128", "AES128", None, id="aes128"),
    pytest.param("aes256", "AES256", None, id="aes256"),
    pytest.param("deflate64", "ZipCrypto", "Deflate64", id="deflate64"),
    pytest.param("bzip2", "ZipCrypto", "BZip2", id="bzip2"),
    pytest.param("lzma", "ZipCrypto", "LZMA", id="lzma"),
    pytest.param("ppmd", "ZipCrypto", "PPMd", id="ppmd"),
]

RAR_CASES = [
    pytest.param("rar5-header", False, True, id="rar5-header"),
    pytest.param("rar5-data", False, False, id="rar5-data"),
    pytest.param("rar4-header", True, True, id="rar4-header"),
    pytest.param("rar4-data", True, False, id="rar4-data"),
]

SEVEN_ZIP_CASES = [
    pytest.param("header-on", True, True, None, id="header-on"),
    pytest.param("header-off", False, True, None, id="header-off"),
    pytest.param("nonsolid", True, False, None, id="nonsolid"),
    pytest.param("lzma", True, True, "LZMA", id="lzma"),
    pytest.param("ppmd", True, True, "PPMd", id="ppmd"),
    pytest.param("bzip2", True, True, "BZip2", id="bzip2"),
    pytest.param("deflate", True, True, "Deflate", id="deflate"),
]


@pytest.mark.parametrize(("case_id", "encryption", "method"), ZIP_CASES)
def test_plan2_encrypted_zip_find_correct_password(
    tmp_path, case_id, encryption, method, plan2_error
):
    password = f"correct-{case_id}"
    plan2_error["case_id"] = f"zip_{case_id}"
    plan2_error["archive_format"] = "zip"
    plan2_error["encryption"] = encryption
    plan2_error["method"] = method
    plan2_error["password_list_size"] = 100
    case = create_encrypted_zip_archive(
        tmp_path,
        f"zip_{case_id}",
        password=password,
        encryption=encryption,
        method=method,
    )

    assert_plan2_success(
        case,
        ".zip",
        passwords=encrypted_password_list(password),
        error_info=plan2_error,
    )


@pytest.mark.parametrize(("case_id", "rar4", "header_encrypt"), RAR_CASES)
def test_plan2_encrypted_rar_find_correct_password(
    tmp_path, case_id, rar4, header_encrypt, plan2_error
):
    if not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    password = f"correct-{case_id}"
    plan2_error["case_id"] = f"rar_{case_id}"
    plan2_error["archive_format"] = "rar"
    plan2_error["rar4"] = rar4
    plan2_error["header_encrypt"] = header_encrypt
    plan2_error["password_list_size"] = 100
    case = create_encrypted_rar_archive(
        tmp_path,
        f"rar_{case_id}",
        password=password,
        rar4=rar4,
        header_encrypt=header_encrypt,
    )

    assert_plan2_success(
        case,
        ".rar",
        passwords=encrypted_password_list(password),
        error_info=plan2_error,
    )


@pytest.mark.parametrize(
    ("case_id", "header_encrypt", "solid", "method"), SEVEN_ZIP_CASES
)
def test_plan2_encrypted_7z_find_correct_password(
    tmp_path, case_id, header_encrypt, solid, method, plan2_error
):
    password = f"correct-{case_id}"
    plan2_error["case_id"] = f"7z_{case_id}"
    plan2_error["archive_format"] = "7z"
    plan2_error["header_encrypt"] = header_encrypt
    plan2_error["solid"] = solid
    plan2_error["method"] = method
    plan2_error["password_list_size"] = 100
    case = create_encrypted_7z_archive(
        tmp_path,
        f"7z_{case_id}",
        password=password,
        header_encrypt=header_encrypt,
        solid=solid,
        method=method,
    )

    assert_plan2_success(
        case,
        ".7z",
        passwords=encrypted_password_list(password),
        error_info=plan2_error,
    )
