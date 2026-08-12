from __future__ import annotations

import pytest

from tests.helpers.real_archives import (
    create_encrypted_7z_archive,
    create_encrypted_rar_archive,
    create_encrypted_zip_archive,
)
from tests.helpers.tool_config import get_optional_rar
from tests.real.encrypted_cases import RAR_CASES, SEVEN_ZIP_CASES, ZIP_CASES
from tests.real.plan3_wrong_passwords.plan3_support import assert_password_error


RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize(("case_id", "encryption", "method"), ZIP_CASES)
def test_plan3_encrypted_zip_reports_password_error(
    tmp_path, case_id, encryption, method, plan3_error
):
    plan3_error["case_id"] = f"zip_{case_id}"
    plan3_error["archive_format"] = "zip"
    plan3_error["encryption"] = encryption
    plan3_error["method"] = method
    case = create_encrypted_zip_archive(
        tmp_path,
        f"zip_{case_id}",
        password="correct-password-not-in-list",
        encryption=encryption,
        method=method,
    )

    assert_password_error(case, error_info=plan3_error)


@pytest.mark.parametrize(("case_id", "rar4", "header_encrypt"), RAR_CASES)
def test_plan3_encrypted_rar_reports_password_error(
    tmp_path, case_id, rar4, header_encrypt, plan3_error
):
    if not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    plan3_error["case_id"] = f"rar_{case_id}"
    plan3_error["archive_format"] = "rar"
    plan3_error["rar4"] = rar4
    plan3_error["header_encrypt"] = header_encrypt
    case = create_encrypted_rar_archive(
        tmp_path,
        f"rar_{case_id}",
        password="correct-password-not-in-list",
        rar4=rar4,
        header_encrypt=header_encrypt,
    )

    assert_password_error(case, error_info=plan3_error)


@pytest.mark.parametrize(
    ("case_id", "header_encrypt", "solid", "method"), SEVEN_ZIP_CASES
)
def test_plan3_encrypted_7z_reports_password_error(
    tmp_path, case_id, header_encrypt, solid, method, plan3_error
):
    plan3_error["case_id"] = f"7z_{case_id}"
    plan3_error["archive_format"] = "7z"
    plan3_error["header_encrypt"] = header_encrypt
    plan3_error["solid"] = solid
    plan3_error["method"] = method
    case = create_encrypted_7z_archive(
        tmp_path,
        f"7z_{case_id}",
        password="correct-password-not-in-list",
        header_encrypt=header_encrypt,
        solid=solid,
        method=method,
    )

    assert_password_error(case, error_info=plan3_error)
