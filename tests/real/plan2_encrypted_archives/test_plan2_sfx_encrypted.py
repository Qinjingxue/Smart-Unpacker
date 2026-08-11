from __future__ import annotations

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan2_encrypted_archives.plan2_support import (
    assert_plan2_success,
    encrypted_password_list,
)


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None
SFX_FORMATS = ["7z", "zip", "rar"]


@pytest.mark.parametrize("archive_format", SFX_FORMATS)
def test_plan2_encrypted_sfx_find_correct_password(tmp_path, archive_format, plan2_error):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    password = f"correct-sfx-{archive_format}"
    plan2_error["case_id"] = f"sfx_{archive_format}"
    plan2_error["archive_format"] = archive_format
    plan2_error["sfx"] = True
    plan2_error["password_list_size"] = 100
    case = FACTORY.create(
        tmp_path,
        f"sfx_{archive_format}",
        archive_format,
        password=password,
        sfx=True,
        payload_size=16 * 1024,
    )

    assert_plan2_success(
        case,
        f".{archive_format}",
        expected_container="pe",
        passwords=encrypted_password_list(password),
        error_info=plan2_error,
    )


@pytest.mark.parametrize("archive_format", SFX_FORMATS)
def test_plan2_encrypted_sfx_split_find_correct_password(tmp_path, archive_format, plan2_error):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    password = f"correct-sfx-split-{archive_format}"
    plan2_error["case_id"] = f"sfx_split_{archive_format}"
    plan2_error["archive_format"] = archive_format
    plan2_error["sfx"] = True
    plan2_error["split"] = True
    plan2_error["password_list_size"] = 100
    case = FACTORY.create(
        tmp_path,
        f"sfx_split_{archive_format}",
        archive_format,
        password=password,
        sfx=True,
        split=True,
        payload_size=420 * 1024,
    )

    assert_plan2_success(
        case,
        f".{archive_format}",
        expected_container="pe",
        passwords=encrypted_password_list(password),
        error_info=plan2_error,
    )
