from __future__ import annotations

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan2_encrypted_archives.plan2_support import (
    assert_plan2_success,
    encrypted_password_list,
)
from tests.real.split_cases import SPLIT_NAMING_CASES, rename_split_parts


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize("naming", SPLIT_NAMING_CASES, ids=lambda item: item.case_id)
def test_plan2_encrypted_split_find_correct_password(tmp_path, naming, plan2_error):
    if naming.archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    password = f"correct-{naming.case_id}"
    plan2_error["case_id"] = naming.case_id
    plan2_error["archive_format"] = naming.archive_format
    plan2_error["naming_scheme"] = naming.case_id
    plan2_error["split"] = True
    plan2_error["password_list_size"] = 100
    case = FACTORY.create(
        tmp_path,
        f"enc_{naming.case_id}",
        naming.archive_format,
        password=password,
        split=True,
        payload_size=420 * 1024,
    )
    rename_split_parts(case, naming)
    part_count = len([path for path in case.archive_dir.iterdir() if path.is_file()])
    plan2_error["part_count"] = part_count

    assert_plan2_success(
        case,
        f".{naming.archive_format}",
        expected_member_count=part_count,
        passwords=encrypted_password_list(password),
        error_info=plan2_error,
    )
