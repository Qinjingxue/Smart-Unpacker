from __future__ import annotations

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan3_wrong_passwords.plan3_support import assert_password_error
from tests.real.split_cases import SPLIT_NAMING_CASES, rename_split_parts


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize("naming", SPLIT_NAMING_CASES, ids=lambda item: item.case_id)
def test_plan3_encrypted_split_reports_password_error(tmp_path, naming, plan3_error):
    if naming.archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    plan3_error["case_id"] = naming.case_id
    plan3_error["archive_format"] = naming.archive_format
    plan3_error["naming_scheme"] = naming.case_id
    plan3_error["split"] = True
    case = FACTORY.create(
        tmp_path,
        f"wrong_{naming.case_id}",
        naming.archive_format,
        password="correct-password-not-in-list",
        split=True,
        payload_size=420 * 1024,
    )
    rename_split_parts(case, naming)
    plan3_error["part_count"] = len(
        [path for path in case.archive_dir.iterdir() if path.is_file()]
    )

    assert_password_error(case, error_info=plan3_error)
