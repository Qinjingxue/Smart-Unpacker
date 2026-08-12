from __future__ import annotations

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan2_encrypted_archives.plan2_support import encrypted_password_list
from tests.real.plan6_confused_volumes.plan6_support import (
    SCENARIOS,
    apply_volume_confusion,
    assert_plan6_success,
)


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize("archive_format", ["7z", "zip", "rar"])
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda item: item.case_id)
def test_plan6_encrypted_split_confused_volumes_extract(
    tmp_path, archive_format, scenario, plan6_error
):
    """部分分卷后缀混乱但卷号标识完整时，加密分卷仍被识别并正确解压。"""
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    password = f"correct-{archive_format}-{scenario.case_id}"
    case_id = f"conf_{archive_format}_{scenario.case_id}"
    plan6_error["case_id"] = case_id
    plan6_error["archive_format"] = archive_format
    plan6_error["split"] = True
    plan6_error["scenario"] = scenario.case_id
    case = FACTORY.create(
        tmp_path,
        case_id,
        archive_format,
        password=password,
        split=True,
        payload_size=420 * 1024,
    )
    renamed = apply_volume_confusion(case, scenario)

    assert_plan6_success(
        case,
        scenario,
        volume_count=len(renamed),
        passwords=encrypted_password_list(password),
        error_info=plan6_error,
    )
