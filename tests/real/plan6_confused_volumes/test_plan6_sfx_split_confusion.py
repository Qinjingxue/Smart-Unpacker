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
def test_plan6_encrypted_sfx_split_confused_volumes_extract(
    tmp_path, archive_format, scenario, plan6_error
):
    """加密 SFX 分卷部分卷后缀混乱但卷号标识完整时，仍被识别并正确解压。"""
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    password = f"correct-sfx-{archive_format}-{scenario.case_id}"
    case_id = f"conf_sfx_{archive_format}_{scenario.case_id}"
    plan6_error["case_id"] = case_id
    plan6_error["archive_format"] = archive_format
    plan6_error["sfx"] = True
    plan6_error["split"] = True
    plan6_error["scenario"] = scenario.case_id
    case = FACTORY.create(
        tmp_path,
        case_id,
        archive_format,
        password=password,
        sfx=True,
        split=True,
        payload_size=420 * 1024,
    )
    renamed = apply_volume_confusion(case, scenario)

    expected_input_volume_count = len(renamed)
    if archive_format in {"7z", "zip"}:
        # The PE launcher is owned by the candidate for cleanup, but is not an
        # archive input volume.  RAR part1.exe remains a real data volume.
        expected_input_volume_count -= 1

    assert_plan6_success(
        case,
        scenario,
        volume_count=expected_input_volume_count,
        expected_container="pe",
        passwords=encrypted_password_list(password),
        error_info=plan6_error,
    )
