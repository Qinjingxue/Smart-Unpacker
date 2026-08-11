from __future__ import annotations

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan1_real_archives.plan1_support import assert_plan1_success


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None
SFX_FORMATS = ["7z", "zip", "rar"]


@pytest.mark.parametrize("archive_format", SFX_FORMATS)
def test_plan1_sfx_archives_extract_and_detect_format(tmp_path, archive_format, plan1_error):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case_id = f"sfx_{archive_format}"
    plan1_error["case_id"] = case_id
    plan1_error["archive_format"] = archive_format
    plan1_error["sfx"] = True
    case = FACTORY.create(tmp_path, case_id, archive_format, sfx=True, payload_size=32 * 1024)

    # SFX 检测为内层格式，容器类型为 pe。
    assert_plan1_success(
        case,
        f".{archive_format}",
        expected_container="pe",
        error_info=plan1_error,
    )


@pytest.mark.parametrize("archive_format", SFX_FORMATS)
def test_plan1_sfx_split_archives_extract_and_detect_format(tmp_path, archive_format, plan1_error):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case_id = f"sfx_split_{archive_format}"
    plan1_error["case_id"] = case_id
    plan1_error["archive_format"] = archive_format
    plan1_error["sfx"] = True
    plan1_error["split"] = True
    case = FACTORY.create(
        tmp_path,
        case_id,
        archive_format,
        sfx=True,
        split=True,
        payload_size=420 * 1024,
    )

    assert_plan1_success(
        case,
        f".{archive_format}",
        expected_container="pe",
        error_info=plan1_error,
    )
