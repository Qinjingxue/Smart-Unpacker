from __future__ import annotations

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar, get_test_tools
from tests.real.plan1_real_archives.plan1_support import (
    EXPECTED_DETECTED_EXT,
    PLAIN_FORMATS,
    assert_plan1_success,
)


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None
ZSTD_TOOL = get_test_tools().get("zstd_exe")


def _zstd_available() -> bool:
    return bool(ZSTD_TOOL and ZSTD_TOOL.is_file())


@pytest.mark.parametrize("archive_format", PLAIN_FORMATS)
def test_plan1_plain_single_archives_extract_and_detect_format(
    tmp_path, archive_format, plan1_error
):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    if archive_format in {"tar.zst", "zstd"} and not _zstd_available():
        pytest.skip("zstd.exe is not configured")
    case_id = f"plain_single_{archive_format.replace('.', '_')}"
    plan1_error["case_id"] = case_id
    plan1_error["archive_format"] = archive_format
    case = FACTORY.create(tmp_path, case_id, archive_format, payload_size=32 * 1024)

    assert_plan1_success(case, EXPECTED_DETECTED_EXT[archive_format], error_info=plan1_error)


@pytest.mark.parametrize("archive_format", PLAIN_FORMATS)
def test_plan1_plain_single_disguised_archives_extract_and_detect_format(
    tmp_path, archive_format, plan1_error
):
    """伪装后缀时检测不依赖扩展名，且仍能正确解压（旧测试迁移升级）。"""
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    if archive_format in {"tar.zst", "zstd"} and not _zstd_available():
        pytest.skip("zstd.exe is not configured")
    case_id = f"plain_disguised_{archive_format.replace('.', '_')}"
    plan1_error["case_id"] = case_id
    plan1_error["archive_format"] = archive_format
    plan1_error["disguise_ext"] = ".unrelated"
    case = FACTORY.create(
        tmp_path,
        case_id,
        archive_format,
        payload_size=32 * 1024,
        disguise_ext=".unrelated",
    )

    assert_plan1_success(case, EXPECTED_DETECTED_EXT[archive_format], error_info=plan1_error)
