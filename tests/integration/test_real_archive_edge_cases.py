import json
from pathlib import Path

import pytest

from tests.helpers.pipeline_engine import execute_pipeline
from sunpack.contracts.failures import FailureKind
from sunpack.config.schema import normalize_config
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import get_optional_rar, get_optional_rar_sfx, require_7z


PASSWORD = "123"
FACTORY = ArchiveFixtureFactory()


def edge_config(passwords: list[str] | None = None, *, allow_partial: bool = False) -> dict:
    return normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "extraction": {
            "content_requirement": "allow_partial" if allow_partial else "complete",
        },
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "verification": {"enabled": True},
        "user_passwords": passwords or [],
        "builtin_passwords": [],
    }, processors=[
        {"name": "embedded_archive", "enabled": True},
        {"name": "pe_overlay_structure", "enabled": True},
        {"name": "executable_carrier", "enabled": True},
        {"name": "zip_eocd_structure", "enabled": True},
        {"name": "tar_header_structure", "enabled": True},
        {"name": "compression_stream_structure", "enabled": True},
        {"name": "seven_zip_structure", "enabled": True},
        {"name": "rar_structure", "enabled": True},
    ], precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "zip_structure_accept", "enabled": True},
        {"name": "tar_structure_accept", "enabled": True},
        {"name": "seven_zip_structure_accept", "enabled": True},
        {"name": "rar_structure_accept", "enabled": True},
        {"name": "compression_stream_accept", "enabled": True},
        {"name": "embedded_payload_identity", "enabled": True},
    ], scoring=[
        {"name": "seven_zip_structure_identity", "enabled": True},
        {"name": "rar_structure_identity", "enabled": True},
        {"name": "zip_structure_identity", "enabled": True},
        {"name": "tar_structure_identity", "enabled": True},
        {"name": "compression_stream_identity", "enabled": True},
    ]))


def run_pipeline(target: Path, passwords: list[str] | None = None, *, allow_partial: bool = False):
    return execute_pipeline(
        edge_config(passwords=passwords, allow_partial=allow_partial),
        str(target),
    )


def assert_success(case: ArchiveCase, passwords: list[str] | None = None):
    summary = run_pipeline(case.archive_dir, passwords=passwords)

    assert summary.success_count == 1
    assert summary.failed_tasks == []
    assert marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)


def assert_failure_contains(
    case: ArchiveCase,
    expected_options: set[str],
    passwords: list[str] | None = None,
    *,
    allow_best_effort_outputs: bool = False,
):
    summary = run_pipeline(case.archive_dir, passwords=passwords)

    assert summary.success_count == 0
    assert summary.failed_tasks
    assert any(any(expected in item for expected in expected_options) for item in summary.failed_tasks)
    if allow_best_effort_outputs:
        manifests = list(case.archive_dir.rglob("extraction_manifest.json"))
        assert manifests
        assert any(json.loads(path.read_text(encoding="utf-8")).get("partial_outputs") for path in manifests)
    else:
        assert not marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)


def archive_formats():
    formats = ["7z", "zip"]
    if get_optional_rar_sfx():
        formats.append("rar")
    return formats


def archive_format_params(default_fast: set[str]):
    return [
        pytest.param(
            archive_format,
            marks=() if archive_format in default_fast else pytest.mark.slow_real_archive,
            id=archive_format,
        )
        for archive_format in archive_formats()
    ]
def sfx_format_params(default_fast: set[str]):
    formats = ["7z"]
    if get_optional_rar():
        formats.append("rar")
    return [
        pytest.param(
            archive_format,
            marks=() if archive_format in default_fast else pytest.mark.slow_real_archive,
            id=archive_format,
        )
        for archive_format in formats
    ]


def carrier_params(default_fast: set[str]):
    carriers = ["jpg", "png", "pdf", "gif", "webp"]
    return [
        pytest.param(
            carrier,
            marks=() if carrier in default_fast else pytest.mark.slow_real_archive,
            id=carrier,
        )
        for carrier in carriers
    ]


def carrier_archive_case_params(default_fast: set[tuple[str, str]]):
    cases = [("pdf", "zip"), ("webp", "7z")]
    if get_optional_rar():
        cases.extend([("jpg", "rar"), ("png", "rar"), ("gif", "rar")])
    return [
        pytest.param(
            carrier,
            archive_format,
            marks=() if (carrier, archive_format) in default_fast else pytest.mark.slow_real_archive,
            id=f"{carrier}-{archive_format}",
        )
        for carrier, archive_format in cases
    ]


@pytest.mark.parametrize("archive_format", archive_format_params(set()))
def test_real_archive_edge_partial_split_corruption_reports_possible_missing_volume(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"partial_split_{archive_format}", archive_format, split=True, split_issue="corrupt_member")

    summary = run_pipeline(case.archive_dir)
    possible = [
        failure
        for failure in summary.failures
        if failure.contains(FailureKind.MISSING_VOLUME)
        and failure.details.get("missing_volume_confirmed") is False
    ]

    assert summary.partial_success_count == 1
    assert summary.failed_tasks == []
    assert possible
    assert possible[0].details["partial_recovery"] is True
    assert summary.recovered_outputs[0]["warning"]["kind"] == "missing_volume"


@pytest.mark.parametrize("archive_format", sfx_format_params(set()))
def test_real_archive_edge_corrupted_sfx_archives_fail(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"corrupted_sfx_{archive_format}", archive_format, sfx=True, corruption="truncate")

    assert_failure_contains(case, {"压缩包损坏", "致命错误"})


@pytest.mark.parametrize("carrier", carrier_params({"jpg", "webp"}))
def test_real_archive_edge_prefixed_carrier_archives_extract(tmp_path, carrier):
    require_7z()
    case = FACTORY.create(tmp_path, f"prefixed_{carrier}_7z", "7z", carrier=carrier)

    assert_success(case)


@pytest.mark.parametrize(("carrier", "archive_format"), carrier_archive_case_params(set()))
def test_real_archive_edge_prefixed_password_carrier_archives_require_matching_password(tmp_path, carrier, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"pwd_prefixed_{carrier}_{archive_format}", archive_format, password=PASSWORD, carrier=carrier)

    assert_failure_contains(case, {"密码错误", "压缩包损坏", "致命错误"})
    assert_success(case, passwords=[PASSWORD])


