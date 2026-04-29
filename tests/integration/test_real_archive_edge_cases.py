import json
from pathlib import Path

import pytest

from packrelic.coordinator.runner import PipelineRunner
from packrelic.config.schema import normalize_config
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import get_optional_rar, require_7z, require_zstd


PASSWORD = "123"
PASSWORD_456 = "456"
PASSWORD_789 = "789"
FACTORY = ArchiveFixtureFactory()


def edge_config(passwords: list[str] | None = None) -> dict:
    return normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "verification": {"enabled": True},
        "user_passwords": passwords or [],
        "builtin_passwords": [],
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".zst", ".001"]}]},
        {"name": "embedded_payload_identity", "enabled": True},
        {"name": "seven_zip_structure_identity", "enabled": True},
        {"name": "rar_structure_identity", "enabled": True},
    ], confirmation=[
        {"name": "seven_zip_probe", "enabled": True},
        {"name": "seven_zip_validation", "enabled": True, "reject_on_failed": False},
    ]))


def detection_disabled_config(passwords: list[str] | None = None) -> dict:
    return normalize_config({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "verification": {"enabled": True},
        "user_passwords": passwords or [],
        "builtin_passwords": [],
        "detection": {
            "fact_collectors": [],
            "processors": [],
            "rule_pipeline": {
                "precheck": [],
                "scoring": [],
                "confirmation": [],
            },
        },
    })


def run_pipeline(target: Path, passwords: list[str] | None = None):
    return PipelineRunner(edge_config(passwords=passwords)).run(str(target))


def run_pipeline_detection_disabled(target: Path, passwords: list[str] | None = None):
    return PipelineRunner(detection_disabled_config(passwords=passwords)).run(str(target))


def marker_was_extracted(root: Path, marker_name: str, marker_text: str) -> bool:
    for path in root.rglob(marker_name):
        try:
            if path.read_text(encoding="utf-8") == marker_text:
                return True
        except OSError:
            continue
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            if path.read_text(encoding="utf-8") == marker_text:
                return True
        except (OSError, UnicodeDecodeError):
            continue
    return False


def assert_success(case: ArchiveCase, passwords: list[str] | None = None):
    summary = run_pipeline(case.archive_dir, passwords=passwords)

    assert summary.success_count == 1
    assert summary.failed_tasks == []
    assert marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)


def assert_success_with_detection_disabled(case: ArchiveCase, passwords: list[str] | None = None):
    summary = run_pipeline_detection_disabled(case.archive_dir, passwords=passwords)

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


def assert_partial_success_without_marker(case: ArchiveCase):
    summary = run_pipeline(case.archive_dir)

    assert summary.success_count == 1
    assert summary.failed_tasks == []
    assert not marker_was_extracted(case.archive_dir, case.marker_name, case.marker_text)


def assert_partial_recovery(case: ArchiveCase):
    summary = run_pipeline(case.archive_dir)

    assert summary.success_count == 1
    assert summary.failed_tasks == []
    assert summary.partial_success_count == 1
    assert summary.recovered_outputs


def archive_formats():
    formats = ["7z", "zip"]
    if get_optional_rar():
        formats.append("rar")
    return formats


def plain_archive_formats():
    return [
        "7z",
        "zip",
        "tar",
        "tar.gz",
        "tar.bz2",
        "tar.xz",
        "tar.zst",
        "gzip",
        "bzip2",
        "xz",
        "zstd",
    ] + (["rar"] if get_optional_rar() else [])


def archive_format_params(default_fast: set[str]):
    return [
        pytest.param(
            archive_format,
            marks=() if archive_format in default_fast else pytest.mark.slow_real_archive,
            id=archive_format,
        )
        for archive_format in archive_formats()
    ]


def plain_archive_format_params(default_fast: set[str]):
    return [
        pytest.param(
            archive_format,
            marks=() if archive_format in default_fast else pytest.mark.slow_real_archive,
            id=archive_format,
        )
        for archive_format in plain_archive_formats()
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


@pytest.mark.parametrize("archive_format", plain_archive_format_params({"7z", "zip", "tar", "gzip", "bzip2", "xz"}))
def test_real_archive_edge_plain_single_archives_extract(tmp_path, archive_format):
    require_7z()
    if archive_format in {"tar.zst", "zstd"}:
        require_zstd()
    case = FACTORY.create(tmp_path, f"plain_single_{archive_format}", archive_format)

    assert_success(case)


@pytest.mark.parametrize("archive_format", plain_archive_format_params({"7z", "zip", "tar", "gzip", "bzip2", "xz"}))
def test_real_archive_edge_plain_single_archives_extract_when_detection_disabled(tmp_path, archive_format):
    require_7z()
    if archive_format in {"tar.zst", "zstd"}:
        require_zstd()
    case = FACTORY.create(tmp_path, f"plain_single_detection_off_{archive_format}", archive_format)

    assert_success_with_detection_disabled(case)


@pytest.mark.parametrize("archive_format", archive_format_params({"7z"}))
def test_real_archive_edge_plain_split_archives_extract(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"plain_split_{archive_format}", archive_format, split=True)

    assert_success(case)


@pytest.mark.parametrize("archive_format", archive_format_params({"7z", "zip"}))
def test_real_archive_edge_plain_split_archives_extract_when_detection_disabled(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"plain_split_detection_off_{archive_format}", archive_format, split=True)

    assert_success_with_detection_disabled(case)


@pytest.mark.parametrize("archive_format", sfx_format_params({"7z"}))
def test_real_archive_edge_sfx_split_archives_extract_when_detection_disabled(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"plain_sfx_split_detection_off_{archive_format}", archive_format, split=True, sfx=True)

    assert_success_with_detection_disabled(case)


@pytest.mark.parametrize("archive_format", archive_format_params({"zip"}))
def test_real_archive_edge_password_archives_require_matching_password(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"pwd_single_{archive_format}", archive_format, password=PASSWORD)

    assert_failure_contains(case, {"密码错误", "压缩包损坏", "致命错误"})
    assert_success(case, passwords=[PASSWORD])


@pytest.mark.parametrize("archive_format", archive_format_params(set()))
def test_real_archive_edge_password_split_archives_require_matching_password(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"pwd_split_{archive_format}", archive_format, password=PASSWORD_456, split=True)

    assert_failure_contains(case, {"密码错误", "压缩包损坏", "分卷缺失或不完整", "致命错误"})
    assert_success(case, passwords=[PASSWORD_456])


@pytest.mark.parametrize("archive_format", archive_format_params({"zip"}))
def test_real_archive_edge_corrupted_single_archives_fail(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"corrupted_single_{archive_format}", archive_format, corruption="truncate")

    if archive_format == "zip":
        assert_success(case)
        return
    assert_failure_contains(case, {"压缩包损坏", "致命错误"})


@pytest.mark.parametrize("archive_format", archive_format_params({"7z", "zip"}))
@pytest.mark.parametrize("corruption", ["byte_flip", "header_damage", "tail_header_damage", "trailing_junk"])
def test_real_archive_edge_corruption_modes_fail(tmp_path, archive_format, corruption):
    require_7z()
    case = FACTORY.create(tmp_path, f"corrupt_{corruption}_{archive_format}", archive_format, corruption=corruption)

    if archive_format == "zip" and corruption == "byte_flip":
        assert_partial_success_without_marker(case)
        return
    if archive_format == "zip" and corruption in {"tail_header_damage", "trailing_junk"}:
        assert_success(case)
        return
    if archive_format == "zip" and corruption == "header_damage":
        assert_success(case)
        return
    if archive_format == "7z" and corruption == "trailing_junk":
        assert_success(case)
        return
    if archive_format == "7z" and corruption == "tail_header_damage":
        assert_failure_contains(case, {"压缩包损坏", "致命错误", "校验失败", "修复结果没有可提取文件"})
        return
    if archive_format == "7z" and corruption == "byte_flip":
        assert_partial_recovery(case)
        return
    assert_failure_contains(
        case,
        {"压缩包损坏", "致命错误"},
        allow_best_effort_outputs=(
            (archive_format == "7z" and corruption == "byte_flip")
        ),
    )


@pytest.mark.parametrize("archive_format", archive_format_params(set()))
def test_real_archive_edge_missing_split_archives_fail(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"missing_split_{archive_format}", archive_format, split=True, split_issue="missing_last")

    assert_failure_contains(case, {"分卷缺失或不完整", "压缩包损坏", "致命错误"})


@pytest.mark.parametrize("archive_format", archive_format_params(set()))
def test_real_archive_edge_partial_split_corruption_fails(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"partial_split_{archive_format}", archive_format, split=True, split_issue="corrupt_member")

    if archive_format == "rar":
        assert_success(case)
        return
    assert_failure_contains(case, {"压缩包损坏", "分卷缺失或不完整", "致命错误"})


@pytest.mark.parametrize("archive_format", sfx_format_params(set()))
def test_real_archive_edge_sfx_archives_extract(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"plain_sfx_{archive_format}", archive_format, sfx=True)

    assert_success(case)


@pytest.mark.parametrize("archive_format", sfx_format_params(set()))
def test_real_archive_edge_password_sfx_archives_require_matching_password(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"pwd_sfx_{archive_format}", archive_format, password=PASSWORD_789, sfx=True)

    assert_failure_contains(case, {"密码错误", "压缩包损坏", "致命错误"})
    assert_success(case, passwords=[PASSWORD_789])


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


@pytest.mark.parametrize("archive_format", archive_format_params({"7z"}))
def test_real_archive_edge_disguised_single_archives_extract(tmp_path, archive_format):
    require_7z()
    case = FACTORY.create(tmp_path, f"disguised_single_{archive_format}", archive_format, disguise_ext=".mix")

    assert_success(case)
