import zipfile
from pathlib import Path

import pytest

from smart_unpacker.config.schema import normalize_config
from smart_unpacker.coordinator.runner import PipelineRunner
from smart_unpacker.support.resources import get_7z_dll_path, get_sevenzip_worker_path
from tests.helpers.detection_config import with_detection_pipeline


MiB = 1024 * 1024


@pytest.mark.large_archive_performance
def test_resource_guard_opt_in_rejects_high_compression_zip_before_extraction(tmp_path, request, record_property):
    _require_native_tools_or_skip()
    size_mb = max(1, int(request.config.getoption("--large-archive-size-mb") or 1))
    archive = tmp_path / "high-compression-bomb.zip"
    _write_high_compression_zip(archive, size_mb=size_mb)
    config = _resource_guard_pipeline_config(
        tmp_path,
        max_total_unpacked_size=max(1, size_mb // 2) * MiB,
        max_compression_ratio=4.0,
    )

    summary = PipelineRunner(config).run(str(tmp_path))

    record_property("payload_size_mb", size_mb)
    record_property("archive_size_bytes", archive.stat().st_size)
    assert summary.success_count == 0
    assert any("resource_guard" in item for item in summary.failed_tasks)
    assert not (tmp_path / archive.stem).exists()


@pytest.mark.large_archive_performance
def test_many_small_file_storm_can_still_extract_when_guard_allows(tmp_path, request, record_property):
    _require_native_tools_or_skip()
    count = max(1000, int(request.config.getoption("--large-archive-count") or 1000))
    archive = tmp_path / "small-file-storm.zip"
    _write_many_small_files_zip(archive, count=count)
    config = _resource_guard_pipeline_config(
        tmp_path,
        max_file_count=count + 100,
        max_total_unpacked_size=16 * MiB,
        max_compression_ratio=1000.0,
    )

    summary = PipelineRunner(config).run(str(tmp_path))

    extracted = list((tmp_path / archive.stem / "items").glob("*.txt"))
    record_property("entry_count", count)
    assert summary.success_count == 1
    assert not summary.failed_tasks
    assert len(extracted) == count


def _resource_guard_pipeline_config(
    tmp_path: Path,
    *,
    max_file_count: int = 100000,
    max_total_unpacked_size: int,
    max_compression_ratio: float,
) -> dict:
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "repair": {
            "enabled": True,
            "max_attempts_per_task": 0,
            "max_repair_rounds_per_task": 0,
            "workspace": str(tmp_path / "repair"),
        },
        "performance": {
            "precise_resource_min_size_mb": 0,
            "resource_guard": {
                "enabled": True,
                "max_file_count": max_file_count,
                "max_total_unpacked_size": max_total_unpacked_size,
                "max_compression_ratio": max_compression_ratio,
            },
        },
        "verification": {"enabled": True},
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip"]}]},
    ]))


def _write_high_compression_zip(path: Path, *, size_mb: int) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as zf:
        zf.writestr("payload.bin", b"A" * (size_mb * MiB))


def _write_many_small_files_zip(path: Path, *, count: int) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
        for index in range(count):
            zf.writestr(f"items/{index:05d}.txt", b"x")


def _require_native_tools_or_skip() -> None:
    try:
        get_7z_dll_path()
        get_sevenzip_worker_path()
    except Exception as exc:
        pytest.skip(f"native extraction tools are required: {exc}")
