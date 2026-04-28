import json
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.config.schema import normalize_config
from smart_unpacker.coordinator.runner import PipelineRunner
from smart_unpacker.extraction.progress import write_extraction_progress_manifest
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.support.resources import get_7z_dll_path, get_sevenzip_worker_path
from smart_unpacker.verification import VerificationScheduler
from tests.helpers.detection_config import with_detection_pipeline


def test_worker_best_effort_zip_payload_damage_records_complete_and_failed_items(tmp_path):
    archive, out_dir, completed, worker_result = _run_payload_damaged_zip_worker(tmp_path)
    output_trace = worker_result["diagnostics"]["output_trace"]
    items = {Path(item["path"]).name: item for item in output_trace["items"]}

    assert completed.returncode != 0
    assert worker_result["status"] == "failed"
    assert worker_result["failure_kind"] in {"checksum_error", "data_error", "corrupted_data"}
    assert worker_result["files_written"] >= 3
    assert (out_dir / "good_before.txt").read_text(encoding="utf-8") == "before"
    assert (out_dir / "good_after.txt").read_text(encoding="utf-8") == "after"
    assert (out_dir / "keep.bin").read_bytes() == b"K" * 32
    assert {"good_before.txt", "bad.bin", "good_after.txt", "keep.bin"} <= set(items)
    assert items["good_before.txt"]["failed"] is False
    assert items["good_after.txt"]["failed"] is False
    assert items["keep.bin"]["failed"] is False
    assert items["bad.bin"]["failed"] is True
    assert items["bad.bin"]["bytes_written"] == 64


def test_verification_scores_best_effort_payload_damage_coverage_from_worker_output(tmp_path):
    archive, out_dir, _completed, worker_result = _run_payload_damaged_zip_worker(tmp_path)
    manifest = write_extraction_progress_manifest(
        archive=str(archive),
        out_dir=str(out_dir),
        diagnostics={"result": worker_result},
        round_index=1,
    )
    result = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        error="payload checksum error",
        diagnostics={"result": worker_result, "progress_manifest": manifest, "partial_outputs": True},
        partial_outputs=True,
        progress_manifest=manifest,
    )

    verification = VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal"},
                {"name": "output_presence"},
                {"name": "archive_test_crc"},
            ],
            "partial_accept_threshold": 0.2,
        }
    }).verify(_task(archive), result)

    assert verification.assessment_status == "partial"
    assert verification.decision_hint == "accept_partial"
    assert verification.source_integrity == "payload_damaged"
    assert verification.archive_coverage.expected_files == 4
    assert verification.archive_coverage.complete_files == 3
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.partial_files in {0, 1}
    assert verification.complete_files == 3
    assert verification.failed_files == 1
    assert verification.completeness == pytest.approx(0.75, abs=0.02)
    assert verification.archive_coverage.completeness == pytest.approx(0.75, abs=0.02)


def test_main_flow_accepts_best_effort_payload_damage_and_reports_coverage(tmp_path):
    _require_worker_or_skip()
    _require_7z_dll_or_skip()
    input_root = tmp_path / "input"
    input_root.mkdir()
    archive = _zip_with_one_bad_payload(input_root)
    config = normalize_config(with_detection_pipeline({
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
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal", "enabled": True},
                {"name": "output_presence", "enabled": True},
                {"name": "archive_test_crc", "enabled": True},
            ],
            "partial_min_completeness": 0.2,
            "partial_accept_threshold": 0.2,
        },
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip"]}]},
    ]))

    summary = PipelineRunner(config).run(str(input_root))

    out_dir = input_root / archive.stem
    report = json.loads((out_dir / ".sunpack" / "recovery_report.json").read_text(encoding="utf-8"))
    bad_entries = [item for item in report["files"] if item["archive_path"] == "bad.bin"]

    assert summary.success_count == 1
    assert summary.partial_success_count == 1
    assert not summary.failed_tasks
    assert report["success_kind"] == "partial"
    assert report["archive_coverage"]["expected_files"] == 4
    assert report["archive_coverage"]["complete_files"] == 3
    assert report["archive_coverage"]["failed_files"] == 1
    assert report["archive_coverage"]["completeness"] == pytest.approx(0.75, abs=0.02)
    assert (out_dir / "good_before.txt").read_text(encoding="utf-8") == "before"
    assert (out_dir / "good_after.txt").read_text(encoding="utf-8") == "after"
    assert (out_dir / "keep.bin").read_bytes() == b"K" * 32
    assert not (out_dir / "bad.bin").exists()
    assert any(item["status"] == "failed" and item["user_action"] == "not_recovered" for item in bad_entries)
    assert any(item["status"] == "discarded" and item["user_action"] == "discarded_low_quality" for item in bad_entries)


def _run_payload_damaged_zip_worker(tmp_path: Path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive = _zip_with_one_bad_payload(tmp_path)
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "best-effort-payload-damage",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
    }

    completed = subprocess.run(
        [worker],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return archive, out_dir, completed, _worker_result(completed.stdout)


def _task(archive: Path) -> ArchiveTask:
    return ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        key=archive.name,
        main_path=str(archive),
        all_parts=[str(archive)],
        logical_name=archive.stem,
        detected_ext="zip",
    )


def _require_worker_or_skip() -> str:
    try:
        return get_sevenzip_worker_path()
    except Exception as exc:
        pytest.skip(f"sevenzip_worker.exe is required: {exc}")


def _require_7z_dll_or_skip() -> str:
    try:
        return get_7z_dll_path()
    except Exception as exc:
        pytest.skip(f"7z.dll is required: {exc}")


def _zip_with_one_bad_payload(tmp_path: Path) -> Path:
    archive = tmp_path / "payload-damaged.zip"
    entries = {
        "good_before.txt": b"before",
        "bad.bin": b"B" * 64,
        "good_after.txt": b"after",
        "keep.bin": b"K" * 32,
    }
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    data = bytearray(archive.read_bytes())
    payload_offset = _zip_stored_payload_offset(bytes(data), "bad.bin")
    data[payload_offset + 7] ^= 0x55
    archive.write_bytes(bytes(data))
    return archive


def _zip_stored_payload_offset(data: bytes, name: str) -> int:
    offset = 0
    target = name.encode("utf-8")
    while offset < len(data):
        index = data.find(b"PK\x03\x04", offset)
        if index < 0:
            break
        name_len, extra_len = struct.unpack_from("<HH", data, index + 26)
        filename = data[index + 30:index + 30 + name_len]
        payload_offset = index + 30 + name_len + extra_len
        if filename == target:
            return payload_offset
        compressed_size = struct.unpack_from("<I", data, index + 18)[0]
        offset = payload_offset + compressed_size
    raise AssertionError(f"ZIP local header not found for {name}")


def _worker_result(stdout: str) -> dict:
    lines = [json.loads(line) for line in stdout.splitlines() if line.strip().startswith("{")]
    return next(item for item in lines if item.get("type") == "result")
