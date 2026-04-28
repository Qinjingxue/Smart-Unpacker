import io
import json
import os
import struct
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.run_context import RunContext
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.config.schema import normalize_config
from smart_unpacker.coordinator.extraction_batch import ExtractionBatchRunner
from smart_unpacker.coordinator.runner import PipelineRunner
from smart_unpacker.extraction.progress import write_extraction_progress_manifest
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.repair.result import RepairResult
from smart_unpacker.support.resources import get_7z_dll_path, get_sevenzip_worker_path
from smart_unpacker.verification import VerificationScheduler
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import require_7z


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


def test_worker_continues_after_middle_zip_payload_damage(tmp_path):
    archive = _zip_with_middle_bad_payload(tmp_path)
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker(archive, out_dir, format_hint="zip")
    items = {Path(item["path"]).name: item for item in worker_result["diagnostics"]["output_trace"]["items"]}
    verification = _verify_worker_output(archive, out_dir, worker_result, detected_ext="zip")

    assert worker_result["status"] == "failed"
    assert worker_result["failure_kind"] in {"checksum_error", "data_error", "corrupted_data"}
    assert (out_dir / "good_before.txt").read_text(encoding="utf-8") == "before"
    assert (out_dir / "good_after.txt").read_text(encoding="utf-8") == "after"
    assert set(items) == {"good_before.txt", "bad_middle.bin", "good_after.txt"}
    assert items["good_before.txt"]["failed"] is False
    assert items["bad_middle.bin"]["failed"] is True
    assert items["good_after.txt"]["failed"] is False
    assert verification.assessment_status == "partial"
    assert verification.archive_coverage.expected_files == 3
    assert verification.archive_coverage.complete_files == 2
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.completeness == pytest.approx(2 / 3, abs=0.02)


def test_verification_keeps_zip_path_collisions_on_archive_path_not_basename(tmp_path):
    archive = _zip_with_path_collisions_and_one_bad_payload(tmp_path)
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker(archive, out_dir, format_hint="zip")
    manifest_path = write_extraction_progress_manifest(
        archive=str(archive),
        out_dir=str(out_dir),
        diagnostics={"result": worker_result},
        round_index=1,
    )
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    manifest_items = {item["archive_path"]: item for item in manifest["files"]}
    verification = _verify_worker_output(archive, out_dir, worker_result, detected_ext="zip")
    states = {item.archive_path: item.state for item in verification.file_observations}

    assert worker_result["status"] == "failed"
    assert {"dir/a.txt", "other/a.txt", "A.txt", "a.txt"} <= set(manifest_items)
    assert manifest_items["dir/a.txt"]["status"] == "complete"
    assert manifest_items["other/a.txt"]["status"] == "partial"
    assert verification.archive_coverage.expected_files == 4
    assert states["dir/a.txt"] == "complete"
    assert states["other/a.txt"] == "failed"
    assert verification.archive_coverage.complete_files == 2
    assert verification.archive_coverage.failed_files == 2
    assert verification.archive_coverage.completeness == pytest.approx(0.5, abs=0.02)


def test_verification_counts_zero_byte_files_and_excludes_zip_directories(tmp_path):
    archive = _zip_with_directory_empty_file_and_bad_payload(tmp_path)
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker(archive, out_dir, format_hint="zip")
    verification = _verify_worker_output(archive, out_dir, worker_result, detected_ext="zip")
    states = {item.archive_path: item.state for item in verification.file_observations}

    assert worker_result["status"] == "failed"
    assert (out_dir / "folder").is_dir()
    assert (out_dir / "folder" / "empty.txt").is_file()
    assert (out_dir / "folder" / "empty.txt").stat().st_size == 0
    assert "folder/" not in states
    assert states["folder/empty.txt"] == "complete"
    assert states["folder/good.txt"] == "complete"
    assert states["folder/bad.bin"] == "failed"
    assert verification.archive_coverage.expected_files == 3
    assert verification.archive_coverage.complete_files == 2
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.expected_bytes == 16
    assert verification.archive_coverage.completeness == pytest.approx(2 / 3, abs=0.02)


def test_worker_and_verification_count_multiple_spaced_zip_payload_failures(tmp_path):
    archive = _zip_with_two_spaced_bad_payloads(tmp_path)
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker(archive, out_dir, format_hint="zip")
    items = {Path(item["path"]).name: item for item in worker_result["diagnostics"]["output_trace"]["items"]}
    verification = _verify_worker_output(archive, out_dir, worker_result, detected_ext="zip")

    assert worker_result["status"] == "failed"
    assert items["file1.txt"]["failed"] is False
    assert items["file2_bad.bin"]["failed"] is True
    assert items["file3.txt"]["failed"] is False
    assert items["file4.txt"]["failed"] is False
    assert items["file5_bad.bin"]["failed"] is True
    assert items["file6.txt"]["failed"] is False
    assert worker_result["failed_item"].replace("\\", "/") == "file2_bad.bin"
    assert verification.archive_coverage.expected_files == 6
    assert verification.archive_coverage.complete_files == 4
    assert verification.archive_coverage.failed_files == 2
    assert verification.archive_coverage.completeness == pytest.approx(4 / 6, abs=0.02)


def test_verification_scores_deflated_zip_payload_crc_damage_as_partial_payload(tmp_path):
    archive = _zip_with_deflated_bad_payload(tmp_path)
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker(archive, out_dir, format_hint="zip")
    items = {Path(item["path"]).name: item for item in worker_result["diagnostics"]["output_trace"]["items"]}
    verification = _verify_worker_output(archive, out_dir, worker_result, detected_ext="zip")

    assert worker_result["status"] == "failed"
    assert worker_result["failure_kind"] in {"checksum_error", "data_error", "corrupted_data"}
    assert (out_dir / "good.txt").read_text(encoding="utf-8") == "good"
    assert items["partial.bin"]["failed"] is True
    assert items["partial.bin"]["bytes_written"] == (out_dir / "partial.bin").stat().st_size
    assert verification.assessment_status == "partial"
    assert verification.source_integrity == "payload_damaged"
    assert verification.archive_coverage.expected_files == 2
    assert verification.archive_coverage.complete_files == 1
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.completeness == pytest.approx(0.5, abs=0.02)


def test_verification_uses_expected_names_for_truncated_tar_member_coverage(tmp_path):
    archive = _truncated_tar_with_partial_member(tmp_path)
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker(archive, out_dir, format_hint="tar")
    fact_bag = FactBag()
    fact_bag.set("resource.analysis", {
        "status": "damaged",
        "expected_names_source": "damaged_scan",
        "expected_names": [f"f{index}.txt" for index in range(5)],
    })
    fact_bag.set("verification.expected_names", [f"f{index}.txt" for index in range(5)])
    verification = _verify_worker_output(
        archive,
        out_dir,
        worker_result,
        detected_ext="tar",
        fact_bag=fact_bag,
        methods=[
            {"name": "extraction_exit_signal"},
            {"name": "output_presence"},
            {"name": "expected_name_presence", "required_match_ratio": 1.0},
            {"name": "archive_test_crc"},
        ],
    )
    states = {item.archive_path: item.state for item in verification.file_observations}

    assert worker_result["status"] == "failed"
    assert worker_result["failure_kind"] in {"corrupted_data", "data_error", "input_truncated", "stream_truncated"}
    assert (out_dir / "f0.txt").is_file()
    assert (out_dir / "f1.txt").is_file()
    assert (out_dir / "f2.txt").is_file()
    assert not (out_dir / "f3.txt").exists()
    assert verification.assessment_status == "partial"
    assert verification.source_integrity in {"payload_damaged", "damaged", "truncated"}
    assert verification.archive_coverage.expected_files == 5
    assert verification.archive_coverage.complete_files == 2
    assert verification.archive_coverage.partial_files >= 1
    assert verification.archive_coverage.missing_files == 2
    assert verification.archive_coverage.completeness == pytest.approx(0.6, abs=0.03)
    assert states["f2.txt"] in {"partial", "failed"}


def test_encrypted_zip_payload_damage_with_known_password_is_not_wrong_password(tmp_path):
    archive = _encrypted_zip_with_bad_payload(tmp_path, password="secret")
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker(archive, out_dir, format_hint="zip", password="secret")
    fact_bag = FactBag()
    fact_bag.set("archive.password", "secret")
    verification = _verify_worker_output(
        archive,
        out_dir,
        worker_result,
        detected_ext="zip",
        fact_bag=fact_bag,
        password="secret",
    )

    assert worker_result["status"] == "failed"
    assert worker_result["native_status"] == "damaged"
    assert worker_result["wrong_password"] is False
    assert worker_result["failure_kind"] in {"checksum_error", "corrupted_data", "data_error"}
    assert (out_dir / "good.txt").read_text(encoding="utf-8") == "good"
    assert (out_dir / "keep.txt").read_text(encoding="utf-8") == "keep"
    assert verification.assessment_status == "partial"
    assert verification.source_integrity == "payload_damaged"
    assert verification.archive_coverage.expected_files == 3
    assert verification.archive_coverage.complete_files == 2
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.completeness == pytest.approx(2 / 3, abs=0.02)
    assert not any(issue.code == "fail.archive_crc_wrong_password" for issue in verification.issues)


def test_missing_split_volume_is_not_reported_as_payload_partial(tmp_path):
    archive, part_paths = _seven_zip_missing_middle_volume(tmp_path)
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker(archive, out_dir, format_hint="7z", part_paths=part_paths)
    manifest = write_extraction_progress_manifest(
        archive=str(archive),
        out_dir=str(out_dir),
        diagnostics={"result": worker_result},
        round_index=1,
    )

    assert worker_result["status"] == "failed"
    assert worker_result["native_status"] == "damaged"
    assert worker_result["missing_volume"] is True
    assert worker_result["wrong_password"] is False
    assert worker_result["failure_kind"] == "missing_volume"
    assert json.loads(Path(manifest).read_text(encoding="utf-8"))["partial_outputs"] is False
    assert not any(path.is_file() and ".sunpack" not in path.parts for path in out_dir.rglob("*"))


def test_main_flow_nested_archive_keeps_outer_complete_and_inner_partial_coverage_separate(tmp_path):
    _require_worker_or_skip()
    _require_7z_dll_or_skip()
    input_root = tmp_path / "input"
    input_root.mkdir()
    outer = _outer_zip_with_damaged_inner_zip(input_root)

    summary = PipelineRunner(_best_effort_pipeline_config(tmp_path)).run(str(input_root))

    outer_out_dir = input_root / outer.stem
    inner_out_dir = outer_out_dir / "inner"
    inner_report = json.loads((inner_out_dir / ".sunpack" / "recovery_report.json").read_text(encoding="utf-8"))
    outer_manifest = json.loads((outer_out_dir / ".sunpack" / "extraction_manifest.json").read_text(encoding="utf-8"))

    assert summary.success_count == 2
    assert summary.partial_success_count == 1
    assert not summary.failed_tasks
    assert outer_manifest["summary"]["complete"] == 2
    assert "recovery" not in outer_manifest
    assert (outer_out_dir / "outer-note.txt").read_text(encoding="utf-8") == "outer"
    assert (outer_out_dir / "inner.zip").is_file()
    assert inner_report["archive"].endswith("inner.zip")
    assert inner_report["success_kind"] == "partial"
    assert inner_report["archive_coverage"]["expected_files"] == 4
    assert inner_report["archive_coverage"]["complete_files"] == 3
    assert inner_report["archive_coverage"]["failed_files"] == 1
    assert inner_report["archive_coverage"]["completeness"] == pytest.approx(0.75, abs=0.02)


def test_batch_flow_repair_structure_then_accepts_best_effort_payload_partial(tmp_path):
    _require_worker_or_skip()
    _require_7z_dll_or_skip()
    input_root = tmp_path / "input"
    input_root.mkdir()
    archive = input_root / "needs-structure-repair.zip"
    archive.write_bytes(b"broken central directory placeholder")
    repaired_root = tmp_path / "repaired-source"
    repaired_root.mkdir()
    repaired_archive = _zip_with_one_bad_payload(repaired_root)
    out_dir = input_root / archive.stem
    config = {
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair"),
            "max_repair_rounds_per_task": 1,
        },
        "verification": {
            "enabled": True,
            "methods": [
                {"name": "extraction_exit_signal"},
                {"name": "output_presence"},
                {"name": "archive_test_crc"},
            ],
            "partial_min_completeness": 0.2,
            "partial_accept_threshold": 0.2,
        },
    }
    extractor = _StructureFailureThenWorkerExtractor(repaired_archive)
    runner = ExtractionBatchRunner(RunContext(), extractor, _NoNestedOutputScanPolicy(), config=config)
    repair_stage = _ApplyRepairedArchiveStage(repaired_archive)
    runner.repair_stage = repair_stage
    task = _task(archive)

    outcome = runner._extract_verify_with_retries(task, str(out_dir), runtime_scheduler=None)
    collected = runner.collect_result(task, outcome)
    report = json.loads((out_dir / ".sunpack" / "recovery_report.json").read_text(encoding="utf-8"))

    assert collected == str(out_dir)
    assert outcome.success is True
    assert outcome.result.partial_outputs is True
    assert extractor.calls == 2
    assert repair_stage.calls == 1
    assert runner.context.partial_success_count == 1
    assert report["success_kind"] == "partial"
    assert report["archive"].endswith(archive.name)
    assert report["archive_coverage"]["expected_files"] == 4
    assert report["archive_coverage"]["complete_files"] == 3
    assert report["archive_coverage"]["failed_files"] == 1
    assert report["archive_coverage"]["completeness"] == pytest.approx(0.75, abs=0.02)
    assert (out_dir / "good_before.txt").read_text(encoding="utf-8") == "before"
    assert (out_dir / "good_after.txt").read_text(encoding="utf-8") == "after"
    assert not (out_dir / "bad.bin").exists()


def test_main_flow_accepts_best_effort_payload_damage_and_reports_coverage(tmp_path):
    _require_worker_or_skip()
    _require_7z_dll_or_skip()
    input_root = tmp_path / "input"
    input_root.mkdir()
    archive = _zip_with_one_bad_payload(input_root)
    config = _best_effort_pipeline_config(tmp_path)

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
    archive = _zip_with_one_bad_payload(tmp_path)
    out_dir = tmp_path / "out"
    completed, worker_result = _run_worker(archive, out_dir, format_hint="zip", job_id="best-effort-payload-damage")
    return archive, out_dir, completed, worker_result


def _run_worker(
    archive: Path,
    out_dir: Path,
    *,
    format_hint: str,
    job_id: str = "best-effort-coverage",
    password: str | None = None,
    part_paths: list[Path] | None = None,
):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    payload = {
        "job_id": job_id,
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": format_hint,
    }
    if password is not None:
        payload["password"] = password
    if part_paths is not None:
        payload["part_paths"] = [str(path) for path in part_paths]

    completed = subprocess.run(
        [worker],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return completed, _worker_result(completed.stdout)


def _verify_worker_output(
    archive: Path,
    out_dir: Path,
    worker_result: dict,
    *,
    detected_ext: str,
    fact_bag: FactBag | None = None,
    password: str | None = None,
    methods: list[dict] | None = None,
):
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
        error=str(worker_result.get("message") or ""),
        password_used=password,
        diagnostics={"result": worker_result, "progress_manifest": manifest, "partial_outputs": True},
        partial_outputs=True,
        progress_manifest=manifest,
    )
    return VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": methods or [
                {"name": "extraction_exit_signal"},
                {"name": "output_presence"},
                {"name": "archive_test_crc"},
            ],
            "partial_accept_threshold": 0.2,
        }
    }).verify(_task(archive, fact_bag=fact_bag, detected_ext=detected_ext), result)


def _task(archive: Path, *, fact_bag: FactBag | None = None, detected_ext: str = "zip") -> ArchiveTask:
    return ArchiveTask(
        fact_bag=fact_bag or FactBag(),
        score=10,
        key=archive.name,
        main_path=str(archive),
        all_parts=[str(archive)],
        logical_name=archive.stem,
        detected_ext=detected_ext,
    )


def _best_effort_pipeline_config(
    tmp_path: Path,
    *,
    repair_rounds: int = 0,
    recursive_rounds: int = 2,
    repair_modules: list[dict] | None = None,
) -> dict:
    return normalize_config(with_detection_pipeline({
        "recursive_extract": str(recursive_rounds),
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "repair": {
            "enabled": True,
            "max_attempts_per_task": repair_rounds,
            "max_repair_rounds_per_task": repair_rounds,
            "workspace": str(tmp_path / "repair"),
            **({"modules": repair_modules} if repair_modules is not None else {}),
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


def _require_7z_exe_or_skip() -> Path:
    try:
        return require_7z()
    except Exception as exc:
        pytest.skip(f"7z.exe is required: {exc}")


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


def _outer_zip_with_damaged_inner_zip(tmp_path: Path) -> Path:
    inner = _zip_with_one_bad_payload(tmp_path)
    inner_bytes = inner.read_bytes()
    inner.unlink()
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("outer-note.txt", b"outer")
        zf.writestr("inner.zip", inner_bytes)
    return outer


def _zip_with_middle_bad_payload(tmp_path: Path) -> Path:
    archive = tmp_path / "middle-payload-damaged.zip"
    entries = {
        "good_before.txt": b"before",
        "bad_middle.bin": b"M" * 80,
        "good_after.txt": b"after",
    }
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    data = bytearray(archive.read_bytes())
    payload_offset = _zip_stored_payload_offset(bytes(data), "bad_middle.bin")
    data[payload_offset + 11] ^= 0x33
    archive.write_bytes(bytes(data))
    return archive


def _zip_with_path_collisions_and_one_bad_payload(tmp_path: Path) -> Path:
    archive = tmp_path / "path-collisions.zip"
    entries = {
        "dir/a.txt": b"dir-good",
        "other/a.txt": b"other-bad",
        "A.txt": b"upper-good",
        "a.txt": b"lower-good",
    }
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    data = bytearray(archive.read_bytes())
    payload_offset = _zip_stored_payload_offset(bytes(data), "other/a.txt")
    data[payload_offset + 2] ^= 0x55
    archive.write_bytes(bytes(data))
    return archive


def _zip_with_directory_empty_file_and_bad_payload(tmp_path: Path) -> Path:
    archive = tmp_path / "directory-empty-payload-damaged.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("folder/", b"")
        zf.writestr("folder/empty.txt", b"")
        zf.writestr("folder/good.txt", b"good")
        zf.writestr("folder/bad.bin", b"B" * 12)
    data = bytearray(archive.read_bytes())
    payload_offset = _zip_stored_payload_offset(bytes(data), "folder/bad.bin")
    data[payload_offset + 3] ^= 0x22
    archive.write_bytes(bytes(data))
    return archive


def _zip_with_two_spaced_bad_payloads(tmp_path: Path) -> Path:
    archive = tmp_path / "two-spaced-payload-failures.zip"
    entries = {
        "file1.txt": b"one",
        "file2_bad.bin": b"2" * 20,
        "file3.txt": b"three",
        "file4.txt": b"four",
        "file5_bad.bin": b"5" * 20,
        "file6.txt": b"six",
    }
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    data = bytearray(archive.read_bytes())
    first_offset = _zip_stored_payload_offset(bytes(data), "file2_bad.bin")
    second_offset = _zip_stored_payload_offset(bytes(data), "file5_bad.bin")
    data[first_offset + 4] ^= 0x11
    data[second_offset + 6] ^= 0x22
    archive.write_bytes(bytes(data))
    return archive


def _zip_with_deflated_bad_payload(tmp_path: Path) -> Path:
    archive = tmp_path / "deflated-payload-damaged.zip"
    payload = os.urandom(512 * 1024)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("partial.bin", payload)
        zf.writestr("good.txt", b"good")
    data = bytearray(archive.read_bytes())
    payload_offset, compressed_size = _zip_payload_offset_and_size(bytes(data), "partial.bin")
    data[payload_offset + compressed_size // 2] ^= 0x55
    archive.write_bytes(bytes(data))
    return archive


def _truncated_tar_with_partial_member(tmp_path: Path) -> Path:
    archive = tmp_path / "truncated-member.tar"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        for index in range(5):
            payload = (f"file-{index}\n".encode("utf-8") * 1000)
            info = tarfile.TarInfo(f"f{index}.txt")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    data = buffer.getvalue()
    third_header = data.find(b"f2.txt")
    assert third_header > 0
    archive.write_bytes(data[: third_header + 512 + 2000])
    return archive


def _encrypted_zip_with_bad_payload(tmp_path: Path, *, password: str) -> Path:
    seven_zip = _require_7z_exe_or_skip()
    source = tmp_path / "encrypted-src"
    source.mkdir()
    (source / "good.txt").write_text("good", encoding="utf-8")
    (source / "bad.bin").write_bytes(b"B" * 256)
    (source / "keep.txt").write_text("keep", encoding="utf-8")
    archive = tmp_path / "encrypted-payload-damaged.zip"
    completed = subprocess.run(
        [
            str(seven_zip),
            "a",
            "-tzip",
            f"-p{password}",
            "-mem=ZipCrypto",
            "-mx=0",
            str(archive),
            "good.txt",
            "bad.bin",
            "keep.txt",
            "-y",
        ],
        cwd=str(source),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0 or not archive.is_file():
        pytest.skip(f"encrypted ZIP fixture could not be created: {completed.stderr or completed.stdout}")
    data = bytearray(archive.read_bytes())
    payload_offset = _zip_stored_payload_offset(bytes(data), "bad.bin")
    data[payload_offset + 20] ^= 0x44
    archive.write_bytes(bytes(data))
    return archive


def _seven_zip_missing_middle_volume(tmp_path: Path) -> tuple[Path, list[Path]]:
    seven_zip = _require_7z_exe_or_skip()
    source = tmp_path / "split-src"
    source.mkdir()
    for index in range(8):
        (source / f"f{index}.bin").write_bytes(bytes([index]) * 5000)
    archive_base = tmp_path / "split.7z"
    completed = subprocess.run(
        [
            str(seven_zip),
            "a",
            "-t7z",
            "-mx=0",
            "-v10k",
            str(archive_base),
            str(source / "*"),
            "-y",
        ],
        cwd=str(source),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    parts = sorted(tmp_path.glob("split.7z.*"))
    if completed.returncode != 0 or len(parts) < 3:
        pytest.skip(f"split 7z fixture could not be created: {completed.stderr or completed.stdout}")
    parts[1].unlink()
    return parts[0], [path for path in parts if path.exists()]


def _zip_stored_payload_offset(data: bytes, name: str) -> int:
    payload_offset, _compressed_size = _zip_payload_offset_and_size(data, name)
    return payload_offset


def _zip_payload_offset_and_size(data: bytes, name: str) -> tuple[int, int]:
    offset = 0
    target = name.encode("utf-8")
    while offset < len(data):
        index = data.find(b"PK\x03\x04", offset)
        if index < 0:
            break
        name_len, extra_len = struct.unpack_from("<HH", data, index + 26)
        filename = data[index + 30:index + 30 + name_len]
        payload_offset = index + 30 + name_len + extra_len
        compressed_size = struct.unpack_from("<I", data, index + 18)[0]
        if filename == target:
            return payload_offset, compressed_size
        offset = payload_offset + compressed_size
    raise AssertionError(f"ZIP local header not found for {name}")


class _StructureFailureThenWorkerExtractor:
    password_session = None

    def __init__(self, repaired_archive: Path):
        self.repaired_archive = repaired_archive
        self.calls = 0

    def default_output_dir_for_task(self, task):
        return str(Path(task.main_path).with_suffix(""))

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        self.calls += 1
        if self.calls == 1:
            return ExtractionResult(
                success=False,
                archive=task.main_path,
                out_dir=out_dir,
                all_parts=[task.main_path],
                error="central directory damaged",
                diagnostics={
                    "result": {
                        "status": "failed",
                        "native_status": "damaged",
                        "failure_stage": "archive_open",
                        "failure_kind": "structure_recognition",
                    }
                },
            )

        archive_path = Path(task.archive_input().entry_path)
        _completed, worker_result = _run_worker(archive_path, Path(out_dir), format_hint="zip")
        manifest = write_extraction_progress_manifest(
            archive=str(archive_path),
            out_dir=str(out_dir),
            diagnostics={"result": worker_result},
            round_index=self.calls,
        )
        return ExtractionResult(
            success=False,
            archive=str(archive_path),
            out_dir=str(out_dir),
            all_parts=[str(archive_path)],
            error=str(worker_result.get("message") or "payload damaged"),
            diagnostics={"result": worker_result, "progress_manifest": manifest, "partial_outputs": True},
            partial_outputs=True,
            progress_manifest=manifest,
        )


class _ApplyRepairedArchiveStage:
    config = {
        "max_repair_rounds_per_task": 1,
        "max_repair_seconds_per_task": 120.0,
        "max_repair_generated_files_per_task": 16,
        "max_repair_generated_mb_per_task": 2048.0,
    }

    def __init__(self, repaired_archive: Path):
        self.repaired_archive = repaired_archive
        self.calls = 0

    def repair_after_extraction_failure_result(self, task, result):
        self.calls += 1
        repaired_input = {"kind": "file", "path": str(self.repaired_archive), "format_hint": "zip"}
        task.set_archive_input(repaired_input)
        task.fact_bag.set("archive.repaired", True)
        task.fact_bag.set("repair.status", "repaired")
        task.fact_bag.set("repair.module", "fake_structure_repair")
        return RepairResult(
            status="repaired",
            confidence=0.95,
            format="zip",
            repaired_input=repaired_input,
            actions=["apply_repaired_archive_for_best_effort_loop_test"],
            module_name="fake_structure_repair",
            workspace_paths=[str(self.repaired_archive)],
        )


class _NoNestedOutputScanPolicy:
    def scan_roots_from_outputs(self, outputs):
        return []


def _worker_result(stdout: str) -> dict:
    lines = [json.loads(line) for line in stdout.splitlines() if line.strip().startswith("{")]
    return next(item for item in lines if item.get("type") == "result")
