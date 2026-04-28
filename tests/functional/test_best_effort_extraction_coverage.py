import io
import gzip
import json
import os
import struct
import subprocess
import tarfile
import zipfile
import zlib
from pathlib import Path

import pytest

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from smart_unpacker.contracts.run_context import RunContext
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.config.schema import normalize_config
from smart_unpacker.coordinator.extraction_batch import BatchExtractionOutcome, ExtractionBatchRunner
from smart_unpacker.coordinator.repair_beam import RepairBeamLoop, RepairBeamState
from smart_unpacker.coordinator.runner import PipelineRunner
from smart_unpacker.coordinator.analysis_stage import ArchiveAnalysisStage
from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputRange
from smart_unpacker.extraction.progress import write_extraction_progress_manifest
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.repair.candidate import RepairCandidate, RepairCandidateBatch
from smart_unpacker.repair.result import RepairResult
from smart_unpacker.support.resources import get_7z_dll_path, get_sevenzip_worker_path
from smart_unpacker.verification import VerificationResult, VerificationScheduler
from smart_unpacker.verification.evidence import VerificationEvidence
from smart_unpacker.verification.pipeline import VerificationPipeline
from smart_unpacker.verification.registry import register_verification_method
from smart_unpacker.verification.result import (
    FileVerificationObservation,
    VerificationIssue,
    VerificationStepResult,
)
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import require_7z


@register_verification_method("test_worker_3_of_4_coverage")
class _TestWorkerThreeOfFourCoverage:
    name = "test_worker_3_of_4_coverage"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        observations = [
            FileVerificationObservation(path=f"f{index}.txt", archive_path=f"f{index}.txt", state="complete", method=self.name)
            for index in range(3)
        ]
        observations.append(FileVerificationObservation(path="bad.txt", archive_path="bad.txt", state="failed", method=self.name))
        return VerificationStepResult(
            method=self.name,
            status="partial",
            completeness_hint=0.75,
            source_integrity_hint="payload_damaged",
            decision_hint="accept_partial",
            file_observations=observations,
            issues=[VerificationIssue(
                method=self.name,
                code="info.worker_manifest_coverage",
                message="worker manifest coverage",
                actual={"coverage": {
                    "completeness": 0.75,
                    "file_coverage": 0.75,
                    "byte_coverage": 0.75,
                    "expected_files": 4,
                    "matched_files": 4,
                    "complete_files": 3,
                    "failed_files": 1,
                    "confidence": 0.9,
                }},
            )],
        )


@register_verification_method("test_native_crc_2_of_4_coverage")
class _TestNativeTwoOfFourCoverage:
    name = "test_native_crc_2_of_4_coverage"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        return VerificationStepResult(
            method=self.name,
            status="failed",
            completeness_hint=0.5,
            source_integrity_hint="payload_damaged",
            issues=[VerificationIssue(
                method=self.name,
                code="info.archive_output_coverage",
                message="native CRC manifest only saw part of the damaged archive",
                actual={"coverage": {
                    "completeness": 0.5,
                    "file_coverage": 0.5,
                    "byte_coverage": 0.5,
                    "expected_files": 4,
                    "matched_files": 2,
                    "complete_files": 2,
                    "failed_files": 0,
                    "confidence": 0.55,
                    "source_strength": "partial_native_probe",
                }},
            )],
        )


@register_verification_method("test_weak_expected_name_scan")
class _TestWeakExpectedNameScan:
    name = "test_weak_expected_name_scan"

    def verify(self, evidence: VerificationEvidence, config: dict) -> VerificationStepResult:
        observations = [
            FileVerificationObservation(path=f"f{index}.txt", archive_path=f"f{index}.txt", state="complete", method=self.name)
            for index in range(3)
        ]
        observations.append(FileVerificationObservation(path="maybe-missing.txt", archive_path="maybe-missing.txt", state="missing", method=self.name))
        return VerificationStepResult(
            method=self.name,
            status="warning",
            completeness_hint=0.75,
            source_integrity_hint="damaged",
            decision_hint="none",
            file_observations=observations,
            issues=[VerificationIssue(
                method=self.name,
                code="warning.weak_expected_names_missing",
                message="weak damaged-scan expected name was missing",
                actual={"coverage": {
                    "completeness": 0.75,
                    "file_coverage": 0.75,
                    "expected_files": 4,
                    "matched_files": 3,
                    "complete_files": 3,
                    "missing_files": 1,
                    "confidence": 0.3,
                    "expected_names_source": "damaged_scan",
                }},
            )],
        )


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


def test_verification_coverage_merge_does_not_let_weak_sources_veto_worker_manifest(tmp_path):
    archive = tmp_path / "conflict.zip"
    archive.write_bytes(b"placeholder")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    task = _task(archive)
    task.fact_bag.set("resource.analysis", {
        "status": "damaged",
        "expected_names_source": "damaged_scan",
    })
    evidence = VerificationEvidence(
        task=task,
        extraction_result=ExtractionResult(
            success=False,
            archive=str(archive),
            out_dir=str(out_dir),
            all_parts=[str(archive)],
            error="payload damaged",
            partial_outputs=True,
        ),
        archive_state=task.archive_state(),
        archive_source=task.archive_state().source.to_dict(),
        patch_digest=task.archive_state().effective_patch_digest(),
        state_is_patched=False,
        archive_path=str(archive),
        output_dir=str(out_dir),
        password=None,
        fact_bag=task.fact_bag,
        health={},
        analysis={"status": "damaged", "expected_names_source": "damaged_scan"},
        progress_manifest=None,
    )

    verification = VerificationPipeline({
        "methods": [
            {"name": "test_worker_3_of_4_coverage"},
            {"name": "test_native_crc_2_of_4_coverage"},
            {"name": "test_weak_expected_name_scan"},
        ],
        "partial_accept_threshold": 0.2,
    }).run(evidence)

    assert verification.decision_hint == "accept_partial"
    assert verification.assessment_status == "partial"
    assert verification.archive_coverage.expected_files == 4
    assert verification.archive_coverage.complete_files == 3
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.missing_files == 0
    assert verification.archive_coverage.completeness == pytest.approx(0.75, abs=0.01)
    assert verification.completeness == pytest.approx(0.75, abs=0.01)


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


def test_encrypted_zip_wrong_password_vs_payload_damage_matrix(tmp_path):
    complete = _encrypted_zip(tmp_path / "complete-encrypted", password="secret", corrupt_payload=False)
    damaged = _encrypted_zip(tmp_path / "damaged-encrypted", password="secret", corrupt_payload=True)

    _complete_completed, complete_wrong = _run_worker(
        complete,
        tmp_path / "out-complete-wrong",
        format_hint="zip",
        password="wrong",
    )
    _damaged_wrong_completed, damaged_wrong = _run_worker(
        damaged,
        tmp_path / "out-damaged-wrong",
        format_hint="zip",
        password="wrong",
    )
    _damaged_ok_completed, damaged_ok = _run_worker(
        damaged,
        tmp_path / "out-damaged-ok",
        format_hint="zip",
        password="secret",
    )

    assert complete_wrong["native_status"] == "wrong_password"
    assert complete_wrong["wrong_password"] is True
    assert complete_wrong["failure_kind"] == "encrypted_or_wrong_password"
    assert complete_wrong["files_written"] == 0

    assert damaged_wrong["native_status"] == "wrong_password"
    assert damaged_wrong["wrong_password"] is True
    assert damaged_wrong["failure_kind"] == "encrypted_or_wrong_password"
    assert damaged_wrong["files_written"] == 0

    assert damaged_ok["native_status"] == "damaged"
    assert damaged_ok["wrong_password"] is False
    assert damaged_ok["failure_kind"] in {"checksum_error", "corrupted_data", "data_error"}
    assert damaged_ok["files_written"] == 2


def test_huge_declared_zip_member_does_not_inflate_partial_byte_coverage(tmp_path):
    archive = _zip_with_huge_declared_stored_member(tmp_path)
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker(archive, out_dir, format_hint="zip")
    verification = _verify_worker_output(archive, out_dir, worker_result, detected_ext="zip")

    assert worker_result["status"] == "failed"
    assert worker_result["bytes_written"] == 1024
    assert (out_dir / "huge.bin").stat().st_size == 1024
    assert verification.assessment_status == "partial"
    assert verification.archive_coverage.expected_files == 1
    assert verification.archive_coverage.partial_files == 1
    assert verification.archive_coverage.complete_files == 0
    assert verification.archive_coverage.expected_bytes == 1024 * 1024 * 1024
    assert verification.archive_coverage.matched_bytes == 1024
    assert verification.archive_coverage.byte_coverage < 0.00001
    assert verification.archive_coverage.completeness < 0.51


def test_unicode_reserved_and_long_zip_paths_match_archive_paths(tmp_path):
    archive, names = _zip_with_unicode_reserved_long_paths(tmp_path)
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
    assert set(names.values()) <= set(manifest_items)
    assert states[names["cjk"]] == "complete"
    assert states[names["combining"]] == "failed"
    assert states[names["reserved"]] == "complete"
    assert states[names["long"]] == "complete"
    assert verification.archive_coverage.expected_files == 4
    assert verification.archive_coverage.complete_files == 3
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.completeness == pytest.approx(0.75, abs=0.02)


def test_path_safety_blocks_unsafe_entries_but_counts_them_in_recovery(tmp_path):
    archive = _zip_with_unsafe_and_conflicting_paths(tmp_path)
    out_dir = tmp_path / "out"
    escape_target = tmp_path / "escape.txt"

    _completed, worker_result = _run_worker(archive, out_dir, format_hint="zip")
    verification = _verify_worker_output(archive, out_dir, worker_result, detected_ext="zip")
    states = {item.archive_path: item.state for item in verification.file_observations}

    assert not escape_target.exists()
    assert not (tmp_path / "absolute.txt").exists()
    assert (out_dir / "safe.txt").read_text(encoding="utf-8") == "safe"
    assert verification.archive_coverage.expected_files == 6
    assert verification.archive_coverage.complete_files >= 1
    assert states["safe.txt"] == "complete"
    assert states["../escape.txt"] in {"failed", "blocked"}
    assert states["absolute.txt"] in {"failed", "blocked"}
    assert states["C:/Windows/system32/evil.txt"] in {"failed", "blocked"}
    assert "unicode/cafe\u0301.txt" in states
    assert "unicode/caf\u00e9.txt" in states


def test_resource_guard_blocks_many_entry_archive_as_guarded_not_generic_failure(tmp_path):
    archive = _zip_with_many_entries(tmp_path, count=260)
    out_dir = tmp_path / "out"
    task = _task(archive)
    task.fact_bag.set("resource.analysis", {
        "status": 0,
        "is_archive": True,
        "is_broken": False,
        "archive_type": "zip",
        "item_count": 260,
        "file_count": 260,
        "dir_count": 0,
        "total_unpacked_size": 260,
        "total_packed_size": archive.stat().st_size,
        "largest_item_size": 1,
        "message": "many-entry test fixture",
    })
    runner = ExtractionBatchRunner(
        RunContext(),
        _FailIfCalledExtractor(archive, out_dir),
        _NoNestedOutputScanPolicy(),
        config={
            "performance": {
                "resource_guard": {
                    "enabled": True,
                    "max_file_count": 128,
                    "on_violation": "fail",
                }
            },
            "verification": {"enabled": True, "methods": []},
        },
    )

    [(returned_task, outcome)] = runner._execute_ready_tasks([task], lambda _task: str(out_dir))

    assert returned_task is task
    assert outcome.success is False
    assert outcome.result.error == "resource_guard"
    assert outcome.result.diagnostics["result"]["failure_kind"] == "resource_guard"
    assert outcome.result.diagnostics["result"]["guard_status"] == "guarded"
    assert task.fact_bag.get("resource.guard")["status"] == "guarded"
    assert not out_dir.exists()


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


def test_sfx_crop_patch_payload_damage_coverage_uses_virtual_zip_not_carrier(tmp_path):
    sfx, prefix_size = _sfx_with_zip_payload_damage(tmp_path)
    task = _task(sfx, detected_ext="zip")
    patched_state = ArchiveState.from_archive_input(
        task.archive_input(),
        patches=[PatchPlan(
            id="crop-sfx-prefix",
            operations=[PatchOperation.delete_range(offset=0, size=prefix_size)],
            provenance={"module": "test_carrier_crop_patch"},
            confidence=0.95,
        )],
    )
    task.set_archive_state(patched_state)
    out_dir = tmp_path / "out"

    _completed, worker_result = _run_worker_state(task, out_dir, format_hint="zip")
    verification = _verify_worker_output(
        sfx,
        out_dir,
        worker_result,
        detected_ext="zip",
        fact_bag=task.fact_bag,
    )

    assert worker_result["status"] == "failed"
    assert worker_result["failure_kind"] in {"checksum_error", "data_error", "corrupted_data"}
    assert verification.source_integrity == "payload_damaged"
    assert verification.archive_coverage.expected_files == 4
    assert verification.archive_coverage.complete_files == 3
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.completeness == pytest.approx(0.75, abs=0.02)
    assert all(source.get("patch_digest") == patched_state.effective_patch_digest()
               for source in verification.archive_coverage.sources
               if source.get("method") == "archive_test_crc")


def test_patch_stack_crop_then_cd_rebuild_then_payload_partial_uses_same_state(tmp_path):
    sfx, patch_stack, expected_digest = _sfx_zip_with_payload_damage_and_bad_cd_patch_stack(tmp_path)
    task = _task(sfx, detected_ext="zip")
    patched_state = ArchiveState.from_archive_input(task.archive_input(), patches=patch_stack)
    task.set_archive_state(patched_state)
    out_dir = tmp_path / "out"

    analysis = ArchiveAnalysisStage({"analysis": {"enabled": True}}).analyze_task(task)
    _completed, worker_result = _run_worker_state(task, out_dir, format_hint="zip")
    verification = _verify_worker_output(
        sfx,
        out_dir,
        worker_result,
        detected_ext="zip",
        fact_bag=task.fact_bag,
    )

    assert analysis is not None
    assert task.fact_bag.get("analysis.selected_format") == "zip"
    assert task.archive_state().effective_patch_digest() == expected_digest
    assert [patch.id for patch in task.archive_state().patches] == ["crop-sfx-prefix", "rebuild-central-directory"]
    assert worker_result["status"] == "failed"
    assert worker_result["failure_kind"] in {"checksum_error", "data_error", "corrupted_data"}
    assert verification.source_integrity == "payload_damaged"
    assert verification.archive_coverage.expected_files == 4
    assert verification.archive_coverage.complete_files == 3
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.completeness == pytest.approx(0.75, abs=0.02)
    assert all(source.get("patch_digest") == expected_digest
               for source in verification.archive_coverage.sources
               if source.get("method") == "archive_test_crc")


def test_recovery_report_includes_failure_kind_coverage_and_patch_lineage(tmp_path):
    sfx, patch_stack, expected_digest = _sfx_zip_with_payload_damage_and_bad_cd_patch_stack(tmp_path)
    task = _task(sfx, detected_ext="zip")
    task.set_archive_state(ArchiveState.from_archive_input(task.archive_input(), patches=patch_stack))
    out_dir = tmp_path / "out"
    _completed, worker_result = _run_worker_state(task, out_dir, format_hint="zip")
    verification = _verify_worker_output(sfx, out_dir, worker_result, detected_ext="zip", fact_bag=task.fact_bag)
    result = ExtractionResult(
        success=False,
        archive=str(sfx),
        out_dir=str(out_dir),
        all_parts=[str(sfx)],
        error="payload damaged",
        diagnostics={"result": worker_result, "partial_outputs": True},
        partial_outputs=True,
        progress_manifest=str(out_dir / ".sunpack" / "extraction_manifest.json"),
    )
    runner = ExtractionBatchRunner(
        RunContext(),
        _NoopExtractor(out_dir),
        _NoNestedOutputScanPolicy(),
        config={"verification": {"enabled": True, "methods": []}},
    )

    collected = runner.collect_result(task, BatchExtractionOutcome(result=result, verification=verification))
    report = json.loads((out_dir / ".sunpack" / "recovery_report.json").read_text(encoding="utf-8"))
    bad = [item for item in report["files"] if item["archive_path"] == "bad.bin"]

    assert collected == str(out_dir)
    assert report["archive_coverage"]["expected_files"] == 4
    assert report["archive_state"]["patch_digest"] == expected_digest
    assert [patch["id"] for patch in report["archive_state"]["patch_stack"]] == [
        "crop-sfx-prefix",
        "rebuild-central-directory",
    ]
    assert bad
    assert bad[0]["failure_kind"] in {"checksum_error", "data_error", "corrupted_data"}


def test_beam_dedupes_equivalent_patch_plans_and_assesses_best_coverage(tmp_path):
    source = tmp_path / "beam-source.zip"
    source.write_bytes(b"raw")
    state = ArchiveState.from_archive_input(ArchiveInputDescriptor(
        entry_path=str(source),
        open_mode="file",
        format_hint="zip",
    ))
    scheduler = _LazyBeamCandidateScheduler(state)
    assessed_modules = []

    def assess(item):
        assessed_modules.append(item.candidate.module_name)
        completeness = 1.0 if item.candidate.module_name == "verified_patch" else 0.25
        return {
            "confidence": completeness,
            "completeness": completeness,
            "recoverable_upper_bound": 1.0,
            "assessment_status": "complete" if completeness == 1.0 else "partial",
            "source_integrity": "complete",
            "decision_hint": "accept" if completeness == 1.0 else "repair",
        }

    loop = RepairBeamLoop(
        scheduler,
        beam_width=3,
        max_candidates_per_state=4,
        max_analyze_candidates=4,
        max_assess_candidates=2,
        analyze=lambda candidate: {"confidence": candidate.confidence},
        assess=assess,
    )
    run = loop.run([
        RepairBeamState(
            source_input={"kind": "file", "path": str(source), "format_hint": "zip"},
            archive_state=state.to_dict(),
            format="zip",
            archive_key="beam-source",
        )
    ], max_rounds=1)

    assert scheduler.materialized == ["verified_patch", "worse_patch"]
    assert assessed_modules == ["verified_patch", "worse_patch"]
    assert run.best_state is not None
    assert run.best_state.decision_hint == "accept"
    assert run.best_state.completeness == pytest.approx(1.0)
    assert [entry["module"] for entry in run.best_state.history] == ["verified_patch"]


def test_repair_terminal_missing_volume_feedback_stops_later_repairs(tmp_path):
    archive = tmp_path / "missing-tail.7z.001"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1cmissing tail placeholder")
    out_dir = tmp_path / "out"
    extractor = _AlwaysFailingExtractor(archive, out_dir, failure_kind="structure_recognition")
    runner = ExtractionBatchRunner(
        RunContext(),
        extractor,
        _NoNestedOutputScanPolicy(),
        config={
            "repair": {"enabled": True, "workspace": str(tmp_path / "repair"), "max_repair_rounds_per_task": 3},
            "verification": {"enabled": True, "methods": []},
        },
    )
    repair_stage = _TerminalMissingVolumeRepairStage()
    runner.repair_stage = repair_stage
    task = _task(archive, detected_ext="7z")

    outcome = runner._extract_verify_with_retries(task, str(out_dir), runtime_scheduler=None)

    assert outcome.success is False
    assert repair_stage.calls == 1
    assert task.fact_bag.get("repair.loop.terminal_reason") == "repair_unrepairable"
    terminal = task.fact_bag.get("repair.loop.terminal")
    assert terminal["module"] == "missing_volume_classifier"
    assert task.fact_bag.get("repair.last_result")["diagnosis"]["failure_kind"] == "missing_volume"


def test_split_concat_ranges_patch_state_reaches_worker_without_full_copy(tmp_path):
    sfx, prefix_size = _sfx_with_zip_payload_damage(tmp_path)
    data = sfx.read_bytes()
    first = tmp_path / "split-sfx.zip.001"
    second = tmp_path / "split-sfx.zip.002"
    split_at = prefix_size + 180
    first.write_bytes(data[:split_at])
    second.write_bytes(data[split_at:])
    task = _task(first, detected_ext="zip")
    descriptor = ArchiveInputDescriptor(
        entry_path=str(first),
        open_mode="concat_ranges",
        format_hint="zip",
        logical_name="split-sfx",
        ranges=[
            ArchiveInputRange(path=str(first), start=0, end=None),
            ArchiveInputRange(path=str(second), start=0, end=None),
        ],
    )
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[PatchPlan(
            id="crop-sfx-prefix-across-split",
            operations=[PatchOperation.delete_range(offset=0, size=prefix_size)],
            provenance={"module": "test_split_carrier_crop_patch"},
            confidence=0.95,
        )],
    )
    task.set_archive_state(state)
    task.all_parts = [str(first), str(second)]
    out_dir = tmp_path / "out"

    _completed, worker_result = _run_worker_state(task, out_dir, format_hint="zip")
    verification = _verify_worker_output(
        first,
        out_dir,
        worker_result,
        detected_ext="zip",
        fact_bag=task.fact_bag,
    )

    input_trace = worker_result["diagnostics"].get("input_trace") or {}
    assert input_trace.get("mode") in {"patched", "virtual_patch"}
    assert input_trace.get("virtual_size") == len(data) - prefix_size
    assert Path(input_trace.get("last_read", {}).get("source_path", "")).name in {first.name, second.name}
    assert worker_result["status"] == "failed"
    assert verification.archive_coverage.expected_files == 4
    assert verification.archive_coverage.complete_files == 3
    assert verification.archive_coverage.failed_files == 1


def test_encrypted_sfx_patch_partial_preserves_password_priority(tmp_path):
    sfx, patch_stack, expected_digest = _encrypted_sfx_with_payload_damage_and_bad_cd_patch_stack(
        tmp_path,
        password="secret",
    )
    task = _task(sfx, detected_ext="zip")
    state = ArchiveState.from_archive_input(task.archive_input(), patches=patch_stack)
    task.set_archive_state(state)

    _wrong_completed, wrong = _run_worker_state(task, tmp_path / "wrong", format_hint="zip", password="wrong")
    _ok_completed, ok = _run_worker_state(task, tmp_path / "ok", format_hint="zip", password="secret")
    task.fact_bag.set("archive.password", "secret")
    verification = _verify_worker_output(
        sfx,
        tmp_path / "ok",
        ok,
        detected_ext="zip",
        fact_bag=task.fact_bag,
        password="secret",
    )

    assert task.archive_state().effective_patch_digest() == expected_digest
    assert [patch.id for patch in task.archive_state().patches] == [
        "crop-encrypted-sfx-prefix",
        "rebuild-encrypted-central-directory",
    ]
    assert wrong["native_status"] == "wrong_password"
    assert wrong["wrong_password"] is True
    assert wrong["failure_kind"] == "encrypted_or_wrong_password"
    assert wrong["files_written"] == 0
    assert ok["native_status"] == "damaged"
    assert ok["wrong_password"] is False
    assert ok["failure_kind"] in {"checksum_error", "corrupted_data", "data_error"}
    assert ok["files_written"] == 2
    assert verification.source_integrity == "payload_damaged"
    assert verification.archive_coverage.expected_files == 3
    assert verification.archive_coverage.complete_files == 2
    assert verification.archive_coverage.failed_files == 1


def test_missing_tail_volume_partial_outputs_do_not_become_partial_success(tmp_path):
    archive = tmp_path / "tail-missing.7z.001"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1cmissing tail placeholder")
    out_dir = tmp_path / "out"
    extractor = _MissingVolumePartialExtractor(archive, out_dir)
    runner = ExtractionBatchRunner(
        RunContext(),
        extractor,
        _NoNestedOutputScanPolicy(),
        config={
            "repair": {"enabled": True, "workspace": str(tmp_path / "repair"), "max_repair_rounds_per_task": 1},
            "verification": {
                "enabled": True,
                "methods": [{"name": "extraction_exit_signal"}, {"name": "output_presence"}],
                "partial_min_completeness": 0.2,
                "partial_accept_threshold": 0.2,
            },
        },
    )
    task = _task(archive, detected_ext="7z")

    outcome = runner._extract_verify_with_retries(task, str(out_dir), runtime_scheduler=None)
    collected = runner.collect_result(task, outcome)

    assert collected is None
    assert outcome.success is False
    assert outcome.verification is not None
    assert outcome.verification.decision_hint == "accept_partial"
    assert runner.context.partial_success_count == 0
    assert runner.context.failed_tasks
    assert not (out_dir / ".sunpack" / "recovery_report.json").exists()


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


def test_main_flow_outer_partial_and_inner_tar_gz_partial_keep_coverage_separate(tmp_path):
    _require_worker_or_skip()
    _require_7z_dll_or_skip()
    input_root = tmp_path / "input"
    input_root.mkdir()
    archive = _outer_zip_partial_with_inner_truncated_tar_gz(input_root)
    config = _zip_tar_gz_recursive_pipeline_config(tmp_path)

    summary = PipelineRunner(config).run(str(input_root))

    outer_out_dir = input_root / archive.stem
    inner_out_dir = outer_out_dir / "inner.tar"
    outer_report = json.loads((outer_out_dir / ".sunpack" / "recovery_report.json").read_text(encoding="utf-8"))
    inner_report = json.loads((inner_out_dir / ".sunpack" / "recovery_report.json").read_text(encoding="utf-8"))

    assert summary.partial_success_count == 2
    assert not summary.failed_tasks
    assert outer_report["archive"].endswith("outer-partial-inner-targz.zip")
    assert outer_report["archive_coverage"]["expected_files"] == 3
    assert outer_report["archive_coverage"]["complete_files"] == 2
    assert outer_report["archive_coverage"]["failed_files"] == 1
    assert outer_report["archive_coverage"]["completeness"] == pytest.approx(2 / 3, abs=0.02)
    assert inner_report["archive"].endswith("inner.tar.gz")
    assert inner_report["archive_coverage"]["expected_files"] == 1
    assert inner_report["archive_coverage"]["partial_files"] == 1
    assert inner_report["archive_coverage"]["completeness"] < outer_report["archive_coverage"]["completeness"]


def test_main_flow_outer_complete_inner_missing_volume_does_not_mix_coverage(tmp_path):
    _require_worker_or_skip()
    _require_7z_dll_or_skip()
    input_root = tmp_path / "input"
    input_root.mkdir()
    archive = _outer_zip_with_inner_missing_volume_marker(input_root)
    config = _zip_7z_recursive_pipeline_config(tmp_path)

    summary = PipelineRunner(config).run(str(input_root))

    outer_out_dir = input_root / archive.stem
    outer_manifest = json.loads((outer_out_dir / ".sunpack" / "extraction_manifest.json").read_text(encoding="utf-8"))

    assert summary.success_count == 1
    assert summary.partial_success_count == 0
    assert any("inner-missing.7z.001" in item for item in summary.failed_tasks)
    assert outer_manifest["summary"]["complete"] == 2
    assert "recovery" not in outer_manifest
    assert not (outer_out_dir / "inner-missing.7z" / ".sunpack" / "recovery_report.json").exists()


def test_main_flow_recurses_into_truncated_tar_gz_partial_tar_stream(tmp_path):
    _require_worker_or_skip()
    _require_7z_dll_or_skip()
    input_root = tmp_path / "input"
    input_root.mkdir()
    archive = _truncated_tar_gz_with_valid_partial_tar_prefix(input_root)
    config = _tar_gz_recursive_pipeline_config(tmp_path)

    summary = PipelineRunner(config).run(str(input_root))

    outer_out_dir = input_root / archive.stem
    report = json.loads((outer_out_dir / ".sunpack" / "recovery_report.json").read_text(encoding="utf-8"))
    extracted_names = {path.name for path in outer_out_dir.rglob("*.bin")}

    assert summary.partial_success_count == 1
    assert not summary.failed_tasks
    assert report["success_kind"] == "partial"
    assert report["archive"].endswith("truncated-stream.tar.gz")
    assert report["archive_coverage"]["expected_files"] == 1
    assert report["archive_coverage"]["partial_files"] == 1
    assert "#0" in {item["archive_path"] for item in report["files"]}
    assert {"f0.bin", "f1.bin"} <= extracted_names
    assert "f2.bin" not in extracted_names


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


def _run_worker_state(
    task: ArchiveTask,
    out_dir: Path,
    *,
    format_hint: str,
    job_id: str = "best-effort-state-coverage",
    password: str | None = None,
):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    payload = {
        "job_id": job_id,
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(task.main_path),
        "output_dir": str(out_dir),
        "format_hint": format_hint,
        "archive_state": task.archive_state().to_dict(),
    }
    if password is not None:
        payload["password"] = password
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


def _zip_tar_gz_recursive_pipeline_config(tmp_path: Path) -> dict:
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "3",
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
        {
            "name": "extension",
            "enabled": True,
            "extension_score_groups": [{"score": 5, "extensions": [".zip", ".tar", ".gz", ".tgz", ".tar.gz"]}],
        },
        {"name": "zip_structure_identity", "enabled": True},
        {"name": "compression_stream_identity", "enabled": True},
        {"name": "tar_structure_identity", "enabled": True},
    ]))


def _zip_7z_recursive_pipeline_config(tmp_path: Path) -> dict:
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "3",
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
        {
            "name": "extension",
            "enabled": True,
            "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".001"]}],
        },
        {"name": "zip_structure_identity", "enabled": True},
        {"name": "seven_zip_structure_identity", "enabled": True},
    ]))


def _tar_gz_recursive_pipeline_config(tmp_path: Path) -> dict:
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "3",
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
        {
            "name": "extension",
            "enabled": True,
            "extension_score_groups": [{"score": 5, "extensions": [".tar", ".gz", ".tgz", ".tar.gz"]}],
        },
        {"name": "compression_stream_identity", "enabled": True},
        {"name": "tar_structure_identity", "enabled": True},
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


def _outer_zip_partial_with_inner_truncated_tar_gz(tmp_path: Path) -> Path:
    inner = _truncated_tar_gz_with_valid_partial_tar_prefix(tmp_path)
    inner_bytes = inner.read_bytes()
    inner.unlink()
    outer = tmp_path / "outer-partial-inner-targz.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("outer-note.txt", b"outer")
        zf.writestr("inner.tar.gz", inner_bytes)
        zf.writestr("outer-bad.bin", b"B" * 32)
    data = bytearray(outer.read_bytes())
    payload_offset = _zip_stored_payload_offset(bytes(data), "outer-bad.bin")
    data[payload_offset + 3] ^= 0x55
    outer.write_bytes(bytes(data))
    return outer


def _outer_zip_with_inner_missing_volume_marker(tmp_path: Path) -> Path:
    outer = tmp_path / "outer-complete-inner-missing-volume.zip"
    with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("outer-note.txt", b"outer")
        zf.writestr("inner-missing.7z.001", b"7z\xbc\xaf\x27\x1cmissing tail placeholder")
    return outer


def _sfx_with_zip_payload_damage(tmp_path: Path) -> tuple[Path, int]:
    zip_archive = _zip_with_one_bad_payload(tmp_path)
    zip_bytes = zip_archive.read_bytes()
    zip_archive.unlink()
    prefix = b"MZ" + b"SFX-STUB" * 32
    sfx = tmp_path / "payload-damaged-sfx.exe"
    sfx.write_bytes(prefix + zip_bytes)
    return sfx, len(prefix)


def _sfx_zip_with_payload_damage_and_bad_cd_patch_stack(tmp_path: Path) -> tuple[Path, list[PatchPlan], str]:
    zip_archive = _zip_with_one_bad_payload(tmp_path)
    zip_bytes = zip_archive.read_bytes()
    zip_archive.unlink()
    cd_start, cd_size = _zip_central_directory_range(zip_bytes)
    damaged_zip = bytearray(zip_bytes)
    damaged_zip[cd_start: cd_start + 4] = b"BAD!"
    prefix = b"MZ" + b"SFX-STUB" * 32
    sfx = tmp_path / "payload-damaged-bad-cd-sfx.exe"
    sfx.write_bytes(prefix + bytes(damaged_zip))
    patch_stack = [
        PatchPlan(
            id="crop-sfx-prefix",
            operations=[PatchOperation.delete_range(offset=0, size=len(prefix))],
            provenance={"module": "test_carrier_crop_patch"},
            confidence=0.95,
        ),
        PatchPlan(
            id="rebuild-central-directory",
            operations=[PatchOperation.replace_bytes(offset=cd_start, data=zip_bytes[cd_start: cd_start + cd_size])],
            provenance={"module": "test_central_directory_rebuild_patch"},
            confidence=0.9,
        ),
    ]
    state = ArchiveState.from_archive_input(_archive_input_for_file(sfx, "zip"), patches=patch_stack)
    return sfx, patch_stack, state.effective_patch_digest()


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


def _zip_with_huge_declared_stored_member(tmp_path: Path) -> Path:
    archive = tmp_path / "huge-declared-member.zip"
    name = b"huge.bin"
    payload = b"A" * 1024
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    declared_size = 1024 * 1024 * 1024
    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            declared_size,
            len(name),
            0,
        )
        + name
        + payload
    )
    cd_offset = len(local)
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            declared_size,
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), cd_offset, 0)
    archive.write_bytes(local + central + eocd)
    return archive


def _zip_with_unicode_reserved_long_paths(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    archive = tmp_path / "unicode-paths.zip"
    names = {
        "cjk": "unicode/\u4e2d\u6587.txt",
        "combining": "unicode/cafe\u0301.txt",
        "reserved": "reserved/CON.txt",
        "long": "long/" + ("a" * 120) + ".txt",
    }
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for name in names.values():
            zf.writestr(name, name.encode("utf-8"))
    data = bytearray(archive.read_bytes())
    payload_offset = _zip_stored_payload_offset(bytes(data), names["combining"])
    data[payload_offset] ^= 0x55
    archive.write_bytes(bytes(data))
    return archive, names


def _zip_with_unsafe_and_conflicting_paths(tmp_path: Path) -> Path:
    archive = tmp_path / "unsafe-paths.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("safe.txt", "safe")
        zf.writestr("../escape.txt", "escape")
        zf.writestr("/absolute.txt", "absolute")
        zf.writestr("C:/Windows/system32/evil.txt", "evil")
        zf.writestr("unicode/cafe\u0301.txt", "combining")
        zf.writestr("unicode/caf\u00e9.txt", "precomposed")
    return archive


def _zip_with_many_entries(tmp_path: Path, *, count: int) -> Path:
    archive = tmp_path / "many-entries.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as zf:
        for index in range(count):
            zf.writestr(f"items/{index:04d}.txt", b"x")
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


def _truncated_tar_gz_with_valid_partial_tar_prefix(tmp_path: Path) -> Path:
    archive = tmp_path / "truncated-stream.tar.gz"
    buffer = io.BytesIO()
    member_size = 64 * 1024
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        for index in range(5):
            payload = bytes([65 + index]) * member_size
            info = tarfile.TarInfo(f"f{index}.bin")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

    tar_data = buffer.getvalue()
    first_two_members = (512 + member_size) * 2
    first_segment = gzip.compress(tar_data[:first_two_members], compresslevel=1)
    truncated_second_segment = gzip.compress(tar_data[first_two_members:], compresslevel=1)[:20]
    archive.write_bytes(first_segment + truncated_second_segment)
    return archive


def _encrypted_zip_with_bad_payload(tmp_path: Path, *, password: str) -> Path:
    return _encrypted_zip(tmp_path, password=password, corrupt_payload=True)


def _encrypted_zip(tmp_path: Path, *, password: str, corrupt_payload: bool) -> Path:
    seven_zip = _require_7z_exe_or_skip()
    source = tmp_path / "encrypted-src"
    source.mkdir(parents=True)
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
    if not corrupt_payload:
        return archive
    data = bytearray(archive.read_bytes())
    payload_offset = _zip_stored_payload_offset(bytes(data), "bad.bin")
    data[payload_offset + 20] ^= 0x44
    archive.write_bytes(bytes(data))
    return archive


def _encrypted_sfx_with_payload_damage_and_bad_cd_patch_stack(
    tmp_path: Path,
    *,
    password: str,
) -> tuple[Path, list[PatchPlan], str]:
    zip_archive = _encrypted_zip(tmp_path / "encrypted-sfx-source", password=password, corrupt_payload=True)
    zip_bytes = zip_archive.read_bytes()
    zip_archive.unlink()
    cd_start, cd_size = _zip_central_directory_range(zip_bytes)
    damaged_zip = bytearray(zip_bytes)
    damaged_zip[cd_start: cd_start + 4] = b"BAD!"
    prefix = b"MZ" + b"ENCRYPTED-SFX-STUB" * 16
    sfx = tmp_path / "encrypted-payload-damaged-bad-cd-sfx.exe"
    sfx.write_bytes(prefix + bytes(damaged_zip))
    patch_stack = [
        PatchPlan(
            id="crop-encrypted-sfx-prefix",
            operations=[PatchOperation.delete_range(offset=0, size=len(prefix))],
            provenance={"module": "test_encrypted_sfx_crop"},
            confidence=0.95,
        ),
        PatchPlan(
            id="rebuild-encrypted-central-directory",
            operations=[PatchOperation.replace_bytes(offset=cd_start, data=zip_bytes[cd_start: cd_start + cd_size])],
            provenance={"module": "test_encrypted_cd_rebuild"},
            confidence=0.9,
        ),
    ]
    state = ArchiveState.from_archive_input(_archive_input_for_file(sfx, "zip"), patches=patch_stack)
    return sfx, patch_stack, state.effective_patch_digest()


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


def _zip_central_directory_range(data: bytes) -> tuple[int, int]:
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        start = zf.start_dir
    eocd = data.rfind(b"PK\x05\x06")
    assert start >= 0
    assert eocd >= start
    comment_size = struct.unpack_from("<H", data, eocd + 20)[0]
    end = eocd + 22 + comment_size
    return start, end - start


def _archive_input_for_file(path: Path, format_hint: str) -> ArchiveInputDescriptor:
    return ArchiveInputDescriptor(
        entry_path=str(path),
        open_mode="file",
        format_hint=format_hint,
    )


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


class _LazyBeamCandidateScheduler:
    def __init__(self, source_state: ArchiveState):
        self.source_state = source_state
        self.materialized: list[str] = []

    def generate_repair_candidates(self, job, lazy=True):
        verified_state = self._patched_state("verified-equivalent-a", b"Z")
        duplicate_verified_state = self._patched_state("verified-equivalent-b", b"Z")
        worse_state = self._patched_state("worse", b"W")
        outside_state = self._patched_state("outside-window", b"O")
        return RepairCandidateBatch(candidates=[
            self._lazy_candidate("verified_patch", verified_state, 0.9),
            self._lazy_candidate("duplicate_verified_patch", duplicate_verified_state, 0.9),
            self._lazy_candidate("worse_patch", worse_state, 0.4),
            self._lazy_candidate("outside_window_patch", outside_state, 0.1),
        ])

    def _patched_state(self, patch_id: str, byte: bytes) -> ArchiveState:
        descriptor = self.source_state.to_archive_input_descriptor()
        return ArchiveState.from_archive_input(
            descriptor,
            patches=[PatchPlan(
                id=patch_id,
                operations=[PatchOperation.replace_bytes(offset=0, data=byte)],
                provenance={"module": patch_id},
                confidence=0.9,
            )],
        )

    def _lazy_candidate(self, module_name: str, state: ArchiveState, confidence: float) -> RepairCandidate:
        def materialize():
            self.materialized.append(module_name)
            return RepairCandidate(
                module_name=module_name,
                format="zip",
                repaired_input={"kind": "archive_state", "format_hint": "zip", "module": module_name},
                confidence=confidence,
                actions=[module_name],
                plan={"archive_state": state.to_dict()},
            )

        return RepairCandidate(
            module_name=module_name,
            format="zip",
            repaired_input={},
            confidence=confidence,
            actions=[module_name],
            materializer=materialize,
            materialized=False,
            plan={"archive_state": state.to_dict()},
        )


class _AlwaysFailingExtractor:
    password_session = None

    def __init__(self, archive: Path, out_dir: Path, *, failure_kind: str):
        self.archive = archive
        self.out_dir = out_dir
        self.failure_kind = failure_kind

    def default_output_dir_for_task(self, task):
        return str(self.out_dir)

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        return ExtractionResult(
            success=False,
            archive=str(self.archive),
            out_dir=str(out_dir),
            all_parts=[str(self.archive)],
            error=self.failure_kind,
            diagnostics={
                "result": {
                    "status": "failed",
                    "native_status": "damaged",
                    "failure_stage": "archive_open",
                    "failure_kind": self.failure_kind,
                    "missing_volume": False,
                    "wrong_password": False,
                }
            },
        )


class _FailIfCalledExtractor:
    password_session = None

    def __init__(self, archive: Path, out_dir: Path):
        self.archive = archive
        self.out_dir = out_dir

    def default_output_dir_for_task(self, task):
        return str(self.out_dir)

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        raise AssertionError("resource-guarded task should not reach extraction")


class _NoopExtractor:
    password_session = None

    def __init__(self, out_dir: Path):
        self.out_dir = out_dir

    def default_output_dir_for_task(self, task):
        return str(self.out_dir)

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        raise AssertionError("noop extractor should not be called")


class _TerminalMissingVolumeRepairStage:
    config = {
        "max_repair_rounds_per_task": 3,
        "max_repair_seconds_per_task": 120.0,
        "max_repair_generated_files_per_task": 16,
        "max_repair_generated_mb_per_task": 2048.0,
    }

    def __init__(self):
        self.calls = 0

    def repair_medium_confidence_task(self, task):
        return None

    def repair_after_extraction_failure_result(self, task, result):
        self.calls += 1
        repair = RepairResult(
            status="unrepairable",
            confidence=1.0,
            format="7z",
            module_name="missing_volume_classifier",
            damage_flags=["missing_volume"],
            diagnosis={
                "failure_kind": "missing_volume",
                "structured_reason": {
                    "code": "missing_volume",
                    "source": "repair_module_feedback",
                },
            },
            message="split archive is missing a required tail volume",
        )
        task.fact_bag.set("repair.last_result", {
            "status": repair.status,
            "module": repair.module_name,
            "diagnosis": dict(repair.diagnosis),
            "message": repair.message,
        })
        return repair

    def repair_after_verification_assessment_result(self, task, result, verification):
        return None


class _MissingVolumePartialExtractor:
    password_session = None

    def __init__(self, archive: Path, out_dir: Path):
        self.archive = archive
        self.out_dir = out_dir

    def default_output_dir_for_task(self, task):
        return str(self.out_dir)

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        output = Path(out_dir)
        output.mkdir(parents=True, exist_ok=True)
        (output / "prefix-file.bin").write_bytes(b"partial prefix")
        worker_result = {
            "status": "failed",
            "native_status": "damaged",
            "missing_volume": True,
            "wrong_password": False,
            "failure_stage": "item_extract",
            "failure_kind": "missing_volume",
            "files_written": 1,
            "bytes_written": 14,
            "message": "split archive is missing tail volume",
            "diagnostics": {
                "output_trace": {
                    "items": [{
                        "index": 0,
                        "path": "prefix-file.bin",
                        "is_dir": False,
                        "bytes_written": 14,
                        "failed": False,
                    }]
                }
            },
        }
        manifest = write_extraction_progress_manifest(
            archive=str(self.archive),
            out_dir=str(output),
            diagnostics={"result": worker_result},
            round_index=1,
        )
        return ExtractionResult(
            success=False,
            archive=str(self.archive),
            out_dir=str(output),
            all_parts=[str(self.archive)],
            error="missing volume",
            diagnostics={"result": worker_result, "progress_manifest": manifest, "partial_outputs": True},
            partial_outputs=True,
            progress_manifest=manifest,
        )


class _NoNestedOutputScanPolicy:
    def scan_roots_from_outputs(self, outputs):
        return []


def _worker_result(stdout: str) -> dict:
    lines = [json.loads(line) for line in stdout.splitlines() if line.strip().startswith("{")]
    return next(item for item in lines if item.get("type") == "result")
