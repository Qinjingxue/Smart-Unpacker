import json
import zipfile

from packrelic.contracts.detection import FactBag
from packrelic.contracts.tasks import ArchiveTask
from packrelic.extraction.result import ExtractionResult
from packrelic.verification import VerificationScheduler


def test_extraction_exit_signal_reports_unusable_failed_extraction(tmp_path):
    task = _task(tmp_path)
    result = ExtractionResult(
        success=False,
        archive=task.main_path,
        out_dir=str(tmp_path / "out"),
        all_parts=task.all_parts,
        error="boom",
    )

    verification = _scheduler([{"name": "extraction_exit_signal"}]).verify(task, result)

    assert verification.decision_hint == "repair"
    assert verification.assessment_status == "unusable"
    assert verification.completeness == 0.0
    assert verification.issues[0].code == "fail.extraction_failed"


def test_output_presence_reports_missing_or_empty_output_as_unusable(tmp_path):
    task = _task(tmp_path)
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(tmp_path / "missing"), all_parts=task.all_parts)

    missing = _scheduler([{"name": "output_presence"}]).verify(task, result)

    assert missing.decision_hint == "fail"
    assert missing.assessment_status == "unusable"
    assert missing.issues[0].code == "fail.output_missing"

    out_dir = tmp_path / "empty"
    out_dir.mkdir()
    result.out_dir = str(out_dir)
    empty = _scheduler([{"name": "output_presence"}]).verify(task, result)

    assert empty.decision_hint == "fail"
    assert empty.issues[0].code == "fail.output_empty"


def test_manifest_size_match_reports_complete_when_expected_size_matches(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "a.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {"file_count": 1, "total_unpacked_size": 5})
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "manifest_size_match"}]).verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.assessment_status == "complete"
    assert verification.completeness == 1.0


def test_manifest_size_match_reports_repair_needed_for_large_manifest_gap(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "a.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {"file_count": 10, "total_unpacked_size": 10 * 1024 * 1024})
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "manifest_size_match"}]).verify(task, result)

    assert verification.decision_hint == "repair"
    assert verification.assessment_status == "partial"
    assert verification.completeness < 1.0
    assert {issue.code for issue in verification.issues} == {
        "fail.manifest_file_count_under",
        "fail.manifest_size_under",
    }


def test_expected_name_presence_reports_missing_entries(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "actual.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {"expected_names": ["expected.txt", "missing.bin"]})
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "expected_name_presence"}]).verify(task, result)

    assert verification.decision_hint == "repair"
    assert verification.missing_files == 2
    assert verification.issues[0].code == "fail.expected_names_all_missing"


def test_expected_name_presence_skips_without_manifest_names(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "actual.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path)
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "expected_name_presence"}]).verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.assessment_status == "complete"
    assert verification.steps[0].status == "skipped"


def test_expected_name_presence_weak_damaged_source_sets_recoverable_upper_bound(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "present.txt").write_text("hello", encoding="utf-8")
    task = _task(tmp_path, {
        "status": "damaged",
        "expected_names": ["present.txt", "maybe-missing.bin"],
        "expected_names_source": "local_header_recovery",
    })
    result = ExtractionResult(success=True, archive=task.main_path, out_dir=str(out_dir), all_parts=task.all_parts)

    verification = _scheduler([{"name": "expected_name_presence"}]).verify(task, result)

    assert verification.source_integrity == "damaged"
    assert verification.completeness == 0.5
    assert verification.recoverable_upper_bound == 0.5
    assert verification.decision_hint == "accept_partial"


def test_archive_test_crc_compares_archive_state_manifest_to_output_files(tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("good.txt", "hello")
        zf.writestr("bad.txt", "expected")
        zf.writestr("missing.txt", "not extracted")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "good.txt").write_text("hello", encoding="utf-8")
    (out_dir / "bad.txt").write_text("oops", encoding="utf-8")
    task = ArchiveTask(fact_bag=FactBag(), score=10, key="sample", main_path=str(archive), all_parts=[str(archive)], detected_ext="zip")
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])

    verification = _scheduler([{"name": "archive_test_crc"}]).verify(task, result)

    assert verification.decision_hint == "repair"
    assert verification.complete_files == 1
    assert verification.failed_files == 1
    assert verification.missing_files == 1
    assert 0.0 < verification.completeness < 1.0
    coverage = [issue for issue in verification.issues if issue.code == "info.archive_output_coverage"][0]
    assert coverage.actual["expected_files"] == 3
    assert coverage.actual["matched_files"] == 2
    assert verification.archive_coverage.expected_files == 3
    assert verification.archive_coverage.matched_files == 2
    assert verification.archive_coverage.complete_files == 1
    assert verification.archive_coverage.failed_files == 1
    assert verification.archive_coverage.missing_files == 1
    assert verification.archive_coverage.sources[0]["code"] == "info.archive_output_coverage"


def test_output_presence_uses_worker_manifest_progress_as_completeness(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    complete = out_dir / "complete.txt"
    partial = out_dir / "partial.bin"
    complete.write_text("ok", encoding="utf-8")
    partial.write_bytes(b"12345")
    manifest = out_dir / ".packrelic" / "extraction_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({
        "files": [
            {"path": str(complete), "archive_path": "complete.txt", "status": "complete", "bytes_written": 2, "expected_size": 2},
            {"path": str(partial), "archive_path": "partial.bin", "status": "partial", "bytes_written": 5, "expected_size": 10},
            {"path": "missing.bin", "archive_path": "missing.bin", "status": "failed", "bytes_written": 0, "expected_size": 10},
        ],
        "summary": {"complete": 1, "partial": 1, "failed": 1, "total": 3},
    }), encoding="utf-8")
    task = _task(tmp_path)
    result = ExtractionResult(
        success=True,
        archive=str(archive),
        out_dir=str(out_dir),
        all_parts=[str(archive)],
        progress_manifest=str(manifest),
    )

    verification = _scheduler([{"name": "output_presence"}]).verify(task, result)

    assert verification.complete_files == 1
    assert verification.partial_files == 1
    assert verification.failed_files == 1
    assert round(verification.completeness, 3) == 0.5
    assert verification.archive_coverage.expected_files == 3
    assert verification.archive_coverage.matched_files == 2
    assert verification.archive_coverage.expected_bytes == 22
    assert verification.archive_coverage.matched_bytes == 7
    assert round(verification.archive_coverage.completeness, 3) == 0.5


def _task(tmp_path, analysis=None):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    bag = FactBag()
    bag.set("resource.analysis", analysis or {})
    return ArchiveTask(fact_bag=bag, score=10, key="sample", main_path=str(archive), all_parts=[str(archive)])


def _scheduler(methods):
    return VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": methods,
        }
    })
