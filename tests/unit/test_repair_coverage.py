from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules.zip.central_directory import ZipCentralDirectoryRebuild
from sunpack.repair.pipeline.modules.zip.data_descriptor import ZipDataDescriptorRecovery
from sunpack.repair.pipeline.modules.zip.deep_partial_recovery import ZipDeepPartialRecovery
from sunpack.repair.pipeline.modules.zip.partial_recovery import ZipPartialRecovery


def test_archive_coverage_view_classifies_payload_damage():
    view = coverage_view_from_job(_job(
        complete=1,
        partial=1,
        failed=1,
        missing=0,
        observations=[
            {"archive_path": "bad.bin", "state": "failed", "bytes_written": 0},
            {"archive_path": "half.bin", "state": "partial", "bytes_written": 100, "expected_size": 200},
        ],
    ))

    assert view.payload_only_suspected is True
    assert view.failed_names == ("bad.bin",)
    assert view.partial_names == ("half.bin",)


def test_zip_modules_use_directory_coverage_to_prioritize_directory_rebuild():
    job = _job(complete=2, partial=0, failed=0, missing=1, flags=["directory_integrity_bad_or_unknown"])
    diagnosis = RepairDiagnosis(format="zip", categories=["directory_rebuild"])

    central = ZipCentralDirectoryRebuild().can_handle(job, diagnosis, {})
    partial = ZipPartialRecovery().can_handle(job, diagnosis, {})
    descriptor = ZipDataDescriptorRecovery().can_handle(job, diagnosis, {})

    assert central > partial
    assert central > descriptor


def test_zip_modules_use_payload_coverage_to_prioritize_partial_recovery():
    job = _job(complete=1, partial=1, failed=1, missing=0, flags=["checksum_error"])
    diagnosis = RepairDiagnosis(format="zip", categories=["content_recovery"])

    central = ZipCentralDirectoryRebuild().can_handle(job, diagnosis, {})
    partial = ZipPartialRecovery().can_handle(job, diagnosis, {})
    descriptor = ZipDataDescriptorRecovery().can_handle(job, diagnosis, {})

    assert partial > central
    assert descriptor > central


def test_zip_modules_use_mixed_coverage_to_prioritize_deep_partial_recovery():
    job = _job(complete=1, partial=1, failed=1, missing=1, flags=["checksum_error", "directory_integrity_bad_or_unknown"])
    diagnosis = RepairDiagnosis(format="zip", categories=["content_recovery", "directory_rebuild"])

    deep = ZipDeepPartialRecovery().can_handle(job, diagnosis, {})
    partial = ZipPartialRecovery().can_handle(job, diagnosis, {})
    central = ZipCentralDirectoryRebuild().can_handle(job, diagnosis, {})

    assert deep >= partial
    assert partial >= central


def _job(
    *,
    complete: int,
    partial: int,
    failed: int,
    missing: int,
    flags: list[str] | None = None,
    observations: list[dict] | None = None,
) -> RepairJob:
    expected = complete + partial + failed + missing
    matched = complete + partial + failed
    return RepairJob(
        source_input={"kind": "file", "path": "broken.zip", "format_hint": "zip"},
        format="zip",
        confidence=0.8,
        damage_flags=list(flags or []),
        extraction_failure={
            "status": "verification_failed",
            "failure_stage": "verification",
            "archive_coverage": {
                "completeness": complete / expected if expected else 1.0,
                "file_coverage": matched / expected if expected else 1.0,
                "byte_coverage": 0.5 if partial or failed else 1.0,
                "expected_files": expected,
                "matched_files": matched,
                "complete_files": complete,
                "partial_files": partial,
                "failed_files": failed,
                "missing_files": missing,
                "unverified_files": 0,
                "confidence": 0.9,
            },
            "file_observations": list(observations or []),
        },
    )
