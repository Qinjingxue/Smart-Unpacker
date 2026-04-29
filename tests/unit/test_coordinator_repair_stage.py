from pathlib import Path

from packrelic.contracts.detection import FactBag
from packrelic.contracts.tasks import ArchiveTask
from packrelic.coordinator.repair_stage import ArchiveRepairStage
from packrelic.extraction.result import ExtractionResult
from packrelic.repair.result import RepairResult
from packrelic.verification.result import ArchiveCoverageSummary, VerificationResult


def test_repair_stage_builds_job_from_verification_decision(tmp_path):
    source = tmp_path / "broken.zip"
    repaired = tmp_path / "fixed.zip"
    source.write_bytes(b"broken")
    repaired.write_bytes(b"fixed")
    task = _task(source)
    scheduler = _FakeRepairScheduler(repaired)
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair")}})
    stage.scheduler = scheduler
    result = ExtractionResult(
        success=False,
        archive=str(source),
        out_dir=str(tmp_path / "out"),
        all_parts=[str(source)],
        error="压缩包损坏",
        diagnostics={
            "failure_stage": "archive_open",
            "failure_kind": "structure_recognition",
            "result": {
                "type": "result",
                "status": "failed",
                "native_status": "damaged",
                "failure_stage": "archive_open",
                "failure_kind": "structure_recognition",
                "damaged": True,
                "diagnostics": {
                    "input_trace": {"mode": "file", "total_bytes_returned": 128},
                    "handler_attempts": [{"format": "zip", "opened": False}],
                },
            },
        },
    )

    verification = _verification("repair", 0.0)

    repair_result = stage.repair_after_verification_assessment_result(task, result, verification)

    assert repair_result is not None and repair_result.ok is True
    assert scheduler.jobs[0].extraction_failure["damaged"] is True
    assert scheduler.jobs[0].extraction_failure["status"] == "verification_failed"
    assert scheduler.jobs[0].extraction_failure["failure_stage"] == "verification"
    assert scheduler.jobs[0].extraction_failure["decision_hint"] == "repair"
    assert scheduler.jobs[0].extraction_failure["failure_kind"] == "structure_recognition"
    assert scheduler.jobs[0].extraction_failure["native_diagnostics"]["input_trace"]["mode"] == "file"
    assert scheduler.jobs[0].extraction_diagnostics["result"]["native_status"] == "damaged"
    assert task.archive_state().source.entry_path == str(repaired)


def test_repair_stage_passes_verification_progress_to_repair_job(tmp_path):
    source = tmp_path / "payload_bad.zip"
    repaired = tmp_path / "partial.zip"
    source.write_bytes(b"broken")
    repaired.write_bytes(b"partial")
    manifest = tmp_path / "out" / ".packrelic" / "extraction_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{}", encoding="utf-8")
    task = _task(source)
    scheduler = _FakeRepairScheduler(repaired)
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair")}})
    stage.scheduler = scheduler
    result = ExtractionResult(
        success=False,
        archive=str(source),
        out_dir=str(tmp_path / "out"),
        all_parts=[str(source)],
        error="CRC Failed",
        partial_outputs=True,
        progress_manifest=str(manifest),
        diagnostics={
            "failure_stage": "item_extract",
            "failure_kind": "checksum_error",
            "result": {
                "status": "failed",
                "native_status": "damaged",
                "failure_stage": "item_extract",
                "failure_kind": "checksum_error",
                "checksum_error": True,
                "files_written": 1,
                "bytes_written": 128,
                "diagnostics": {
                    "output_trace": {
                        "items": [
                            {"path": str(tmp_path / "out" / "good.txt"), "archive_path": "good.txt", "failed": False, "bytes_written": 64},
                            {"path": str(tmp_path / "out" / "bad.bin"), "archive_path": "bad.bin", "failed": True, "bytes_written": 64},
                        ]
                    }
                },
            },
        },
    )

    verification = _verification("repair", 0.5)

    repair_result = stage.repair_after_verification_assessment_result(task, result, verification)

    assert repair_result is not None and repair_result.ok is True
    failure = scheduler.jobs[0].extraction_failure
    assert failure["partial_outputs"] is True
    assert failure["progress_manifest"] == str(manifest)
    assert failure["files_written"] == 1
    assert failure["bytes_written"] == 128
    assert failure["decision_hint"] == "repair"
    assert failure["completeness"] == 0.5
    assert len(failure["complete_items"]) == 1
    assert len(failure["failed_items"]) == 1
    assert failure["output_trace"]["items"][1]["archive_path"] == "bad.bin"


class _FakeRepairScheduler:
    def __init__(self, repaired_path: Path):
        self.repaired_path = repaired_path
        self.jobs = []

    def repair(self, job):
        self.jobs.append(job)
        return RepairResult(
            status="repaired",
            confidence=0.9,
            format=job.format,
            repaired_input={"kind": "file", "path": str(self.repaired_path), "format_hint": job.format},
            module_name="fake_repair",
        )


def _task(path: Path) -> ArchiveTask:
    return ArchiveTask(
        fact_bag=FactBag(),
        score=100,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
        detected_ext=path.suffix.lstrip("."),
    )


def _verification(decision: str, completeness: float) -> VerificationResult:
    return VerificationResult(
        completeness=completeness,
        recoverable_upper_bound=1.0,
        assessment_status="partial",
        source_integrity="damaged",
        decision_hint=decision,
        archive_coverage=ArchiveCoverageSummary(
            completeness=completeness,
            file_coverage=completeness,
            byte_coverage=completeness,
            expected_files=2,
            matched_files=1,
            complete_files=1 if completeness else 0,
            failed_files=1,
            confidence=0.9,
        ),
    )
