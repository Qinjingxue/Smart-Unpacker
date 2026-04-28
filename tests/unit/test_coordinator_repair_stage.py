from pathlib import Path

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.repair_stage import ArchiveRepairStage
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.repair.result import RepairResult


def test_repair_stage_repairs_medium_confidence_analysis(tmp_path):
    source = tmp_path / "carrier.bin"
    repaired = tmp_path / "repaired.zip"
    source.write_bytes(b"shellPK")
    repaired.write_bytes(b"PK")
    task = _task(source)
    task.fact_bag.set("analysis.evidences", [
        {
            "format": "zip",
            "confidence": 0.62,
            "status": "damaged",
            "segments": [
                {
                    "start_offset": 5,
                    "end_offset": None,
                    "confidence": 0.62,
                    "damage_flags": ["boundary_unreliable", "local_header_recovery"],
                }
            ],
        }
    ])
    scheduler = _FakeRepairScheduler(repaired)
    stage = ArchiveRepairStage({"repair": {"workspace": str(tmp_path / "repair")}})
    stage.scheduler = scheduler

    stage.repair_medium_confidence_tasks([task])

    assert scheduler.jobs[0].format == "zip"
    assert scheduler.jobs[0].source_input["kind"] == "file_range"
    assert task.fact_bag.get("archive.repaired") is True
    archive_input = task.archive_input()
    assert archive_input.open_mode == "file"
    assert archive_input.entry_path == str(repaired)


def test_repair_stage_repairs_after_extraction_failure(tmp_path):
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

    assert stage.repair_after_extraction_failure(task, result) is True
    assert scheduler.jobs[0].extraction_failure["damaged"] is True
    assert scheduler.jobs[0].extraction_failure["failure_stage"] == "archive_open"
    assert scheduler.jobs[0].extraction_failure["failure_kind"] == "structure_recognition"
    assert scheduler.jobs[0].extraction_failure["native_diagnostics"]["input_trace"]["mode"] == "file"
    assert scheduler.jobs[0].extraction_diagnostics["result"]["native_status"] == "damaged"
    assert task.archive_state().source.entry_path == str(repaired)


def test_repair_stage_passes_partial_output_progress_to_repair_job(tmp_path):
    source = tmp_path / "payload_bad.zip"
    repaired = tmp_path / "partial.zip"
    source.write_bytes(b"broken")
    repaired.write_bytes(b"partial")
    manifest = tmp_path / "out" / ".sunpack" / "extraction_manifest.json"
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

    assert stage.repair_after_extraction_failure(task, result) is True
    failure = scheduler.jobs[0].extraction_failure
    assert failure["partial_outputs"] is True
    assert failure["progress_manifest"] == str(manifest)
    assert failure["files_written"] == 1
    assert failure["bytes_written"] == 128
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
