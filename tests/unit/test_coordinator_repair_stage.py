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
    archive_input = task.fact_bag.get("archive.input")
    assert archive_input["kind"] == "archive_input"
    assert archive_input["open_mode"] == "file"
    assert archive_input["entry_path"] == str(repaired)


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
    )

    assert stage.repair_after_extraction_failure(task, result) is True
    assert scheduler.jobs[0].extraction_failure["damaged"] is True
    assert task.fact_bag.get("archive.input")["entry_path"] == str(repaired)


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
