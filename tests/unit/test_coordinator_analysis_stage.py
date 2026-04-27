from smart_unpacker.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence, ArchiveSegment
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask, SplitArchiveInfo
from smart_unpacker.coordinator.analysis_stage import ArchiveAnalysisStage


class _FakeAnalysisScheduler:
    def __init__(self, report):
        self.report = report

    def analyze_task(self, task):
        return self.report


def _task(path, *, parts=None, volumes=None):
    bag = FactBag()
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(item) for item in (parts or [path])])
    return ArchiveTask(
        fact_bag=bag,
        score=10,
        main_path=str(path),
        all_parts=[str(item) for item in (parts or [path])],
        logical_name="case",
        split_info=SplitArchiveInfo(
            is_split=bool(parts and len(parts) > 1),
            parts=[str(item) for item in (parts or [path])],
            volumes=volumes or [],
        ),
    )


def _report(path, evidence):
    return ArchiveAnalysisReport(
        path=str(path),
        size=100,
        evidences=[evidence],
        selected=[evidence],
        prepass={"formats": [evidence.format]},
        read_bytes=32,
        cache_hits=1,
    )


def test_analysis_stage_writes_file_range_input(tmp_path):
    archive = tmp_path / "carrier.bin"
    archive.write_bytes(b"junk" + b"PK\x03\x04" + b"x" * 32 + b"tail")
    evidence = ArchiveFormatEvidence(
        format="zip",
        confidence=0.99,
        status="extractable",
        segments=[ArchiveSegment(start_offset=4, end_offset=40, confidence=0.99)],
    )
    task = _task(archive)
    stage = ArchiveAnalysisStage({"analysis": {"enabled": False}})
    stage.enabled = True
    stage.scheduler = _FakeAnalysisScheduler(_report(archive, evidence))

    stage.analyze_task(task)

    assert task.fact_bag.get("analysis.selected_format") == "zip"
    assert task.fact_bag.get("analysis.segment")["start_offset"] == 4
    assert task.fact_bag.get("archive.input") == {
        "kind": "archive_input",
        "entry_path": str(archive),
        "open_mode": "file_range",
        "format_hint": "zip",
        "logical_name": "case",
        "parts": [{"path": str(archive), "role": "main", "start": 4, "end": 40}],
        "segment": {"start": 4, "source": "analysis", "end": 40, "confidence": 0.99},
        "analysis": {"status": "extractable", "confidence": 0.99, "damage_flags": []},
    }


def test_analysis_stage_maps_split_logical_segment_to_concat_ranges(tmp_path):
    part1 = tmp_path / "case.7z.001"
    part2 = tmp_path / "case.7z.002"
    part3 = tmp_path / "case.7z.003"
    part1.write_bytes(b"a" * 10)
    part2.write_bytes(b"b" * 10)
    part3.write_bytes(b"c" * 10)
    volumes = [
        {"path": str(part2), "number": 2},
        {"path": str(part1), "number": 1},
        {"path": str(part3), "number": 3},
    ]
    evidence = ArchiveFormatEvidence(
        format="7z",
        confidence=0.97,
        status="extractable",
        segments=[ArchiveSegment(start_offset=8, end_offset=24, confidence=0.97)],
    )
    task = _task(part1, parts=[part1, part2, part3], volumes=volumes)
    stage = ArchiveAnalysisStage({"analysis": {"enabled": False}})
    stage.enabled = True
    stage.scheduler = _FakeAnalysisScheduler(_report(part1, evidence))

    stage.analyze_task(task)

    assert task.fact_bag.get("archive.input") == {
        "kind": "archive_input",
        "entry_path": str(part1),
        "open_mode": "concat_ranges",
        "format_hint": "7z",
        "logical_name": "case",
        "ranges": [
            {"path": str(part1), "start": 8, "end": 10},
            {"path": str(part2), "start": 0, "end": 10},
            {"path": str(part3), "start": 0, "end": 4},
        ],
        "segment": {"start": 8, "source": "analysis", "end": 24, "confidence": 0.97},
        "analysis": {"status": "extractable", "confidence": 0.97, "damage_flags": []},
    }
