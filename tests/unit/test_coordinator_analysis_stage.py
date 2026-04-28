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


def _multi_report(path, evidences):
    return ArchiveAnalysisReport(
        path=str(path),
        size=200,
        evidences=list(evidences),
        selected=list(evidences),
        prepass={"formats": [evidence.format for evidence in evidences]},
        read_bytes=64,
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
    assert task.archive_input().to_dict() == {
        "kind": "archive_input",
        "entry_path": str(archive),
        "open_mode": "file_range",
        "format_hint": "zip",
        "logical_name": "case",
        "parts": [{"path": str(archive), "role": "main", "start": 4, "end": 40}],
        "segment": {"start": 4, "source": "analysis", "end": 40, "confidence": 0.99},
        "analysis": {"status": "extractable", "confidence": 0.99, "damage_flags": []},
    }
    state = task.fact_bag.get("archive.state")
    assert state["source"]["open_mode"] == "file_range"
    assert state["source"]["parts"][0]["start"] == 4
    assert state["patches"] == []


def test_analysis_stage_expands_carrier_into_logical_archive_tasks(tmp_path):
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"junk" + b"Rar!\x1a\x07\x01\x00" + b"x" * 20 + b"pad" + b"7z\xbc\xaf\x27\x1c" + b"y" * 20)
    rar = ArchiveFormatEvidence(
        format="rar",
        confidence=0.97,
        status="extractable",
        segments=[ArchiveSegment(start_offset=4, end_offset=32, confidence=0.97)],
    )
    seven = ArchiveFormatEvidence(
        format="7z",
        confidence=0.96,
        status="extractable",
        segments=[ArchiveSegment(start_offset=35, end_offset=61, confidence=0.96)],
    )
    task = _task(carrier)
    stage = ArchiveAnalysisStage({"analysis": {"enabled": False}})
    stage.enabled = True
    stage.scheduler = _FakeAnalysisScheduler(_multi_report(carrier, [rar, seven]))

    tasks = stage.analyze_tasks([task])

    assert [item.logical_name for item in tasks] == ["case_01_rar", "case_02_7z"]
    assert [item.fact_bag.get("analysis.selected_format") for item in tasks] == ["rar", "7z"]
    assert tasks[0].archive_input().to_dict() == {
        "kind": "archive_input",
        "entry_path": str(carrier),
        "open_mode": "file_range",
        "format_hint": "rar",
        "logical_name": "case_01_rar",
        "parts": [{"path": str(carrier), "role": "main", "start": 4, "end": 32}],
        "segment": {"start": 4, "source": "analysis", "end": 32, "confidence": 0.97},
        "analysis": {"status": "extractable", "confidence": 0.97, "damage_flags": []},
    }
    assert tasks[1].archive_input().format_hint == "7z"
    assert tasks[1].archive_input().parts[0].range.start == 35
    assert tasks[1].key.endswith("#segment2:7z")


def test_analysis_stage_prefers_compressed_tar_over_stream_for_same_range(tmp_path):
    archive = tmp_path / "payload.tar.gz"
    archive.write_bytes(b"gzipped tar")
    gzip = ArchiveFormatEvidence(
        format="gzip",
        confidence=0.88,
        status="extractable",
        segments=[ArchiveSegment(start_offset=0, end_offset=100, confidence=0.88)],
    )
    tar_gz = ArchiveFormatEvidence(
        format="tar.gz",
        confidence=0.93,
        status="extractable",
        segments=[ArchiveSegment(start_offset=0, end_offset=100, confidence=0.93)],
    )
    task = _task(archive)
    stage = ArchiveAnalysisStage({"analysis": {"enabled": False}})
    stage.enabled = True
    stage.scheduler = _FakeAnalysisScheduler(_multi_report(archive, [gzip, tar_gz]))

    tasks = stage.analyze_tasks([task])

    assert tasks == [task]
    assert task.fact_bag.get("analysis.selected_format") == "tar.gz"


def test_analysis_stage_uses_range_input_for_embedded_password_required_archive(tmp_path):
    carrier = tmp_path / "payload.exe"
    carrier.write_bytes(b"MZ" + b"x" * 198)
    evidence = ArchiveFormatEvidence(
        format="rar",
        confidence=0.72,
        status="damaged",
        segments=[
            ArchiveSegment(
                start_offset=64,
                end_offset=None,
                confidence=0.72,
                damage_flags=["valid_encrypted_but_unwalkable"],
            )
        ],
        details={"password_required": True, "header_encrypted": True},
    )
    task = _task(carrier)
    stage = ArchiveAnalysisStage({"analysis": {"enabled": False}})
    stage.enabled = True
    stage.scheduler = _FakeAnalysisScheduler(_multi_report(carrier, [evidence]))

    stage.analyze_task(task)

    assert task.fact_bag.get("analysis.selected_format") == "rar"
    assert task.archive_input().to_dict() == {
        "kind": "archive_input",
        "entry_path": str(carrier),
        "open_mode": "file_range",
        "format_hint": "rar",
        "logical_name": "case",
        "parts": [{"path": str(carrier), "role": "main", "start": 64}],
        "segment": {"start": 64, "source": "analysis", "confidence": 0.72},
        "analysis": {
            "status": "damaged",
            "confidence": 0.72,
            "damage_flags": ["valid_encrypted_but_unwalkable"],
        },
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

    assert task.archive_input().to_dict() == {
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
    state = task.fact_bag.get("archive.state")
    assert state["source"]["open_mode"] == "concat_ranges"
    assert [item["path"] for item in state["source"]["ranges"]] == [str(part1), str(part2), str(part3)]
