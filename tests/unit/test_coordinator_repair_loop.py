from pathlib import Path

from smart_unpacker.analysis.result import ArchiveAnalysisReport
from smart_unpacker.analysis.scheduler import ArchiveAnalysisScheduler
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.run_context import RunContext
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.extraction_batch import ExtractionBatchRunner
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.repair.result import RepairResult


def test_extraction_failure_repair_reanalysis_loop_runs_until_success(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"broken")
    fixed_1 = tmp_path / "fixed-1.zip"
    fixed_2 = tmp_path / "fixed-2.zip"
    out_dir = tmp_path / "out"
    task = _task(source)
    extractor = _FakeExtractor([
        _failed(source, out_dir),
        _failed(fixed_1, out_dir),
        ExtractionResult(success=True, archive=str(fixed_2), out_dir=str(out_dir), all_parts=[str(fixed_2)]),
    ])
    runner = _runner(tmp_path, extractor)
    runner.analysis_stage = _FakeAnalysisStage()
    runner.repair_stage = _FakeRepairStage([fixed_1, fixed_2])

    outcome = runner._extract_verify_with_retries(task, str(out_dir), runtime_scheduler=None)

    assert outcome.success is True
    assert runner.analysis_stage.calls == 2
    assert task.fact_bag.get("archive.input")["entry_path"] == str(fixed_2)
    assert len(task.fact_bag.get("repair.loop.rounds")) == 2
    assert not task.fact_bag.get("repair.loop.terminal_reason")


def test_repair_loop_stops_when_repaired_input_repeats(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"broken")
    fixed = tmp_path / "fixed.zip"
    out_dir = tmp_path / "out"
    task = _task(source)
    extractor = _FakeExtractor([
        _failed(source, out_dir),
        _failed(fixed, out_dir),
    ])
    runner = _runner(tmp_path, extractor)
    runner.analysis_stage = _FakeAnalysisStage()
    runner.repair_stage = _FakeRepairStage([fixed, fixed])

    outcome = runner._extract_verify_with_retries(task, str(out_dir), runtime_scheduler=None)

    assert outcome.success is False
    assert task.fact_bag.get("repair.loop.terminal_reason") == "repeated_repair_input"
    assert len(task.fact_bag.get("repair.loop.rounds")) == 2


def test_analysis_scheduler_reanalyzes_repaired_archive_input_file(tmp_path):
    source = tmp_path / "original.zip"
    repaired = tmp_path / "repaired.zip"
    source.write_bytes(b"broken")
    repaired.write_bytes(b"fixed")
    task = _task(source)
    task.fact_bag.set("archive.input", {
        "kind": "archive_input",
        "entry_path": str(repaired),
        "open_mode": "file",
        "format_hint": "zip",
    })
    scheduler = _RecordingAnalysisScheduler()

    scheduler.analyze_task(task)

    assert scheduler.paths == [str(repaired)]


class _FakeOutputScanPolicy:
    def scan_roots_from_outputs(self, outputs):
        return list(outputs)


class _RecordingAnalysisScheduler(ArchiveAnalysisScheduler):
    def __init__(self):
        self.paths = []

    def analyze_path(self, path):
        self.paths.append(str(path))
        return ArchiveAnalysisReport(path=str(path), size=0, evidences=[], selected=[])


class _FakeVerifier:
    config = {"max_retries": 0, "cleanup_failed_output": True}

    def verify(self, task, result):
        return type("Verification", (), {"ok": True})()


class _FakeExtractor:
    password_session = None

    def __init__(self, results):
        self.results = list(results)

    def default_output_dir_for_task(self, task):
        return str(Path(task.main_path).with_suffix(""))

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        return self.results.pop(0)


class _FakeAnalysisStage:
    def __init__(self):
        self.calls = 0

    def analyze_task(self, task):
        self.calls += 1
        task.fact_bag.set("analysis.selected_format", "zip")
        return ArchiveAnalysisReport(path=task.main_path, size=0, evidences=[], selected=[])

    def analyze_task_to_tasks(self, task):
        self.analyze_task(task)
        return [task]


class _FakeRepairStage:
    def __init__(self, repaired_paths):
        self.paths = list(repaired_paths)
        self.config = {
            "max_repair_rounds_per_task": 3,
            "max_repair_seconds_per_task": 120.0,
            "max_repair_generated_files_per_task": 16,
            "max_repair_generated_mb_per_task": 2048.0,
        }

    def repair_medium_confidence_task(self, task):
        return None

    def repair_after_extraction_failure_result(self, task, result):
        path = self.paths.pop(0)
        path.write_bytes(f"fixed:{path.name}".encode("ascii"))
        task.fact_bag.set("archive.input", {
            "kind": "archive_input",
            "entry_path": str(path),
            "open_mode": "file",
            "format_hint": "zip",
        })
        return RepairResult(
            status="repaired",
            confidence=0.9,
            format="zip",
            repaired_input={"kind": "file", "path": str(path), "format_hint": "zip"},
            actions=["fake_fix"],
            workspace_paths=[str(path)],
            module_name="fake_repair",
        )


def _runner(tmp_path, extractor):
    runner = ExtractionBatchRunner(
        RunContext(),
        extractor,
        _FakeOutputScanPolicy(),
        config={"repair": {"workspace": str(tmp_path / "repair"), "max_repair_rounds_per_task": 3}},
    )
    runner.verifier = _FakeVerifier()
    return runner


def _task(path: Path) -> ArchiveTask:
    return ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
        detected_ext=path.suffix.lstrip("."),
    )


def _failed(path: Path, out_dir: Path) -> ExtractionResult:
    return ExtractionResult(
        success=False,
        archive=str(path),
        out_dir=str(out_dir),
        all_parts=[str(path)],
        error="压缩包损坏",
        diagnostics={
            "failure_stage": "archive_open",
            "failure_kind": "structure_recognition",
            "result": {
                "status": "failed",
                "native_status": "damaged",
                "failure_stage": "archive_open",
                "failure_kind": "structure_recognition",
                "damaged": True,
            },
        },
    )
