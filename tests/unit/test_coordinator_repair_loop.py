from pathlib import Path

from sunpack.analysis.result import ArchiveAnalysisReport
from sunpack.analysis.scheduler import ArchiveAnalysisScheduler
from sunpack.contracts.detection import FactBag
from sunpack.contracts.run_context import RunContext
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner
from sunpack.extraction.result import ExtractionResult
from sunpack.repair.candidate import RepairCandidate, RepairCandidateBatch
from sunpack.verification.result import ArchiveCoverageSummary, VerificationResult


def test_extraction_failure_repair_reanalysis_loop_skips_reanalysis_after_accepted_candidate(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"broken")
    fixed_1 = tmp_path / "fixed-1.zip"
    fixed_2 = tmp_path / "fixed-2.zip"
    fixed_1.write_bytes(b"fixed:one")
    fixed_2.write_bytes(b"fixed:two")
    out_dir = tmp_path / "out"
    task = _task(source)
    extractor = _PatchPlanExtractor(accept_name="fixed-2.zip")
    runner = _runner(tmp_path, extractor)
    runner.analysis_stage = _FakeAnalysisStage()
    runner.repair_stage.scheduler = _SequencedBeamCandidateScheduler([fixed_1, fixed_2])

    outcome = runner._extract_verify_with_retries(task, str(out_dir), runtime_scheduler=None)

    assert outcome.success is True
    assert runner.analysis_stage.calls == 1
    archive_input = task.archive_input()
    assert archive_input.entry_path.endswith("fixed-2.zip")
    rounds = task.fact_bag.get("repair.loop.rounds")
    assert len(rounds) == 2
    assert rounds[0]["trigger"] == "verification_beam"
    assert rounds[0]["module"] == "fixed-1"
    assert rounds[1]["trigger"] == "verification_beam"
    assert rounds[1]["module"] == "fixed-2"
    assert not task.fact_bag.get("repair.loop.terminal_reason")


def test_repair_loop_stops_when_patch_plan_does_not_improve(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"broken")
    worse = tmp_path / "worse.zip"
    worse.write_bytes(b"worse")
    out_dir = tmp_path / "out"
    task = _task(source)
    extractor = _PatchPlanExtractor(accept_name="never.zip")
    runner = _runner(tmp_path, extractor)
    runner.analysis_stage = _FakeAnalysisStage()
    runner.repair_stage.scheduler = _SequencedBeamCandidateScheduler([worse])

    outcome = runner._extract_verify_with_retries(task, str(out_dir), runtime_scheduler=None)

    assert outcome.success is False
    assert task.fact_bag.get("repair.loop.terminal_reason") == "no_repair_improvement"
    assert task.fact_bag.get("repair.loop.rounds") in (None, [])


def test_analysis_scheduler_reanalyzes_repaired_archive_input_file(tmp_path):
    source = tmp_path / "original.zip"
    repaired = tmp_path / "repaired.zip"
    source.write_bytes(b"broken")
    repaired.write_bytes(b"fixed")
    task = _task(source)
    task.set_archive_input({
        "kind": "archive_input",
        "entry_path": str(repaired),
        "open_mode": "file",
        "format_hint": "zip",
    })
    scheduler = _RecordingAnalysisScheduler()

    scheduler.analyze_task(task)

    assert scheduler.paths == [str(repaired)]


def test_verification_repair_uses_beam_to_select_complete_candidate(tmp_path):
    source = tmp_path / "broken.zip"
    bad = tmp_path / "bad.zip"
    good = tmp_path / "good.zip"
    source.write_bytes(b"broken")
    bad.write_bytes(b"bad")
    good.write_bytes(b"good")
    out_dir = tmp_path / "out"
    task = _task(source)
    task.fact_bag.set("analysis.selected_format", "zip")
    extractor = _ArchiveInputExtractor()
    runner = ExtractionBatchRunner(
        RunContext(),
        extractor,
        _FakeOutputScanPolicy(),
        config={
            "repair": {
                "workspace": str(tmp_path / "repair"),
                "max_repair_rounds_per_task": 2,
                "beam": {
                    "enabled": True,
                    "beam_width": 2,
                    "max_candidates_per_state": 2,
                    "max_analyze_candidates": 2,
                    "max_assess_candidates": 2,
                    "max_rounds": 1,
                    "min_improvement": 0.0,
                },
            },
            "verification": {"enabled": True, "methods": []},
        },
    )
    runner.verifier = _PathAwareVerifier()
    runner.repair_stage.scheduler = _BeamCandidateScheduler(bad, good)
    runner.analysis_stage = _FakeAnalysisStage()

    outcome = runner._extract_verify_with_retries(task, str(out_dir), runtime_scheduler=None)

    assert outcome.success is True
    assert outcome.verification.decision_hint == "accept"
    selected_input = task.archive_input()
    assert selected_input.entry_path.endswith("round_01_good_candidate.zip")
    assert Path(selected_input.entry_path).read_bytes() == good.read_bytes()
    assert (out_dir / "good.txt").exists()


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
        return VerificationResult(decision_hint="accept", assessment_status="complete", completeness=1.0)


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


class _ArchiveInputExtractor:
    password_session = None

    def default_output_dir_for_task(self, task):
        return str(Path(task.main_path).with_suffix(""))

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        descriptor = task.archive_input()
        archive = descriptor.entry_path or task.main_path
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        if "good" in Path(archive).name:
            (Path(out_dir) / "good.txt").write_text("ok", encoding="utf-8")
        else:
            (Path(out_dir) / "bad.txt").write_text("bad", encoding="utf-8")
        return ExtractionResult(success=True, archive=archive, out_dir=str(out_dir), all_parts=[archive])


class _PatchPlanExtractor:
    password_session = None

    def __init__(self, *, accept_name):
        self.accept_name = accept_name

    def default_output_dir_for_task(self, task):
        return str(Path(task.main_path).with_suffix(""))

    def inspect(self, task, out_dir):
        return type("Preflight", (), {"skip_result": None})()

    def extract(self, task, out_dir, runtime_scheduler=None):
        archive = task.archive_input().entry_path or task.main_path
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        if Path(archive).name == self.accept_name:
            (Path(out_dir) / "ok.txt").write_text("ok", encoding="utf-8")
            return ExtractionResult(success=True, archive=archive, out_dir=str(out_dir), all_parts=[archive])
        return _failed(Path(archive), Path(out_dir))


class _PathAwareVerifier:
    config = {"max_retries": 0, "cleanup_failed_output": True}

    def verify(self, task, result):
        if "good" in Path(result.archive).name or "fixed-2" in Path(result.archive).name:
            return _verification("accept", 1.0)
        if "fixed-1" in Path(result.archive).name:
            return _verification("repair", 0.5)
        return _verification("repair", 0.2)


class _BeamCandidateScheduler:
    def __init__(self, bad, good):
        self.bad = bad
        self.good = good
        self.jobs = []

    def generate_repair_candidates(self, job):
        self.jobs.append(job)
        return RepairCandidateBatch(candidates=[
            _candidate("bad_candidate", self.bad, 0.9),
            _candidate("good_candidate", self.good, 0.5),
        ])


class _SequencedBeamCandidateScheduler:
    def __init__(self, paths):
        self.paths = list(paths)
        self.jobs = []

    def generate_repair_candidates(self, job, *, lazy=False):
        self.jobs.append(job)
        if not self.paths:
            return RepairCandidateBatch(candidates=[])
        path = self.paths.pop(0)
        return RepairCandidateBatch(candidates=[
            _candidate(Path(path).stem, path, 0.8),
        ])


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


def _runner(tmp_path, extractor):
    runner = ExtractionBatchRunner(
        RunContext(),
        extractor,
        _FakeOutputScanPolicy(),
        config={
            "repair": {
                "workspace": str(tmp_path / "repair"),
                "max_repair_rounds_per_task": 3,
                "beam": {
                    "enabled": True,
                    "beam_width": 1,
                    "max_candidates_per_state": 1,
                    "max_analyze_candidates": 1,
                    "max_assess_candidates": 1,
                    "max_rounds": 1,
                },
            },
        },
    )
    runner.verifier = _PathAwareVerifier()
    return runner


def _candidate(module, path, confidence):
    return RepairCandidate(
        module_name=module,
        format="zip",
        repaired_input={"kind": "file", "path": str(path), "format_hint": "zip"},
        confidence=confidence,
        actions=[module],
        workspace_paths=[str(path)],
    )


def _verification(decision, completeness):
    status = "complete" if decision == "accept" else "partial"
    return VerificationResult(
        completeness=completeness,
        recoverable_upper_bound=1.0,
        assessment_status=status,
        source_integrity="complete",
        decision_hint=decision,
        archive_coverage=ArchiveCoverageSummary(
            completeness=completeness,
            file_coverage=completeness,
            byte_coverage=completeness,
            expected_files=1,
            matched_files=1 if completeness > 0 else 0,
            complete_files=1 if completeness >= 1 else 0,
            confidence=0.9,
        ),
    )


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
