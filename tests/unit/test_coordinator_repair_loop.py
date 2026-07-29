from pathlib import Path

from sunpack.analysis.result import ArchiveAnalysisReport
from sunpack.analysis import ArchiveAnalyzer
from sunpack.analysis.engine import AnalysisEngine
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair.loop import RepairLoopLimits, RepairLoopState
from sunpack.contracts.extraction import ExtractionResult
from sunpack.repair.result import RepairResult
from sunpack.contracts.verification import ArchiveCoverageSummary, VerificationResult
from sunpack.coordinator.repair_runtime_transition import RepairRuntimeTransitionEvaluator
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner
from sunpack.repair.candidate import RepairCandidate
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.inspect import ArchiveInspector, InspectionFeedback


def test_inspector_reanalyzes_repaired_archive_input_file(tmp_path):
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
    engine = _RecordingAnalysisEngine()

    ArchiveInspector(analyzer=ArchiveAnalyzer(engine=engine)).analyze_task(task)

    assert engine.paths == [str(repaired)]


def test_policy_stop_records_final_extraction_gate(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"broken")
    task = _task(source)
    state = RepairLoopState(task, RepairLoopLimits(max_rounds=3))
    result = RepairResult(
        status="partial",
        module_name="policy_finish",
        format="zip",
        actions=["policy_finish"],
        repaired_input={"kind": "file", "path": str(source), "format_hint": "zip"},
        diagnosis={
            "policy_stop_requested": True,
            "policy_loop": {"terminal_action": "stop", "policy_stop_requested": True},
        },
        partial=True,
        message="policy_step_stop",
    )

    handled = state.record_result(result, trigger="verification_policy")

    assert handled is True
    assert task.knowledge().get("repair.loop.terminal_reason") == "policy_stop"
    assert task.knowledge().get("repair.loop.policy_stop_after_next_extraction") is True
    assert task.knowledge().get("repair.loop.repair_disabled_after_policy_stop") is True
    assert RepairLoopState(task, RepairLoopLimits(max_rounds=3)).can_attempt(trigger="verification") is False


def test_recovery_no_improvement_requires_patience(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"broken")
    task = _task(source)
    state = RepairLoopState(
        task,
        RepairLoopLimits(max_rounds=100, comparison_no_improvement_patience_rounds=20),
    )
    comparison = {"stop_reason": "no_improvement", "should_continue_repair": False}

    for _ in range(19):
        assert state.record_recovery_comparison(comparison, trigger="verification_comparison") is False
        assert not task.knowledge().get("repair.loop.terminal_reason")

    assert state.record_recovery_comparison(comparison, trigger="verification_comparison") is True
    assert task.knowledge().get("repair.loop.terminal_reason") == "comparison_no_improvement_patience"


class _FakeOutputScanPolicy:
    def scan_roots_from_outputs(self, outputs):
        return list(outputs)


class _RecordingAnalysisEngine(AnalysisEngine):
    def __init__(self):
        self.paths = []

    def analyze_path(self, path, **_kwargs):
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


class _FakeAnalysisStage:
    def __init__(self):
        self.calls = 0

    def analyze_task(self, task):
        self.calls += 1
        task.fact_bag.set("inspection.selected_format", "zip")
        return ArchiveAnalysisReport(path=task.main_path, size=0, evidences=[], selected=[])

    def analyze_task_to_tasks(self, task):
        self.analyze_task(task)
        return [task]


class _FakeInspector:
    def __init__(self):
        self.calls = 0

    def inspect_task(self, task, use_cache=True):
        self.calls += 1
        return type("Feedback", (), {
            "to_score_payload": lambda self: {
                "status": "damaged",
                "format": "zip",
                "confidence": 0.8,
            },
        })()

    def refresh_task(self, task):
        self.calls += 1
        task.fact_bag.set("inspection.status", "damaged")
        return InspectionFeedback(status="damaged", format="zip", confidence=0.8)


class _FakeRepairStage:
    def _descriptor_from_repaired_input(self, task, repaired_input):
        return ArchiveInputDescriptor.from_any(
            repaired_input,
            archive_path=task.main_path,
            part_paths=task.all_parts,
        )


def test_runtime_transition_can_shadow_inspect_candidate(tmp_path):
    source = tmp_path / "broken.zip"
    repaired = tmp_path / "good.zip"
    source.write_bytes(b"broken")
    repaired.write_bytes(b"fixed")
    task = _task(source)
    inspector = _FakeInspector()
    evaluator = RepairRuntimeTransitionEvaluator(
        extractor=_ArchiveInputExtractor(),
        verifier=_FakeVerifier(),
        repair_stage=_FakeRepairStage(),
        inspector=inspector,
    )
    candidate = RepairCandidate(
        module_name="test_repair",
        format="zip",
        repaired_input={"kind": "file", "path": str(repaired), "format_hint": "zip"},
        confidence=0.7,
    )

    transition = evaluator.evaluate(
        task,
        candidate,
        temp_dir=tmp_path / "candidate-output",
        inspect_candidate=True,
    )

    assert inspector.calls == 1
    assert transition.inspection_feedback == {
        "status": "damaged",
        "format": "zip",
        "confidence": 0.8,
    }


def test_repair_entry_refreshes_inspection_feedback(tmp_path):
    source = tmp_path / "broken.zip"
    source.write_bytes(b"broken")
    task = _task(source)
    inspector = _FakeInspector()
    runner = ExtractionBatchRunner.__new__(ExtractionBatchRunner)
    runner.inspector = inspector

    runner._inspect_before_repair(task)

    assert inspector.calls == 1
    assert task.fact_bag.get("inspection.status") == "damaged"
    assert task.knowledge().get("repair.candidate_log")[-1]["phase"] == "inspection_before_repair"


def _verification(decision, completeness):
    status = "complete" if decision == "accept" else "partial"
    return VerificationResult(
        completeness=completeness,
        recoverable_upper_bound=1.0,
        assessment_status=status,
        content_integrity="verified_complete",
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
