from __future__ import annotations

from pathlib import Path

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.contracts.extraction import ExtractionResult
from sunpack.contracts.run_context import RunContext
from sunpack.contracts.tasks import ArchiveTask
from sunpack.contracts.verification import VerificationResult
from sunpack.coordinator.extraction_batch import BatchExtractionOutcome, ExtractionBatchRunner
from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.postprocess.failed_output_cleanup import REPAIR_ENTERED_FACT, cleanup_failed_output_if_eligible


@pytest.mark.parametrize("with_zero_file", [False, True])
def test_cleanup_removes_failed_output_with_no_payload_bytes(tmp_path, with_zero_file):
    output = tmp_path / "output"
    metadata = output / ".sunpack"
    metadata.mkdir(parents=True)
    (metadata / "diagnostic.json").write_text('{"error": true}', encoding="utf-8")
    if with_zero_file:
        (output / "empty.txt").write_bytes(b"")

    result = cleanup_failed_output_if_eligible(
        str(output),
        planned_output_dir=str(output),
        failed=True,
        repair_entered=False,
    )

    assert result.cleaned is True
    assert not output.exists()


@pytest.mark.parametrize(
    ("failed", "repair_entered", "planned_matches", "expected_reason"),
    [
        (False, False, True, "task_not_failed"),
        (True, True, True, "repair_entered"),
        (True, False, False, "unowned_output_dir"),
    ],
)
def test_cleanup_preserves_output_when_gate_is_not_satisfied(
    tmp_path,
    failed,
    repair_entered,
    planned_matches,
    expected_reason,
):
    output = tmp_path / "output"
    output.mkdir()

    result = cleanup_failed_output_if_eligible(
        str(output),
        planned_output_dir=str(output if planned_matches else tmp_path / "different"),
        failed=failed,
        repair_entered=repair_entered,
    )

    assert result.reason == expected_reason
    assert output.is_dir()


def test_cleanup_preserves_failed_output_with_nonzero_payload(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "payload.bin").write_bytes(b"x")

    result = cleanup_failed_output_if_eligible(
        str(output),
        planned_output_dir=str(output),
        failed=True,
        repair_entered=False,
    )

    assert result.reason == "nonempty_payload"
    assert result.payload_bytes == 1
    assert output.is_dir()


def test_collect_result_applies_main_pipeline_cleanup_after_diagnostics(tmp_path):
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"broken")
    output = tmp_path / "broken"
    output.mkdir()
    (output / "empty.txt").write_bytes(b"")
    task = ArchiveTask(
        fact_bag=FactBag(),
        score=1,
        main_path=str(archive),
        all_parts=[str(archive)],
        logical_name="broken",
        detected_ext="zip",
    )
    task.fact_bag.set(REPAIR_ENTERED_FACT, False)
    extraction = ExtractionResult(
        success=False,
        archive=str(archive),
        out_dir=str(output),
        all_parts=[str(archive)],
        error="damaged",
    )
    outcome = BatchExtractionOutcome(result=extraction, planned_out_dir=str(output))
    runner = object.__new__(ExtractionBatchRunner)
    runner.context = RunContext()
    runner.config = {}

    returned = runner.collect_result(task, outcome)

    assert returned is None
    assert not output.exists()
    assert extraction.diagnostics["failed_output_cleanup"]["cleaned"] is True
    assert runner.context.failed_tasks == ["broken.zip [damaged]"]


def test_pipeline_marks_actual_repair_entry_and_preserves_zero_output(tmp_path, pipeline_resource_scheduler):
    archive = tmp_path / "repairable.zip"
    archive.write_bytes(b"broken")
    output = tmp_path / "repairable"
    task = ArchiveTask(
        fact_bag=FactBag(),
        score=1,
        main_path=str(archive),
        all_parts=[str(archive)],
        logical_name="repairable",
        detected_ext="zip",
    )

    class Extractor:
        password_session = None

        def default_output_dir_for_task(self, _task):
            return str(output)

        def extract(self, _task, out_dir, runtime_scheduler=None):
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            (Path(out_dir) / "empty.txt").write_bytes(b"")
            return ExtractionResult(
                success=False,
                archive=str(archive),
                out_dir=str(out_dir),
                all_parts=[str(archive)],
                error="damaged",
            )

    class RepairVerifier:
        config = {
            "max_retries": 0,
            "cleanup_failed_output": True,
            "recovery_min_improvement": 0.0,
        }

        def verify(self, _task, _result):
            return VerificationResult(
                decision_hint="repair",
                assessment_status="damaged",
                completeness=0.0,
            )

    runner = ExtractionBatchRunner(
        RunContext(),
        Extractor(),
        NestedOutputScanPolicy({}),
        pipeline_resource_scheduler,
        config={},
    )
    runner.verifier = RepairVerifier()
    runner._repair_after_verification_decision_with_beam = lambda *args, **kwargs: False

    outcome = runner._extract_verify_with_retries(task, str(output), runtime_scheduler=None)
    outcome.planned_out_dir = str(output)
    runner.collect_result(task, outcome)

    assert task.fact_bag.get(REPAIR_ENTERED_FACT) is True
    assert output.is_dir()
    assert outcome.result.diagnostics["failed_output_cleanup"]["reason"] == "repair_entered"
    assert outcome.result.failure is not None
    assert outcome.result.failure.details["repair"]["status"] == "attempted_no_recovery"
