from types import SimpleNamespace

from smart_unpacker.config.schema import normalize_config
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.coordinator.context import RunContext
from smart_unpacker.coordinator.extraction_batch import ExtractionBatchRunner
from smart_unpacker.detection import NestedOutputScanPolicy
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.verification import VerificationStepResult, register_verification_method
from smart_unpacker.verification.result import VerificationIssue
from tests.helpers.detection_config import with_detection_pipeline


@register_verification_method("integration_fail_once")
class IntegrationFailOnceMethod:
    calls = 0

    def verify(self, evidence, config):
        type(self).calls += 1
        if type(self).calls <= int(config.get("fail_count", 1)):
            return VerificationStepResult(
                method="integration_fail_once",
                score_delta=-100,
                hard_fail=True,
                issues=[VerificationIssue(method="integration_fail_once", code="fail.integration", message="failed")],
            )
        return VerificationStepResult(method="integration_fail_once", score_delta=0)


def test_batch_failure_path_runs_through_coordinator_executor(tmp_path, monkeypatch):
    archive = tmp_path / "not_archive.txt"
    archive.write_text("not an archive", encoding="utf-8")
    out_dir = tmp_path / "extracted_fake"

    def make_task() -> ArchiveTask:
        bag = FactBag()
        bag.set("file.detected_ext", ".txt")
        bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
        return ArchiveTask(fact_bag=bag, score=10, main_path=str(archive), all_parts=[str(archive)])

    config = normalize_config(with_detection_pipeline({"recursive_extract": "1"}))
    extractor = ExtractionScheduler(max_retries=1)
    runner = ExtractionBatchRunner(
        RunContext(),
        extractor,
        NestedOutputScanPolicy(config),
        config=config,
    )
    monkeypatch.setattr(extractor, "inspect", lambda *_args, **_kwargs: SimpleNamespace(skip_result=None))
    monkeypatch.setattr(runner.resource_inspector, "inspect", lambda task: task)

    def fake_extract(task, _out_dir, runtime_scheduler=None):
        return ExtractionResult(
            success=False,
            archive=task.main_path,
            out_dir=str(out_dir),
            all_parts=task.all_parts,
            error="压缩包损坏",
        )

    monkeypatch.setattr(extractor, "extract", fake_extract)

    results = runner._execute_ready_tasks([make_task(), make_task()], lambda _item: str(out_dir))

    assert len(results) == 2
    assert all(outcome.success is False for _, outcome in results)
    assert all(outcome.result.error for _, outcome in results)


def test_single_ready_task_uses_estimated_resource_profile(tmp_path, monkeypatch):
    archive = tmp_path / "sample.rar"
    archive.write_bytes(b"rar")
    out_dir = tmp_path / "sample"
    bag = FactBag()
    bag.set("resource.health", {"is_archive": True, "archive_type": "rar"})
    task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive), all_parts=[str(archive)])

    config = normalize_config(with_detection_pipeline({"recursive_extract": "1"}))
    extractor = ExtractionScheduler(max_retries=1)
    runner = ExtractionBatchRunner(RunContext(), extractor, NestedOutputScanPolicy(config), config=config)
    monkeypatch.setattr(extractor, "inspect", lambda *_args, **_kwargs: SimpleNamespace(skip_result=None))
    monkeypatch.setattr(
        runner.resource_inspector,
        "inspect",
        lambda _task: (_ for _ in ()).throw(AssertionError("single task should not run precise resource analysis")),
    )
    monkeypatch.setattr(
        extractor,
        "extract",
        lambda item, output_dir, runtime_scheduler=None: ExtractionResult(
            success=False,
            archive=item.main_path,
            out_dir=str(out_dir),
            all_parts=item.all_parts,
            error="stop",
        ),
    )

    runner._execute_ready_tasks([task], lambda _item: str(out_dir))

    assert bag.get("resource.profile_key") == "rar|estimated|single"
    assert bag.get("resource.analysis")["message"] == "estimated single-task resource profile"


def test_multiple_ready_tasks_use_combined_resource_preflight(tmp_path, monkeypatch):
    config = normalize_config(with_detection_pipeline({"recursive_extract": "1"}))
    extractor = ExtractionScheduler(max_retries=1)
    runner = ExtractionBatchRunner(RunContext(), extractor, NestedOutputScanPolicy(config), config=config)
    analysis = SimpleNamespace(
        ok=True,
        dominant_method="Store",
        archive_type="rar",
        archive_size=100,
        total_unpacked_size=100,
        total_packed_size=100,
        largest_dictionary_size=0,
        file_count=1,
        item_count=1,
        dir_count=0,
        largest_item_size=100,
        solid=False,
        status=0,
        is_archive=True,
        is_encrypted=False,
        is_broken=False,
        message="ok",
    )
    monkeypatch.setattr(
        extractor,
        "inspect_with_resource_analysis",
        lambda *_args, **_kwargs: SimpleNamespace(skip_result=None, resource_analysis=analysis),
    )

    calls = 0

    def fake_record_precise_analysis(task, resource_analysis):
        nonlocal calls
        calls += 1
        task.fact_bag.set("resource.analysis", {"message": "combined"})
        task.fact_bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
        return task

    monkeypatch.setattr(runner.resource_inspector, "record_precise_analysis", fake_record_precise_analysis)
    monkeypatch.setattr(
        runner.resource_inspector,
        "inspect",
        lambda _task: (_ for _ in ()).throw(AssertionError("combined preflight should provide resource analysis")),
    )
    monkeypatch.setattr(
        extractor,
        "extract",
        lambda item, output_dir, runtime_scheduler=None: ExtractionResult(
            success=False,
            archive=item.main_path,
            out_dir=output_dir,
            all_parts=item.all_parts,
            error="stop",
        ),
    )

    tasks = []
    for index in range(2):
        archive = tmp_path / f"sample{index}.rar"
        archive.write_bytes(b"rar")
        tasks.append(ArchiveTask(fact_bag=FactBag(), score=10, main_path=str(archive), all_parts=[str(archive)]))

    runner._execute_ready_tasks(tasks, lambda item: str(tmp_path / (item.main_path + ".out")))

    assert calls == 2


def test_batch_verification_failure_retries_extract_and_cleans_output(tmp_path, monkeypatch):
    IntegrationFailOnceMethod.calls = 0
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    out_dir = tmp_path / "sample"
    partial = out_dir / "partial.txt"
    bag = FactBag()
    bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
    task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive), all_parts=[str(archive)])

    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "verification": {
            "enabled": True,
            "max_retries": 1,
            "methods": [{"name": "integration_fail_once", "enabled": True, "fail_count": 1}],
        },
    }))
    context = RunContext()
    extractor = ExtractionScheduler(max_retries=1)
    runner = ExtractionBatchRunner(context, extractor, NestedOutputScanPolicy(config), config=config)
    monkeypatch.setattr(extractor, "inspect", lambda *_args, **_kwargs: SimpleNamespace(skip_result=None))
    monkeypatch.setattr(runner.resource_inspector, "inspect", lambda item: item)
    calls = 0

    def fake_extract(item, output_dir, runtime_scheduler=None):
        nonlocal calls
        calls += 1
        partial.parent.mkdir(parents=True, exist_ok=True)
        if calls == 1:
            partial.write_text("partial", encoding="utf-8")
        return ExtractionResult(success=True, archive=item.main_path, out_dir=output_dir, all_parts=item.all_parts)

    monkeypatch.setattr(extractor, "extract", fake_extract)

    runner.execute([task])

    assert calls == 2
    assert context.success_count == 1
    assert not partial.exists()


def test_batch_verification_failure_logs_score_without_retry(tmp_path, monkeypatch):
    IntegrationFailOnceMethod.calls = 0
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    bag = FactBag()
    bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
    task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive), all_parts=[str(archive)])

    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "verification": {
            "enabled": True,
            "max_retries": 0,
            "methods": [{"name": "integration_fail_once", "enabled": True, "fail_count": 99}],
        },
    }))
    context = RunContext()
    extractor = ExtractionScheduler(max_retries=1)
    runner = ExtractionBatchRunner(context, extractor, NestedOutputScanPolicy(config), config=config)
    monkeypatch.setattr(extractor, "inspect", lambda *_args, **_kwargs: SimpleNamespace(skip_result=None))
    monkeypatch.setattr(runner.resource_inspector, "inspect", lambda item: item)
    monkeypatch.setattr(
        extractor,
        "extract",
        lambda item, output_dir, runtime_scheduler=None: ExtractionResult(
            success=True,
            archive=item.main_path,
            out_dir=output_dir,
            all_parts=item.all_parts,
        ),
    )

    output_dirs = runner.execute([task])

    assert output_dirs == []
    assert context.success_count == 0
    assert len(context.failed_tasks) == 1
    assert "校验失败" in context.failed_tasks[0]
    assert "score=0" in context.failed_tasks[0]
    assert "integration_fail_once:-100=>0" in context.failed_tasks[0]
