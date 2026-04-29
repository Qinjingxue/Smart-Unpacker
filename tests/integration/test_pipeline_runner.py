from pathlib import Path

from packrelic.coordinator.runner import PipelineRunner
from packrelic.config.schema import normalize_config
from packrelic.extraction.result import ExtractionResult
from packrelic.contracts.detection import FactBag
from packrelic.contracts.tasks import ArchiveTask
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def test_pipeline_runner_passes_performance_scheduler_overrides():
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "performance": {
            "scheduler_profile": "auto",
            "max_extract_task_seconds": 1800,
            "process_no_progress_timeout_seconds": 180,
        },
    }))

    runner = PipelineRunner(config)

    assert runner.extractor.process_config["max_extract_task_seconds"] == 1800
    assert runner.extractor.process_config["process_no_progress_timeout_seconds"] == 180
    assert runner.batch_runner.scheduler_config["max_extract_task_seconds"] == 1800
    assert runner.batch_runner.scheduler_config["process_no_progress_timeout_seconds"] == 180


def test_pipeline_runner_uses_tmp_path_and_applies_success_postprocess(tmp_path, monkeypatch):
    archive = tmp_path / "payload.zip"
    archive.write_bytes(make_zip({"inside.txt": "hello"}))

    config = normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "d",
            "flatten_single_directory": True,
        },
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip"]}]},
    ]))

    runner = PipelineRunner(config)

    monkeypatch.setattr(runner.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
    monkeypatch.setattr(runner.batch_runner.resource_inspector, "inspect", lambda task: task)

    def fake_extract(task, out_dir, runtime_scheduler=None):
        out_path = tmp_path / "payload" / "inside.txt"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("hello", encoding="utf-8")
        return ExtractionResult(
            success=True,
            archive=task.main_path,
            out_dir=out_dir,
            all_parts=task.all_parts,
        )

    monkeypatch.setattr(runner.extractor, "extract", fake_extract)

    summary = runner.run(str(tmp_path))

    assert summary.success_count == 1
    assert summary.failed_tasks == []
    assert not archive.exists()
    assert (tmp_path / "payload" / "inside.txt").exists()
    assert (tmp_path / "failed_log.txt").exists() is False


def test_pipeline_runner_exposes_recent_passwords_without_password_manager():
    runner = PipelineRunner(normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "user_passwords": ["secret"],
        "builtin_passwords": [],
    })))
    runner.extractor.password_store.remember_success("secret")

    assert not hasattr(runner, "password_manager")
    assert runner.recent_passwords == ["secret"]


def test_batch_skips_stale_nested_output_tasks_in_same_round(tmp_path, monkeypatch):
    archive = tmp_path / "payload.zip"
    nested = tmp_path / "payload" / "inner.zip"
    archive.write_bytes(b"parent")
    nested.parent.mkdir()
    nested.write_bytes(b"nested")

    runner = PipelineRunner(normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    })))
    extracted = []

    def task_for(path):
        bag = FactBag()
        return ArchiveTask(fact_bag=bag, score=10, main_path=str(path), all_parts=[str(path)])

    monkeypatch.setattr(runner.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
    monkeypatch.setattr(runner.batch_runner.resource_inspector, "inspect", lambda task: task)

    def fake_extract(task, out_dir, runtime_scheduler=None):
        extracted.append(task.main_path)
        return ExtractionResult(success=True, archive=task.main_path, out_dir=out_dir, all_parts=task.all_parts)

    monkeypatch.setattr(runner.extractor, "extract", fake_extract)
    runner.batch_runner.execute([task_for(archive), task_for(nested)])

    assert extracted == [str(archive)]


def test_output_root_preserves_tree_and_recursive_scan_uses_success_outputs(tmp_path, monkeypatch):
    input_root = tmp_path / "input"
    archive = input_root / "sub" / "payload.zip"
    output_root = tmp_path / "out"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"parent")

    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "2",
        "output": {
            "root": str(output_root),
            "common_root": str(input_root),
        },
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    }, scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip"]}]},
    ]))
    runner = PipelineRunner(config)
    task = ArchiveTask(fact_bag=FactBag(), score=10, main_path=str(archive), all_parts=[str(archive)], logical_name="payload")

    monkeypatch.setattr(runner.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
    monkeypatch.setattr(runner.batch_runner.resource_inspector, "inspect", lambda item: item)

    def fake_extract(item, out_dir, runtime_scheduler=None):
        nested = Path(out_dir) / "nested.zip"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_bytes(b"nested")
        return ExtractionResult(success=True, archive=item.main_path, out_dir=out_dir, all_parts=item.all_parts)

    monkeypatch.setattr(runner.extractor, "extract", fake_extract)

    scan_roots = runner.batch_runner.execute([task])

    expected_out_dir = output_root / "sub" / "payload"
    assert expected_out_dir.exists()
    assert scan_roots == [str(expected_out_dir)]
