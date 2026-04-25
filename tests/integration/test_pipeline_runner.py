from smart_unpacker.coordinator.runner import PipelineRunner
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def test_pipeline_runner_uses_tmp_path_and_applies_success_postprocess(tmp_path, monkeypatch):
    archive = tmp_path / "payload.zip"
    archive.write_bytes(make_zip({"inside.txt": "hello"}))

    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": {"mode": "fixed", "max_rounds": 1},
        "post_extract": {
            "archive_cleanup_mode": "delete",
            "flatten_single_directory": True,
        },
    }, hard_stop=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip"]}]},
    ])

    runner = PipelineRunner(config)

    def fake_extract(task, out_dir):
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
    runner = PipelineRunner(with_detection_pipeline({
        "recursive_extract": {"mode": "fixed", "max_rounds": 1},
        "post_extract": {
            "archive_cleanup_mode": "keep",
            "flatten_single_directory": False,
        },
        "user_passwords": ["secret"],
        "builtin_passwords": [],
    }))
    runner.extractor.password_manager.add_recent_password("secret")

    assert not hasattr(runner, "password_manager")
    assert runner.recent_passwords == ["secret"]


def test_batch_skips_stale_nested_output_tasks_in_same_round(tmp_path, monkeypatch):
    archive = tmp_path / "payload.zip"
    nested = tmp_path / "payload" / "inner.zip"
    archive.write_bytes(b"parent")
    nested.parent.mkdir()
    nested.write_bytes(b"nested")

    runner = PipelineRunner(with_detection_pipeline({
        "recursive_extract": {"mode": "fixed", "max_rounds": 1},
        "post_extract": {
            "archive_cleanup_mode": "keep",
            "flatten_single_directory": False,
        },
    }))
    extracted = []

    def task_for(path):
        bag = FactBag()
        bag.set("file.path", str(path))
        return ArchiveTask.from_fact_bag(bag, score=10)

    def fake_extract(task, out_dir):
        extracted.append(task.main_path)
        return ExtractionResult(success=True, archive=task.main_path, out_dir=out_dir, all_parts=task.all_parts)

    monkeypatch.setattr(runner.extractor, "extract", fake_extract)
    runner.batch_runner.execute([task_for(archive), task_for(nested)])

    assert extracted == [str(archive)]
