from pathlib import Path

import sunpack.coordinator.engine as engine_module
from sunpack.coordinator.engine import PipelineEngine
from sunpack.config.schema import normalize_config
from sunpack.contracts.extraction import ExtractionResult
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def _configure_request_runtime(engine, callback):
    factory = engine._request_runtime_factory

    def configured(*args):
        runtime = factory(*args)
        callback(runtime)
        return runtime

    engine._request_runtime_factory = configured


def test_pipeline_runner_passes_native_worker_overrides():
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "performance": {
            "worker": {
                "profile": "auto",
                "max_task_seconds": 1800,
                "watchdog_no_progress_timeout_seconds": 180,
            },
        },
    }))

    engine = PipelineEngine(config)
    captured = {}
    _configure_request_runtime(engine, lambda runtime: captured.update(
        extractor=runtime.extractor.process_config,
    ))
    with engine:
        engine.submit(["missing.zip"]).result(timeout=5)

    assert captured["extractor"]["max_task_seconds"] == 1800
    assert captured["extractor"]["watchdog_no_progress_timeout_seconds"] == 180


def test_pipeline_runner_uses_tmp_path_and_applies_success_postprocess(tmp_path, monkeypatch):
    archive = tmp_path / "payload.zip"
    archive.write_bytes(make_zip({"inside.txt": "hello"}))

    config = normalize_config(with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
        "recursive_extract": "1",
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {
            "archive_cleanup_mode": "d",
            "flatten_single_directory": True,
        },
    }, precheck=[
        {"name": "size_range", "enabled": True, "gte": 0},
        {"name": "zip_structure_accept", "enabled": True},
    ], scoring=[
        {"name": "zip_structure_identity", "enabled": True},
    ]))

    engine = PipelineEngine(config)
    call_order = []
    postprocess_actions = engine_module.PostProcessActions

    class TrackedPostProcessActions:
        def __init__(self, *args, **kwargs):
            self._delegate = postprocess_actions(*args, **kwargs)

        def apply(self, **kwargs):
            call_order.append("postprocess")
            return self._delegate.apply(**kwargs)

    monkeypatch.setattr(engine_module, "PostProcessActions", TrackedPostProcessActions)

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

    def fake_extract_async(task, out_dir, *, on_complete, **_kwargs):
        on_complete(fake_extract(task, out_dir))

    def configure(runtime):
        original_close = runtime.extractor.close

        def tracked_close():
            original_close()
            call_order.append("close")

        monkeypatch.setattr(runtime.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
        monkeypatch.setattr(runtime.batch_runner.resource_inspector, "inspect", lambda task: task)
        monkeypatch.setattr(runtime.extractor, "extract", fake_extract)
        monkeypatch.setattr(runtime.extractor, "extract_async", fake_extract_async)
        monkeypatch.setattr(runtime.extractor, "close", tracked_close)

    _configure_request_runtime(engine, configure)

    with engine:
        summary = engine.submit([str(tmp_path)]).result().summary

    assert summary.success_count == 1
    assert summary.failed_tasks == []
    assert not archive.exists()
    assert (tmp_path / "payload" / "inside.txt").exists()
    assert (tmp_path / "failed_log.txt").exists() is False
    assert call_order[:2] == ["close", "postprocess"]


def test_pipeline_runner_exposes_recent_passwords_without_password_manager():
    engine = PipelineEngine(normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "user_passwords": ["secret"],
        "builtin_passwords": [],
    })))
    _configure_request_runtime(
        engine,
        lambda runtime: runtime.extractor.password_store.remember_success("secret"),
    )
    with engine:
        engine.submit(["missing.zip"]).result(timeout=5)
        assert engine.recent_passwords == ["secret"]


def test_batch_does_not_treat_existing_same_name_directory_as_output(tmp_path, monkeypatch):
    archive = tmp_path / "payload.zip"
    nested = tmp_path / "payload" / "inner.zip"
    archive.write_bytes(b"parent")
    nested.parent.mkdir()
    nested.write_bytes(b"nested")

    engine = PipelineEngine(normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    })))
    extracted = []

    def task_for(path):
        bag = FactBag()
        return ArchiveTask(fact_bag=bag, score=10, main_path=str(path), all_parts=[str(path)])

    def fake_extract(task, out_dir):
        extracted.append(task.main_path)
        return ExtractionResult(success=True, archive=task.main_path, out_dir=out_dir, all_parts=task.all_parts)

    def fake_extract_async(task, out_dir, *, on_complete, **_kwargs):
        on_complete(fake_extract(task, out_dir))

    captured = {}
    def configure(runtime):
        captured["runtime"] = runtime
        monkeypatch.setattr(runtime.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
        monkeypatch.setattr(runtime.batch_runner.resource_inspector, "inspect", lambda task: task)
        monkeypatch.setattr(runtime.extractor, "extract", fake_extract)
        monkeypatch.setattr(runtime.extractor, "extract_async", fake_extract_async)

    _configure_request_runtime(engine, configure)
    engine.start()
    try:
        engine.submit([str(tmp_path / "missing.zip")]).result(timeout=5)
        captured["runtime"].batch_runner.execute([task_for(archive), task_for(nested)])
    finally:
        engine.close()

    assert extracted == [str(archive), str(nested)]
    engine.close()


def test_output_root_preserves_tree_and_recursive_scan_uses_success_outputs(tmp_path, monkeypatch):
    input_root = tmp_path / "input"
    archive = input_root / "sub" / "payload.zip"
    output_root = tmp_path / "out"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"parent")

    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "2",
        "repair": {"enabled": False},
        "verification": {"enabled": False, "methods": []},
        "output": {
            "root": str(output_root),
            "common_root": str(input_root),
        },
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
    }))
    engine = PipelineEngine(config)
    task = ArchiveTask(fact_bag=FactBag(), score=10, main_path=str(archive), all_parts=[str(archive)], logical_name="payload")

    def fake_extract(item, out_dir):
        nested = Path(out_dir) / "nested.zip"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_bytes(b"nested")
        return ExtractionResult(success=True, archive=item.main_path, out_dir=out_dir, all_parts=item.all_parts)

    def fake_extract_async(item, out_dir, *, on_complete, **_kwargs):
        on_complete(fake_extract(item, out_dir))

    captured = {}
    def configure(runtime):
        captured["runtime"] = runtime
        monkeypatch.setattr(runtime.extractor, "inspect", lambda *_args, **_kwargs: type("Preflight", (), {"skip_result": None})())
        monkeypatch.setattr(runtime.batch_runner.resource_inspector, "inspect", lambda item: item)
        monkeypatch.setattr(runtime.extractor, "extract", fake_extract)
        monkeypatch.setattr(runtime.extractor, "extract_async", fake_extract_async)

    _configure_request_runtime(engine, configure)

    engine.start()
    try:
        engine.submit([str(input_root / "missing.zip")]).result(timeout=5)
        scan_roots = captured["runtime"].batch_runner.execute([task])
    finally:
        engine.close()

    expected_out_dir = output_root / "sub" / "payload"
    assert expected_out_dir.exists()
    assert scan_roots == [str(expected_out_dir)]
    engine.close()
