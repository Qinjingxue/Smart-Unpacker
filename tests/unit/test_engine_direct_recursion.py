from types import SimpleNamespace

from sunpack.config.schema import normalize_config
from sunpack.coordinator.engine import PipelineEngine
from tests.helpers.detection_config import with_detection_pipeline


def test_direct_submission_feeds_nested_roots_back_into_resident_pipeline(tmp_path, monkeypatch):
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "2",
        "cli": {"quiet": True},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))
    engine = PipelineEngine(config)
    outer = SimpleNamespace(main_path=str(tmp_path / "outer.zip"), key="outer")
    inner = SimpleNamespace(main_path=str(tmp_path / "nested-root" / "inner.zip"), key="inner")
    monkeypatch.setattr(engine._runtime.task_scanner, "direct_file_tasks", lambda _paths: [outer])
    monkeypatch.setattr(engine._runtime.task_scanner, "scan_targets", lambda roots: [inner] if roots == ["nested-root"] else [])
    executed = []

    def execute(tasks, **_kwargs):
        executed.append(list(tasks))
        return ["nested-root"] if tasks == [outer] else []

    monkeypatch.setattr(engine.batch_runner, "execute", execute)
    with engine:
        engine.submit([str(tmp_path / "outer.zip")], direct=True).result()

    assert executed == [[outer], [inner]]
