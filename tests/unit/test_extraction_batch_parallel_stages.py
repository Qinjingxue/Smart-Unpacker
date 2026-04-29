import threading
import time
from pathlib import Path

from sunpack.contracts.detection import FactBag
from sunpack.contracts.run_context import RunContext
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.extraction_batch import ExtractionBatchRunner


def test_preflight_inspect_uses_conservative_parallel_stage(tmp_path):
    tasks = [_task(tmp_path / f"archive_{index}.zip") for index in range(3)]
    extractor = _ConcurrentInspectExtractor(delay_seconds=0.05)
    runner = _runner(
        tmp_path,
        extractor,
        {
            "performance": {
                "parallel_preflight_inspect": True,
                "preflight_inspect_max_workers": 2,
            }
        },
    )
    runner.max_workers = 8

    results = runner._inspect_tasks_before_extract(tasks, lambda task: str(Path(task.main_path).with_suffix("")))

    assert [item[1].logical_name for item in results] == ["archive_0", "archive_1", "archive_2"]
    assert extractor.max_active == 2


def test_resource_preflight_uses_parallel_stage_when_ready_tasks_are_many(tmp_path):
    tasks = [_task(tmp_path / f"archive_{index}.zip") for index in range(4)]
    runner = _runner(
        tmp_path,
        _ConcurrentInspectExtractor(),
        {
            "performance": {
                "parallel_resource_preflight": True,
                "resource_preflight_max_workers": 2,
            }
        },
    )
    runner.max_workers = 8
    inspector = _ConcurrentResourceInspector(delay_seconds=0.05)
    runner.resource_inspector = inspector

    runner._inspect_resource_profiles(tasks)

    assert inspector.max_active == 2


class _ConcurrentInspectExtractor:
    password_session = None

    def __init__(self, delay_seconds=0.0):
        self.delay_seconds = delay_seconds
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def default_output_dir_for_task(self, task):
        return str(Path(task.main_path).with_suffix(""))

    def inspect(self, task, out_dir):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.delay_seconds:
                time.sleep(self.delay_seconds)
            return type("Preflight", (), {"skip_result": None})()
        finally:
            with self.lock:
                self.active -= 1


class _ConcurrentResourceInspector:
    def __init__(self, delay_seconds=0.0):
        self.delay_seconds = delay_seconds
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def inspect(self, task):
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.delay_seconds:
                time.sleep(self.delay_seconds)
            task.fact_bag.set("resource.tokens", {"cpu": 1, "io": 1, "memory": 1})
            return task
        finally:
            with self.lock:
                self.active -= 1


class _FakeOutputScanPolicy:
    def scan_roots_from_outputs(self, outputs):
        return list(outputs)


def _runner(tmp_path, extractor, config=None):
    return ExtractionBatchRunner(
        RunContext(),
        extractor,
        _FakeOutputScanPolicy(),
        config={
            "repair": {"enabled": False, "workspace": str(tmp_path / "repair")},
            **(config or {}),
        },
    )


def _task(path: Path) -> ArchiveTask:
    path.write_bytes(b"zip")
    return ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        key=path.name,
        main_path=str(path),
        all_parts=[str(path)],
        logical_name=path.stem,
        detected_ext=path.suffix.lstrip("."),
    )
