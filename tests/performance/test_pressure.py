import threading
import time
import zipfile
from pathlib import Path

from smart_unpacker.coordinator.scanner import ScanOrchestrator
from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.extraction.scheduler import ConcurrencyScheduler
from smart_unpacker.extraction.internal.executor import TaskExecutor
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.fs_builder import make_zip


def pressure_scan_config() -> dict:
    return with_detection_pipeline({
        "thresholds": {
            "archive_score_threshold": 5,
            "maybe_archive_threshold": 3,
        },
    }, hard_stop=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
        {
            "name": "blacklist",
            "enabled": True,
            "blocked_extensions": [".jar", ".docx", ".apk", ".xlsx"],
        },
    ], scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 5, "extensions": [".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".001"]}]},
        {"name": "archive_identity", "enabled": True, "carrier_tail_score": 5},
    ], confirmation=[
        {"name": "seven_zip_probe", "enabled": True},
        {"name": "seven_zip_validation", "enabled": True},
    ])


def write_large_resource(path: Path, label: str, size: int = 128 * 1024):
    chunk = (f"PRESSURE::{label}::".encode("ascii") * 4096)[:8192]
    with path.open("wb") as handle:
        remaining = size
        while remaining > 0:
            piece = chunk[: min(len(chunk), remaining)]
            handle.write(piece)
            remaining -= len(piece)


def create_container(path: Path, kind: str):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        if kind == "jar":
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            archive.writestr("com/example/App.class", b"\xca\xfe\xba\xbe")
        elif kind == "docx":
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("word/document.xml", "<w:document />")
        elif kind == "apk":
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
            archive.writestr("classes.dex", b"dex\n035\x00")
        elif kind == "xlsx":
            archive.writestr("[Content_Types].xml", "<Types></Types>")
            archive.writestr("xl/workbook.xml", "<workbook />")
        else:
            raise ValueError(kind)


def build_pressure_corpus(root: Path):
    normal_exts = [".jpg", ".png", ".mp4", ".dll", ".pak", ".bin", ".dat", ".log"]
    for index in range(32):
        write_large_resource(root / f"bulk_asset_{index:03d}{normal_exts[index % len(normal_exts)]}", f"normal-{index}")

    expected = []
    for index in range(3):
        archive = root / f"real_archive_{index:02d}.zip"
        archive.write_bytes(make_zip({f"marker_{index}.txt": f"real::{index}"}))
        expected.append(archive.name)

    for index in range(2):
        disguised = root / f"masked_archive_{index:02d}.jpg"
        disguised.write_bytes(b"\xff\xd8synthetic-image\xff\xd9" + b"7z\xbc\xaf\x27\x1c")
        expected.append(disguised.name)

    for index, kind in enumerate(["jar", "docx", "apk", "xlsx"]):
        create_container(root / f"container_{index:02d}.{kind}", kind)

    write_large_resource(root / "ordinary_tool.exe", "ordinary-tool", size=32 * 1024)
    write_large_resource(root / "ordinary_tool.part1.rar", "ordinary-part", size=32 * 1024)
    return sorted(expected)


def test_pressure_scan_avoids_7z_confirmation_fanout_on_mixed_corpus(tmp_path, monkeypatch):
    expected = build_pressure_corpus(tmp_path)
    fact_counts = {"7z.probe": 0, "7z.validation": 0}
    original_fill_fact = FactProvider.fill_fact

    def counting_fill_fact(self, fact_bag, fact_name):
        if fact_name in fact_counts:
            fact_counts[fact_name] += 1
        return original_fill_fact(self, fact_bag, fact_name)

    monkeypatch.setattr(FactProvider, "fill_fact", counting_fill_fact)

    start = time.perf_counter()
    results = ScanOrchestrator(pressure_scan_config()).scan(str(tmp_path))
    elapsed = time.perf_counter() - start
    actual = sorted(Path(result.primary_path).name for result in results)

    assert actual == expected
    assert fact_counts == {"7z.probe": 0, "7z.validation": 0}
    assert elapsed < 2.0


def test_task_executor_uses_multiple_workers_under_backlog():
    scheduler = ConcurrencyScheduler(
        {
            "initial_concurrency_limit": 4,
            "poll_interval_ms": 100,
            "scale_up_streak_required": 1,
            "scale_down_streak_required": 1,
        },
        current_limit=4,
        max_workers=4,
    )
    executor = TaskExecutor(scheduler, max_workers=4)
    lock = threading.Lock()
    active = 0
    peak_active = 0

    def make_task(index: int) -> ArchiveTask:
        bag = FactBag()
        bag.set("file.path", f"archive_{index}.zip")
        return ArchiveTask(fact_bag=bag, score=5)

    def worker(_task):
        nonlocal active, peak_active
        with lock:
            active += 1
            peak_active = max(peak_active, active)
        try:
            time.sleep(0.05)
            return True
        finally:
            with lock:
                active -= 1

    tasks = [make_task(index) for index in range(8)]
    start = time.perf_counter()
    results = executor.execute_all(tasks, worker)
    elapsed = time.perf_counter() - start

    assert results == [True] * 8
    assert peak_active >= 3
    assert elapsed < 0.35
