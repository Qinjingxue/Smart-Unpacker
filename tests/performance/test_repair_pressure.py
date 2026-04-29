import struct
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Callable

from packrelic.config.schema import normalize_config
from packrelic.coordinator.runner import PipelineRunner
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import require_7z


KiB = 1024


class StageTimer:
    def __init__(self):
        self.totals: dict[str, float] = {}
        self.counts: dict[str, int] = {}
        self._restore: list[Callable[[], None]] = []

    def wrap(self, owner, method_name: str, label: str):
        original = getattr(owner, method_name)

        def wrapped(*args, **kwargs):
            started = time.perf_counter()
            try:
                return original(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - started
                self.totals[label] = self.totals.get(label, 0.0) + elapsed
                self.counts[label] = self.counts.get(label, 0) + 1

        setattr(owner, method_name, wrapped)
        self._restore.append(lambda: setattr(owner, method_name, original))

    def restore(self) -> None:
        while self._restore:
            self._restore.pop()()

    def ms(self, label: str) -> float:
        return round(self.totals.get(label, 0.0) * 1000, 2)

    def snapshot(self) -> dict[str, dict[str, float | int]]:
        return {
            label: {"ms": round(total * 1000, 2), "count": self.counts.get(label, 0)}
            for label, total in sorted(self.totals.items(), key=lambda item: item[1], reverse=True)
        }

    def hottest(self, limit: int = 5) -> list[tuple[str, float, int]]:
        return [
            (label, round(total * 1000, 2), self.counts.get(label, 0))
            for label, total in sorted(self.totals.items(), key=lambda item: item[1], reverse=True)[:limit]
        ]


def attach_timing(runner: PipelineRunner) -> StageTimer:
    timer = StageTimer()
    timer.wrap(runner.task_scanner, "scan_targets", "scan")
    timer.wrap(runner.batch_runner, "execute", "batch_execute")
    timer.wrap(runner.batch_runner, "prepare_tasks", "prepare")
    timer.wrap(runner.batch_runner.analysis_stage, "analyze_tasks", "analysis")
    timer.wrap(runner.batch_runner, "_execute_ready_tasks", "execute_ready")
    timer.wrap(runner.batch_runner.verifier, "verify", "verify")
    timer.wrap(runner.batch_runner.repair_stage, "repair_after_verification_assessment_result", "repair_direct")
    timer.wrap(runner.batch_runner, "_repair_after_verification_with_beam", "repair_beam")
    scheduler = runner.batch_runner.repair_stage.scheduler
    if scheduler is not None:
        timer.wrap(scheduler, "generate_repair_candidates", "repair_candidates")
        timer.wrap(scheduler, "diagnose", "repair_diagnose")
    timer.wrap(runner.extractor, "inspect", "preflight")
    timer.wrap(runner.extractor, "extract", "extract")
    timer.wrap(runner.batch_runner.resource_inspector, "inspect", "resource_precise")
    timer.wrap(runner.batch_runner.resource_inspector, "record_estimated_single_task_profile", "resource_estimate")
    timer.wrap(runner.batch_runner, "collect_result", "collect_result")
    timer.wrap(runner.output_scan_policy, "scan_roots_from_outputs", "output_scan")
    timer.wrap(runner.postprocess_actions, "apply", "postprocess")
    return timer


def repair_pressure_config(tmp_path: Path, *, scheduler_profile: str = "single") -> dict:
    return normalize_config(with_detection_pipeline({
        "recursive_extract": "1",
        "post_extract": {
            "archive_cleanup_mode": "k",
            "flatten_single_directory": False,
        },
        "max_retries": 1,
        "performance": {
            "scheduler_profile": scheduler_profile,
            "parallel_preflight_inspect": False,
            "parallel_resource_inspect": False,
        },
        "verification": {
            "enabled": True,
            "accept_partial_when_source_damaged": True,
            "partial_min_completeness": 0.2,
            "partial_accept_threshold": 0.2,
            "retry_on_verification_failure": True,
            "methods": [
                {"name": "extraction_exit_signal", "enabled": True},
                {"name": "output_presence", "enabled": True},
                {"name": "expected_name_presence", "enabled": True},
                {"name": "manifest_size_match", "enabled": True},
                {"name": "archive_test_crc", "enabled": True},
            ],
        },
        "repair": {
            "enabled": True,
            "workspace": str(tmp_path / "repair-workspace"),
            "max_attempts_per_task": 3,
            "max_repair_rounds_per_task": 3,
            "stages": {"targeted": True, "safe_repair": True, "deep": False},
            "auto_deep": {
                "enabled": True,
                "require_verification_repair": True,
                "max_modules": 2,
                "max_candidates_per_module": 1,
                "max_input_size_mb": 64,
            },
            "beam": {
                "enabled": True,
                "beam_width": 4,
                "max_candidates_per_state": 4,
                "max_analyze_candidates": 8,
                "max_assess_candidates": 4,
                "max_rounds": 3,
                "min_improvement": 0.01,
            },
        },
    }, precheck=[
        {"name": "size_minimum", "enabled": True, "min_inspection_size_bytes": 0},
        {"name": "blacklist", "enabled": True, "blocked_extensions": [".jar", ".docx", ".apk", ".xlsx"]},
    ], scoring=[
        {
            "name": "extension",
            "enabled": True,
            "extension_score_groups": [{
                "score": 5,
                "extensions": [".zip", ".001", ".tar", ".gz", ".tgz"],
            }],
        },
        {"name": "zip_structure_identity", "enabled": True},
        {"name": "tar_structure_identity", "enabled": True},
        {"name": "compression_stream_identity", "enabled": True},
    ], confirmation=[]))


def test_repair_pipeline_mixed_batch_pressure(tmp_path, request, record_property):
    repetitions = max(1, request.config.getoption("--repair-performance-repetitions"))
    payload_size = max(1, request.config.getoption("--repair-performance-payload-kb")) * KiB
    max_seconds = request.config.getoption("--repair-performance-max-seconds")

    for index in range(repetitions):
        _write_zip(tmp_path / f"{index:02d}_ok.zip", {f"ok_{index}.txt": b"ok"})
        _write_zip_with_bad_cd_offset(tmp_path / f"{index:02d}_cd_repair.zip")
        _write_zip_with_bad_payload(tmp_path / f"{index:02d}_partial_payload.zip", payload_size=payload_size)
        _write_zip_with_bad_cd_offset_and_payload(tmp_path / f"{index:02d}_repair_then_salvage.zip", payload_size=payload_size)
        _write_missing_tail_split_zip(tmp_path, f"{index:02d}_missing_tail", payload_size=payload_size * 3)

    runner = PipelineRunner(repair_pressure_config(tmp_path))
    timer = attach_timing(runner)
    started = time.perf_counter()
    try:
        summary = runner.run(str(tmp_path))
    finally:
        timer.restore()
    elapsed = time.perf_counter() - started

    expected_success_floor = repetitions * 4
    expected_partial_floor = repetitions
    expected_failure_floor = repetitions
    repaired_outputs = sorted(path for path in tmp_path.glob("*_cd_repair/*.txt"))
    partial_reports = sorted(tmp_path.glob("*_partial_payload/.packrelic/recovery_report.json"))

    record_property("repetitions", repetitions)
    record_property("payload_size_kb", payload_size // KiB)
    record_property("elapsed_seconds", round(elapsed, 3))
    record_property("success_count", summary.success_count)
    record_property("partial_success_count", summary.partial_success_count)
    record_property("failed_count", len(summary.failed_tasks))
    for label, payload in timer.snapshot().items():
        record_property(f"{label}_ms", payload["ms"])
        record_property(f"{label}_count", payload["count"])
    print(
        "repair_pipeline_pressure: "
        f"repetitions={repetitions}, elapsed={elapsed:.3f}s, "
        f"success={summary.success_count}, partial={summary.partial_success_count}, "
        f"failed={len(summary.failed_tasks)}, hotspots={timer.hottest()}"
    )

    assert summary.success_count >= expected_success_floor
    assert summary.partial_success_count >= expected_partial_floor
    assert len(summary.failed_tasks) >= expected_failure_floor
    assert len(repaired_outputs) >= repetitions
    assert len(partial_reports) >= repetitions
    assert elapsed < max_seconds


def test_repair_pipeline_partial_acceptance_pressure(tmp_path, request, record_property):
    repetitions = max(1, request.config.getoption("--repair-performance-repetitions"))
    payload_size = max(1, request.config.getoption("--repair-performance-payload-kb")) * KiB
    max_seconds = request.config.getoption("--repair-performance-max-seconds")

    for index in range(repetitions * 2):
        _write_zip_with_bad_payload(tmp_path / f"{index:02d}_partial_payload.zip", payload_size=payload_size)

    runner = PipelineRunner(repair_pressure_config(tmp_path))
    timer = attach_timing(runner)
    started = time.perf_counter()
    try:
        summary = runner.run(str(tmp_path))
    finally:
        timer.restore()
    elapsed = time.perf_counter() - started

    record_property("elapsed_seconds", round(elapsed, 3))
    record_property("success_count", summary.success_count)
    record_property("partial_success_count", summary.partial_success_count)
    record_property("failed_count", len(summary.failed_tasks))
    print(
        "repair_partial_pressure: "
        f"repetitions={repetitions}, elapsed={elapsed:.3f}s, "
        f"success={summary.success_count}, partial={summary.partial_success_count}, "
        f"failed={len(summary.failed_tasks)}, hotspots={timer.hottest()}"
    )

    assert summary.success_count == repetitions * 2
    assert summary.partial_success_count == repetitions * 2
    assert not summary.failed_tasks
    assert elapsed < max_seconds


def test_many_small_files_success_pressure(tmp_path, request, record_property):
    file_count = max(1, request.config.getoption("--repair-performance-small-file-count"))
    max_seconds = request.config.getoption("--repair-performance-max-seconds")
    archive = tmp_path / "many-small-ok.zip"
    _write_many_small_files_zip(archive, count=file_count, payload_size=32)

    runner = PipelineRunner(repair_pressure_config(tmp_path))
    timer = attach_timing(runner)
    started = time.perf_counter()
    try:
        summary = runner.run(str(tmp_path))
    finally:
        timer.restore()
    elapsed = time.perf_counter() - started

    extracted_files = list((tmp_path / "many-small-ok").glob("dir_*/file_*.txt"))
    record_property("file_count", file_count)
    record_property("elapsed_seconds", round(elapsed, 3))
    record_property("success_count", summary.success_count)
    record_property("partial_success_count", summary.partial_success_count)
    for label, payload in timer.snapshot().items():
        record_property(f"{label}_ms", payload["ms"])
        record_property(f"{label}_count", payload["count"])
    print(
        "many_small_files_success_pressure: "
        f"files={file_count}, elapsed={elapsed:.3f}s, "
        f"success={summary.success_count}, partial={summary.partial_success_count}, "
        f"hotspots={timer.hottest()}"
    )

    assert summary.success_count == 1
    assert summary.partial_success_count == 0
    assert len(extracted_files) == file_count
    assert elapsed < max_seconds


def test_many_small_files_partial_report_pressure(tmp_path, request, record_property):
    file_count = max(2, request.config.getoption("--repair-performance-small-file-count"))
    max_seconds = request.config.getoption("--repair-performance-max-seconds")
    archive = tmp_path / "many-small-partial.zip"
    bad_name = f"dir_{(file_count - 1) // 100:03d}/file_{file_count - 1:05d}.txt"
    _write_many_small_files_zip_with_bad_payload(archive, count=file_count, payload_size=32, bad_name=bad_name)

    runner = PipelineRunner(repair_pressure_config(tmp_path))
    timer = attach_timing(runner)
    started = time.perf_counter()
    try:
        summary = runner.run(str(tmp_path))
    finally:
        timer.restore()
    elapsed = time.perf_counter() - started

    report = tmp_path / "many-small-partial" / ".packrelic" / "recovery_report.json"
    record_property("file_count", file_count)
    record_property("elapsed_seconds", round(elapsed, 3))
    record_property("success_count", summary.success_count)
    record_property("partial_success_count", summary.partial_success_count)
    for label, payload in timer.snapshot().items():
        record_property(f"{label}_ms", payload["ms"])
        record_property(f"{label}_count", payload["count"])
    print(
        "many_small_files_partial_report_pressure: "
        f"files={file_count}, elapsed={elapsed:.3f}s, "
        f"success={summary.success_count}, partial={summary.partial_success_count}, "
        f"hotspots={timer.hottest()}"
    )

    assert summary.success_count == 1
    assert summary.partial_success_count == 1
    assert report.exists()
    assert elapsed < max_seconds


def _write_zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)


def _write_many_small_files_zip(path: Path, *, count: int, payload_size: int) -> None:
    payload = b"x" * max(1, payload_size)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
        for index in range(count):
            archive.writestr(f"dir_{index // 100:03d}/file_{index:05d}.txt", payload)


def _write_many_small_files_zip_with_bad_payload(
    path: Path,
    *,
    count: int,
    payload_size: int,
    bad_name: str,
) -> None:
    _write_many_small_files_zip(path, count=count, payload_size=payload_size)
    data = bytearray(path.read_bytes())
    payload = _zip_payload_offset(data, bad_name)
    data[payload] ^= 0xFF
    path.write_bytes(data)


def _write_zip_with_bad_cd_offset(path: Path) -> None:
    _write_zip(path, {"good_a.txt": b"a", "good_b.txt": b"b"})
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd >= 0
    data[eocd + 16 : eocd + 20] = b"\xff\xff\xff\x7f"
    path.write_bytes(data)


def _write_zip_with_bad_payload(path: Path, *, payload_size: int) -> None:
    _write_zip(path, {"good.txt": b"good", "bad.bin": b"A" * payload_size})
    data = bytearray(path.read_bytes())
    payload = _zip_payload_offset(data, "bad.bin")
    data[payload] ^= 0xFF
    path.write_bytes(data)


def _write_zip_with_bad_cd_offset_and_payload(path: Path, *, payload_size: int) -> None:
    _write_zip_with_bad_payload(path, payload_size=payload_size)
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd >= 0
    data[eocd + 16 : eocd + 20] = b"\xff\xff\xff\x7f"
    path.write_bytes(data)


def _write_missing_tail_split_zip(root: Path, stem: str, *, payload_size: int) -> None:
    source = root / f"{stem}_src"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"M" * payload_size)
    archive = root / f"{stem}.zip"
    try:
        subprocess.run(
            [str(require_7z()), "a", str(archive), str(source), "-tzip", "-mx=0", "-v50k", "-y"],
            cwd=str(root),
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        shutil.rmtree(source, ignore_errors=True)
    parts = sorted(root.glob(f"{stem}.zip.*"))
    assert len(parts) > 1
    parts[-1].unlink()


def _zip_payload_offset(data: bytes | bytearray, name: str) -> int:
    target = name.encode("utf-8")
    offset = 0
    while True:
        local = bytes(data).find(b"PK\x03\x04", offset)
        if local < 0:
            raise AssertionError(f"local header not found: {name}")
        name_len = struct.unpack_from("<H", data, local + 26)[0]
        extra_len = struct.unpack_from("<H", data, local + 28)[0]
        entry_name = bytes(data[local + 30 : local + 30 + name_len])
        payload_offset = local + 30 + name_len + extra_len
        if entry_name == target:
            return payload_offset
        offset = local + 4
