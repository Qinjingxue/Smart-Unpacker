import json
import subprocess
import struct
import zipfile

import pytest

from packrelic.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, ArchiveInputRange
from packrelic.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from packrelic.contracts.detection import FactBag
from packrelic.contracts.tasks import ArchiveTask
from packrelic.extraction.scheduler import ExtractionScheduler
from packrelic.support.resources import get_7z_dll_path, get_sevenzip_worker_path
from tests.helpers.tool_config import get_test_tools


def _require_worker_or_skip():
    try:
        return get_sevenzip_worker_path()
    except Exception as exc:
        pytest.skip(f"sevenzip_worker.exe is required: {exc}")


def _require_7z_or_skip():
    seven_zip = get_test_tools()["seven_zip"]
    if not seven_zip or not seven_zip.is_file():
        pytest.skip("7z.exe is required to build worker extraction fixtures")
    _require_worker_or_skip()
    return seven_zip


def _require_7z_dll_or_skip():
    try:
        return get_7z_dll_path()
    except Exception as exc:
        pytest.skip(f"7z.dll is required: {exc}")


def _create_7z(tmp_path, name: str, text: str):
    seven_zip = _require_7z_or_skip()
    source = tmp_path / f"{name}.txt"
    source.write_text(text, encoding="utf-8")
    archive = tmp_path / f"{name}.7z"
    result = subprocess.run(
        [str(seven_zip), "a", str(archive), str(source), "-mx=0", "-y"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"7z failed:\n{result.stdout}\n{result.stderr}")
    return archive, source.name


def _create_7z_with_nested_file(tmp_path):
    seven_zip = _require_7z_or_skip()
    nested_dir = tmp_path / "conflict"
    nested_dir.mkdir()
    child = nested_dir / "child.txt"
    child.write_text("nested payload", encoding="utf-8")
    archive = tmp_path / "nested.7z"
    result = subprocess.run(
        [str(seven_zip), "a", str(archive), "conflict\\child.txt", "-mx=0", "-y"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"7z failed:\n{result.stdout}\n{result.stderr}")
    return archive


def _create_zip_with_bad_eocd_count(tmp_path):
    archive = tmp_path / "bad_count.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("payload.txt", "patched worker payload")
    data = bytearray(archive.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise RuntimeError("test ZIP did not contain EOCD")
    struct.pack_into("<H", data, eocd + 10, 99)
    archive.write_bytes(bytes(data))
    return archive, eocd


def test_worker_failed_result_includes_diagnostics(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    missing = tmp_path / "missing.7z"
    payload = {
        "job_id": "diagnostics",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(missing),
        "output_dir": str(tmp_path / "out"),
    }

    result = subprocess.run(
        [worker],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip().startswith("{")]
    worker_result = next(item for item in lines if item.get("type") == "result")

    assert result.returncode != 0
    assert worker_result["status"] == "failed"
    assert worker_result["failure_stage"] == "input_open"
    assert worker_result["failure_kind"] == "input_stream"
    assert worker_result["operation_result_name"] == "ok"
    assert worker_result["diagnostics"]["input_trace"]["read_error"] is True
    assert worker_result["diagnostics"]["input_trace"]["last_win32_error"] != 0
    assert "handler_attempts" in worker_result["diagnostics"]
    assert "output_trace" in worker_result["diagnostics"]


def test_worker_dry_run_reads_archive_state_with_patch_stack(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive, eocd = _create_zip_with_bad_eocd_count(tmp_path)
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(archive), format_hint="zip")
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[PatchPlan(operations=[PatchOperation.replace_bytes(offset=eocd + 10, data=struct.pack("<H", 1))])],
    )
    payload = {
        "job_id": "patched-state",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "part_paths": [str(archive)],
        "archive_state": state.to_dict(),
        "format_hint": "zip",
        "dry_run": True,
    }

    result = subprocess.run(
        [worker],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip().startswith("{")]
    worker_result = next(item for item in lines if item.get("type") == "result")

    assert result.returncode == 0, result.stdout + result.stderr
    assert worker_result["status"] == "ok"
    assert worker_result["diagnostics"]["input_trace"]["mode"] == "virtual_patch"


def test_worker_dry_run_reads_7z_archive_state_with_sfx_crop_patch(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive, filename = _create_7z(tmp_path, "sfx-patched", "7z patched payload")
    prefix = b"MZ-SFX-STUB" * 17
    carrier = tmp_path / "sfx-carrier.exe"
    carrier.write_bytes(prefix + archive.read_bytes())
    state = ArchiveState.from_archive_input(
        ArchiveInputDescriptor.from_parts(archive_path=str(carrier), format_hint="7z"),
        patches=[PatchPlan(
            id="crop-7z-sfx-prefix",
            operations=[PatchOperation.delete_range(offset=0, size=len(prefix))],
            confidence=0.98,
        )],
    )
    payload = {
        "job_id": "patched-7z-state",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(carrier),
        "part_paths": [str(carrier)],
        "archive_state": state.to_dict(),
        "format_hint": "7z",
        "dry_run": True,
    }

    result = subprocess.run(
        [worker],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    worker_result = _worker_result(result.stdout)

    assert result.returncode == 0, result.stdout + result.stderr
    assert worker_result["status"] == "ok"
    assert worker_result["diagnostics"]["input_trace"]["mode"] == "virtual_patch"
    assert worker_result["diagnostics"]["input_trace"]["virtual_size"] == archive.stat().st_size
    assert worker_result["diagnostics"]["output_trace"]["items"][0]["path"].endswith(filename)


def test_worker_output_trace_includes_per_item_failure(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive = _create_7z_with_nested_file(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "conflict").write_text("blocks directory creation", encoding="utf-8")
    payload = {
        "job_id": "output-trace",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(out_dir),
    }

    result = subprocess.run(
        [worker],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip().startswith("{")]
    worker_result = next(item for item in lines if item.get("type") == "result")
    output_items = worker_result["diagnostics"]["output_trace"]["items"]
    failed_items = [item for item in output_items if item["failed"]]

    assert result.returncode != 0
    assert worker_result["failure_stage"] == "output_write"
    assert failed_items
    assert failed_items[-1]["bytes_written"] == 0
    assert "conflict" in failed_items[-1]["path"].replace("\\", "/")


def test_worker_dry_run_reports_success_diagnostics_without_writing(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive, filename = _create_7z(tmp_path, "dryrun", "dry-run payload")
    dry_output = tmp_path / "dry_output"
    payload = {
        "job_id": "dry-run",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(dry_output),
        "format_hint": "7z",
        "dry_run": True,
    }

    result = subprocess.run(
        [worker],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip().startswith("{")]
    worker_result = next(item for item in lines if item.get("type") == "result")
    output_trace = worker_result["diagnostics"]["output_trace"]

    assert result.returncode == 0
    assert worker_result["status"] == "ok"
    assert worker_result["dry_run"] is True
    assert worker_result["files_written"] == 1
    assert worker_result["bytes_written"] == len("dry-run payload")
    assert output_trace["items"]
    assert output_trace["items"][0]["path"].endswith(filename)
    assert not dry_output.exists()


def test_extraction_scheduler_saves_process_failure_diagnostics(tmp_path):
    archive = tmp_path / "sample.bin"
    archive.write_bytes(b"not an archive")
    scheduler = ExtractionScheduler(max_retries=1)
    scheduler.sevenzip_runner.worker_path = str(tmp_path / "missing_worker.exe")

    try:
        result = scheduler.extract(_task(archive), str(tmp_path / "out"))
    finally:
        scheduler.close()

    assert result.success is False
    assert result.diagnostics["process_failure"]["failure_stage"] == "worker_start"
    assert result.diagnostics["process_failure"]["failure_kind"] == "process_start"
    assert result.diagnostics["repro"]["request"]["archive_path"] == str(archive)


def test_extraction_scheduler_classifies_malformed_worker_output_as_process_exit(tmp_path):
    worker = tmp_path / "malformed_worker.cmd"
    worker.write_text("@echo not-json\r\n@exit /b 2\r\n", encoding="utf-8")
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"not used")
    scheduler = ExtractionScheduler(max_retries=1, process_config={"persistent_workers": False})
    scheduler.sevenzip_runner.worker_path = str(worker)

    try:
        result = scheduler.extract(_task(archive), str(tmp_path / "out"))
    finally:
        scheduler.close()

    assert result.success is False
    assert result.diagnostics["failure_stage"] == "worker_exit"
    assert result.diagnostics["failure_kind"] == "process_exit"
    assert result.diagnostics["process_failure"]["message"]


def test_sevenzip_runner_observed_process_timeout_reports_process_timeout(tmp_path):
    worker = tmp_path / "sleep_worker.cmd"
    worker.write_text("@ping 127.0.0.1 -n 3 >nul\r\n", encoding="utf-8")
    scheduler = ExtractionScheduler(
        max_retries=1,
        process_config={
            "persistent_workers": False,
            "max_extract_task_seconds": 0.1,
            "process_sample_interval_ms": 10,
        },
    )
    process = subprocess.Popen(
        [str(worker)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )

    stdout, stderr = scheduler.sevenzip_runner.communicate_observed_process(process, runtime_scheduler=None, task=_task(worker))
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        process.kill()
    finally:
        scheduler.close()

    assert stdout == ""
    assert "timed out" in stderr
    assert process.returncode == -101


def _task(path, archive_input=None):
    bag = FactBag()
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(path)])
    if archive_input:
        bag.set("archive.input", archive_input)
    return ArchiveTask(
        fact_bag=bag,
        score=100,
        main_path=str(path),
        all_parts=[str(path)],
        key=str(path),
    )


def _worker_result(stdout: str) -> dict:
    lines = [json.loads(line) for line in stdout.splitlines() if line.strip().startswith("{")]
    return next(item for item in lines if item.get("type") == "result")


def test_extraction_scheduler_uses_worker_for_file_range(tmp_path):
    archive, filename = _create_7z(tmp_path, "payload", "range payload")
    data = archive.read_bytes()
    prefix = b"SHELLDATA"
    mixed = tmp_path / "mixed.bin"
    mixed.write_bytes(prefix + data + b"TAIL")

    task = _task(mixed, {
        "kind": "file_range",
        "path": str(mixed),
        "start": len(prefix),
        "end": len(prefix) + len(data),
        "format_hint": "7z",
    })
    result = ExtractionScheduler(max_retries=1).extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert (tmp_path / "out" / filename).read_text(encoding="utf-8") == "range payload"


def test_extraction_scheduler_saves_worker_diagnostics_on_failure(tmp_path):
    _require_worker_or_skip()
    _require_7z_dll_or_skip()
    missing = tmp_path / "missing.7z"
    result = ExtractionScheduler(max_retries=1).extract(_task(missing), str(tmp_path / "out"))

    assert result.success is False
    assert result.diagnostics["result"]["failure_stage"] == "input_open"
    assert result.diagnostics["result"]["failure_kind"] == "input_stream"
    assert result.diagnostics["result"]["diagnostics"]["input_trace"]["read_error"] is True
    assert result.diagnostics["repro"]["request"]["archive_path"] == str(missing)


def test_extraction_scheduler_uses_worker_for_concat_ranges(tmp_path):
    archive, filename = _create_7z(tmp_path, "payload", "concat payload")
    data = archive.read_bytes()
    midpoint = len(data) // 2
    part_a = tmp_path / "part_a.bin"
    part_b = tmp_path / "part_b.bin"
    part_a.write_bytes(data[:midpoint])
    part_b.write_bytes(data[midpoint:])

    virtual = tmp_path / "payload.virtual"
    virtual.write_bytes(b"not used directly")
    task = _task(virtual, {
        "kind": "concat_ranges",
        "format_hint": "7z",
        "ranges": [
            {"path": str(part_a), "start": 0},
            {"path": str(part_b), "start": 0},
        ],
    })
    result = ExtractionScheduler(max_retries=1).extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert (tmp_path / "out" / filename).read_text(encoding="utf-8") == "concat payload"


def test_extraction_scheduler_uses_worker_archive_input_descriptor(tmp_path):
    archive, filename = _create_7z(tmp_path, "payload", "descriptor payload")
    data = archive.read_bytes()
    prefix = b"DESCRIPTOR"
    mixed = tmp_path / "descriptor.bin"
    mixed.write_bytes(prefix + data + b"TAIL")

    descriptor = ArchiveInputDescriptor(
        entry_path=str(mixed),
        open_mode="file_range",
        format_hint="7z",
        parts=[
            ArchiveInputPart(
                path=str(mixed),
                range=ArchiveInputRange(path=str(mixed), start=len(prefix), end=len(prefix) + len(data)),
            )
        ],
    )
    task = _task(mixed, descriptor.to_dict())
    result = ExtractionScheduler(max_retries=1).extract(task, str(tmp_path / "out"))

    assert result.success is True
    assert (tmp_path / "out" / filename).read_text(encoding="utf-8") == "descriptor payload"
