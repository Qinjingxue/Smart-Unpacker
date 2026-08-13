import binascii
import json
import subprocess
import struct
import tarfile
import zipfile

import pytest

from sunpack.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, ArchiveInputRange
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.internal.sevenzip.sevenzip_runner import _PersistentWorker
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.support.resources import get_7z_dll_path, get_sevenzip_bridge_worker_path
from tests.helpers.tool_config import get_test_tools


def _require_worker_or_skip():
    try:
        return get_sevenzip_bridge_worker_path()
    except Exception as exc:
        pytest.skip(f"sunpack_sevenzip_worker.exe is required: {exc}")


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


def _create_encrypted_zip(tmp_path, password: str = "secret"):
    seven_zip = _require_7z_or_skip()
    source = tmp_path / "encrypted-source.txt"
    source.write_text("encrypted worker payload", encoding="utf-8")
    archive = tmp_path / "encrypted.zip"
    result = subprocess.run(
        [
            str(seven_zip),
            "a",
            str(archive),
            str(source),
            "-tzip",
            "-mx=0",
            "-y",
            f"-p{password}",
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"7z failed:\n{result.stdout}\n{result.stderr}")
    return archive, source.name


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


def _create_shift_jis_zip(tmp_path):
    archive = tmp_path / "shift-jis.zip"
    expected_name = "日本語/説明.txt"
    raw_name = expected_name.encode("cp932")
    payload = b"shift-jis payload"
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name), 0,
    ) + raw_name + payload
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50, 20, 20, 0, 0, 0, 0, crc,
        len(payload), len(payload), len(raw_name),
        0, 0, 0, 0, 0, 0,
    ) + raw_name
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50, 0, 0, 1, 1, len(central), len(local), 0,
    )
    archive.write_bytes(local + central + eocd)
    return archive, expected_name, payload


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


def test_worker_does_not_classify_unencrypted_open_failure_as_wrong_password(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive = tmp_path / "malformed.7z"
    archive.write_bytes(b"7z\xbc\xaf'\x1c" + b"\x00" * 26)
    payload = {
        "job_id": "unencrypted-open-failure",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(tmp_path / "out"),
        "password": "irrelevant",
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
    assert worker_result["wrong_password"] is False
    assert worker_result["encrypted"] is False
    assert worker_result["failure_kind"] != "encrypted_or_wrong_password"


def test_worker_candidate_batch_probes_then_extracts_with_selected_password(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive, filename = _create_encrypted_zip(tmp_path)
    from sunpack.passwords.verifier.zip_fast import ZipFastVerifier

    weak_candidates = [f"weak-collision-{index}" for index in range(1024)]
    weak_match = ZipFastVerifier().verify_batch(str(archive), [*weak_candidates, "secret"])
    collision = next(
        (
            weak_candidates[index]
            for index in weak_match.matched_indices
            if index < len(weak_candidates)
        ),
        None,
    )
    if collision is None:
        pytest.skip("the generated ZipCrypto header had no weak false-positive candidate")
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "candidate-batch-success",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
        "password": "weak-header-placeholder",
        "password_candidates": [collision, "secret"],
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
    assert worker_result["password_candidate_batch"] is True
    assert worker_result["password_candidates_all_rejected"] is False
    assert worker_result["password_candidate_count"] == 2
    assert worker_result["password_attempts"] == 2
    assert worker_result["matched_index"] == 1
    assert (out_dir / filename).read_text(encoding="utf-8") == "encrypted worker payload"


def test_worker_candidate_batch_rejects_all_candidates_without_full_extraction(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive, filename = _create_encrypted_zip(tmp_path)
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "candidate-batch-rejected",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
        "password": "weak-header-placeholder",
        "password_candidates": ["wrong-password-1", "wrong-password-2"],
    }

    result = subprocess.run(
        [worker],
        input=json.dumps(payload, ensure_ascii=False),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    worker_result = _worker_result(result.stdout)

    assert result.returncode != 0
    assert worker_result["status"] == "failed"
    assert worker_result["native_status"] == "wrong_password"
    assert worker_result["failure_stage"] == "password_probe"
    assert worker_result["password_candidate_batch"] is True
    assert worker_result["password_candidates_all_rejected"] is True
    assert worker_result["password_candidate_count"] == 2
    assert worker_result["password_attempts"] == 2
    assert worker_result["matched_index"] == -1
    assert not (out_dir / filename).exists()


def test_persistent_worker_result_escapes_control_characters(tmp_path):
    worker_path = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive = tmp_path / "control-name.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("control-\x01-name.txt", "unsafe filename payload")
    payload = {
        "job_id": "control-name",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(tmp_path / "out"),
    }
    runner = ExtractionScheduler(
        max_retries=1,
        process_config={"max_extract_task_seconds": 2, "process_sample_interval_ms": 10},
    ).sevenzip_runner
    persistent = _PersistentWorker(worker_path, None)

    try:
        persistent.send(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
        stdout, stderr, returncode, reusable, result_payload, _progress_events = runner._read_persistent_worker_result(  # noqa: SLF001
            persistent,
            runtime_scheduler=None,
            task=_task(archive),
        )
    finally:
        persistent.close()

    worker_result = result_payload
    assert returncode != 0
    assert reusable is True
    assert "timed out" not in stderr.lower()
    assert worker_result["job_id"] == "control-name"
    assert worker_result["failed_item"] == "control-\x01-name.txt"
    assert worker_result["diagnostics"]["failed_item"]["path"] == "control-\x01-name.txt"


def test_persistent_worker_starts_in_neutral_working_directory(tmp_path, monkeypatch):
    captured = {}

    class StartObserved(RuntimeError):
        pass

    def fake_popen(*args, **kwargs):
        captured.update(kwargs)
        raise StartObserved

    monkeypatch.setattr(
        "sunpack.extraction.internal.sevenzip.sevenzip_runner.runtime_working_directory",
        lambda: str(tmp_path),
    )
    monkeypatch.setattr("sunpack.extraction.internal.sevenzip.sevenzip_runner.subprocess.Popen", fake_popen)

    with pytest.raises(StartObserved):
        _PersistentWorker("worker.exe", None)

    assert captured["cwd"] == str(tmp_path)


def test_compact_worker_manifest_is_parsed_into_native_storage():
    from sunpack.extraction.internal.sevenzip.worker_diagnostics import (
        build_worker_diagnostics,
        worker_manifest_files,
    )

    stdout = (
        '{"type":"result","status":"ok","verified_manifest":'
        '{"version":3,"validated":true,"item_count":1,"file_count":1,'
        '"inventory":[1,1,0,3,1],"rows":[[0,"a.txt","",3,3,1,1,1,1,1,1,1,123,"616263"]]}}\n'
    )
    result = build_worker_diagnostics(stdout=stdout, stderr="", returncode=0)["result"]

    manifest = result["verified_manifest"]
    native = manifest["native_rows"]
    assert len(native) == 1
    assert native.all_complete() is True
    assert "files" not in manifest
    materialized = worker_manifest_files(result)[0]
    assert materialized["path"] == "a.txt"
    assert "output_path" not in materialized
    assert materialized["status"] == "complete"
    assert materialized["magic"] == b"abc"
    assert materialized["mtime_ns"] == 123
    assert result["verified_manifest"]["inventory"]["identity_paths"] is True
    assert "rows" not in manifest


def test_worker_manifest_v2_is_not_accepted():
    from sunpack.extraction.internal.sevenzip.worker_diagnostics import build_worker_diagnostics

    payload = {
        "type": "result",
        "status": "ok",
        "verified_manifest": {"version": 2, "validated": True, "rows": []},
    }
    result = build_worker_diagnostics(stdout="", stderr="", returncode=0, result_payload=payload)["result"]

    assert "native_rows" not in result["verified_manifest"]


def test_preparsed_worker_result_avoids_stdout_reparse_and_bounds_tail():
    from sunpack.extraction.internal.sevenzip.worker_diagnostics import (
        build_worker_diagnostics,
        worker_manifest_files,
    )

    result_payload = {
        "type": "result",
        "status": "ok",
        "verified_manifest": {
            "version": 3,
            "validated": True,
            "rows": [[0, "source.txt", "output.txt", 3, 3, 1, 7, 1, 7, 1, 1, 1, 123, "616263"]],
            "inventory": [1, 1, 0, 3, 0],
        },
    }
    diagnostics = build_worker_diagnostics(
        stdout="x" * 100_000,
        stderr="",
        returncode=0,
        result_payload=result_payload,
    )

    assert diagnostics["result"] is result_payload
    assert "rows" not in result_payload["verified_manifest"]
    assert "files" not in result_payload["verified_manifest"]
    files = worker_manifest_files(result_payload)
    assert files[0]["path"] == "source.txt"
    assert files[0]["output_path"] == "output.txt"
    assert sum(len(line) for line in diagnostics["process"]["stdout_tail"]) <= 4000


def test_complete_worker_inventory_drops_transient_native_rows_and_output_trace():
    from sunpack.extraction.internal.sevenzip.worker_diagnostics import (
        build_worker_diagnostics,
        compact_success_worker_diagnostics,
    )

    result = {
        "status": "ok",
        "verified_manifest": {
            "version": 3,
            "validated": True,
            "inventory": [1, 1, 0, 3, 1],
            "rows": [[0, "a.txt", "", 3, 3, 1, 7, 1, 7, 1, 1, 1, 123, "616263"]],
        },
        "diagnostics": {"output_trace": {"items": [{"path": "a.txt"}], "files_written": 1}},
    }
    diagnostics = build_worker_diagnostics(stdout="", stderr="", returncode=0, result_payload=result)

    compact_success_worker_diagnostics(diagnostics)

    assert "items" not in result["diagnostics"]["output_trace"]
    assert "native_rows" not in result["verified_manifest"]


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


def test_worker_propagates_delayed_async_file_open_failure(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive, _ = _create_7z(tmp_path, "async-open-failure", "payload")
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "async-open-failure",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        # Wildcards pass archive path traversal validation, but CreateFileW
        # rejects them. The async writer must report that delayed failure
        # after draining instead of publishing a successful extraction.
        "decoded_names": ["invalid*output.txt"],
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

    assert result.returncode != 0
    assert worker_result["status"] == "failed"
    assert worker_result["failure_stage"] == "output_write"
    assert worker_result["failure_kind"] == "output_filesystem"
    assert worker_result["files_written"] == 0
    assert output_items[-1]["failed"] is True
    assert output_items[-1]["bytes_written"] == 0
    assert not list(out_dir.glob("invalid*output.txt"))


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
    item = output_trace["items"][0]
    assert item["path"].endswith(filename)
    assert item["has_source_crc32"] is True
    assert item["has_output_crc32"] is True
    assert item["output_crc32"] == item["source_crc32"]
    assert item["crc_verified"] is True
    assert not dry_output.exists()


def test_worker_dry_run_hashes_output_when_source_crc_is_missing(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    payload = b"tar payload without an archive CRC"
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)
    archive = tmp_path / "payload.tar"
    with tarfile.open(archive, "w") as handle:
        handle.add(source, arcname=source.name)
    result = subprocess.run(
        [worker],
        input=json.dumps({
            "job_id": "dry-run-no-source-crc",
            "seven_zip_dll_path": seven_zip_dll,
            "archive_path": str(archive),
            "output_dir": "",
            "format_hint": "tar",
            "dry_run": True,
        }),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    worker_result = _worker_result(result.stdout)
    item = next(
        row for row in worker_result["diagnostics"]["output_trace"]["items"]
        if not row["is_dir"]
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert item["has_source_crc32"] is False
    assert item["has_output_crc32"] is True
    assert item["output_crc32"] == (binascii.crc32(payload) & 0xFFFFFFFF)
    assert item["crc_verified"] is True


def test_worker_async_output_extracts_format_without_source_crc(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    payload = b"streamed tar payload"
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)
    archive = tmp_path / "payload.tar"
    with tarfile.open(archive, "w") as handle:
        handle.add(source, arcname=source.name)
    out_dir = tmp_path / "out"

    result = subprocess.run(
        [worker],
        input=json.dumps({
            "job_id": "async-no-source-crc",
            "seven_zip_dll_path": seven_zip_dll,
            "archive_path": str(archive),
            "output_dir": str(out_dir),
            "format_hint": "tar",
        }),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    worker_result = _worker_result(result.stdout)

    assert result.returncode == 0, result.stdout + result.stderr
    assert worker_result["status"] == "ok"
    assert worker_result["files_written"] == 1
    assert worker_result["bytes_written"] == len(payload)
    manifest = worker_result["verified_manifest"]
    assert manifest["version"] == 3
    row = manifest["rows"][0]
    assert len(row) == 14
    assert row[11] == 1
    assert row[12] > 0
    assert row[13] == payload[:16].hex()
    assert (out_dir / source.name).read_bytes() == payload


def test_worker_applies_explicit_shift_jis_item_paths(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive, expected_name, payload_bytes = _create_shift_jis_zip(tmp_path)
    out_dir = tmp_path / "out"
    payload = {
        "job_id": "shift-jis",
        "seven_zip_dll_path": seven_zip_dll,
        "archive_path": str(archive),
        "output_dir": str(out_dir),
        "format_hint": "zip",
        "codepage": "932",
        "decoded_names": [expected_name],
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
    assert worker_result["requested_codepage"] == "932"
    assert worker_result["applied_codepage"] == "932"
    assert worker_result["filename_decoder"] == "sunpack_zip_raw_names"
    assert (out_dir / "日本語" / "説明.txt").read_bytes() == payload_bytes


def test_worker_batch_isolates_failed_job_and_continues(tmp_path):
    worker = _require_worker_or_skip()
    seven_zip_dll = _require_7z_dll_or_skip()
    archive = tmp_path / "ok.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("ok.txt", "batch payload")
    request = {
        "worker_command": "batch_extract",
        "batch_id": "isolation",
        "jobs": [
            {"job_id": "bad", "seven_zip_dll_path": seven_zip_dll, "archive_path": str(tmp_path / "missing.zip"), "output_dir": str(tmp_path / "bad")},
            {"job_id": "ok", "seven_zip_dll_path": seven_zip_dll, "archive_path": str(archive), "output_dir": str(tmp_path / "ok")},
        ],
    }

    result = subprocess.run([worker], input=json.dumps(request), capture_output=True, text=True, encoding="utf-8")
    messages = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    results = {message["job_id"]: message for message in messages if message.get("type") == "result"}
    batch = next(message for message in messages if message.get("type") == "batch_result")

    assert results["bad"]["status"] == "failed"
    assert results["ok"]["status"] == "ok"
    assert batch["status"] == "partial"
    assert batch["failed_count"] == 1
    assert (tmp_path / "ok" / "ok.txt").read_text(encoding="utf-8") == "batch payload"


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
