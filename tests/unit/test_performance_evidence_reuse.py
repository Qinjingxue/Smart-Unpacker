from types import SimpleNamespace
import zipfile

from sunpack.contracts.detection import FactBag
from sunpack.contracts.archive_state import ArchiveSource, ArchiveState
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.scheduling import machine_probe
from sunpack.extraction.result import ExtractionResult
from sunpack.verification import VerificationScheduler
from sunpack.verification import archive_state_manifest as manifest_module
from sunpack.verification.methods import _output_stats
from sunpack.verification.methods import archive_test_crc as archive_test_crc_module
from sunpack.verification.methods.archive_test_crc import _can_use_worker_output_crc, _worker_crc_match_result


def _worker_result():
    return {
        "status": "ok",
        "archive_type": "zip",
        "verified_manifest": {
            "validated": True,
            "source": "sevenzip_worker_extract",
            "item_count": 1,
            "file_count": 1,
            "files": [{
                "path": "a.txt",
                "size": 5,
                "bytes_written": 5,
                "has_crc": True,
                "crc32": 0x3610A686,
                "has_output_crc": True,
                "output_crc32": 0x3610A686,
                "crc_ok": True,
                "status": "complete",
            }],
        },
    }


def test_machine_probe_persists_disk_type(monkeypatch, tmp_path):
    cache_path = tmp_path / "machine.json"
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="SSD\n")

    monkeypatch.setattr(machine_probe.os, "name", "nt")
    monkeypatch.setenv("SUNPACK_MACHINE_PROBE_CACHE", str(cache_path))
    monkeypatch.setattr(machine_probe.subprocess, "run", fake_run)
    machine_probe._MEMORY_CACHE.clear()

    assert machine_probe.detect_max_workers() >= 2
    machine_probe._MEMORY_CACHE.clear()  # Simulate a fresh process.
    assert machine_probe.detect_max_workers() >= 2
    assert len(calls) == 1


def test_worker_manifest_avoids_native_source_manifest(monkeypatch):
    state = ArchiveState(source=ArchiveSource(entry_path="sample.zip", format_hint="zip"))
    evidence = SimpleNamespace(
        archive_state=state,
        password=None,
        selected_codepage=None,
        patch_digest=state.effective_patch_digest(),
        worker_result=_worker_result(),
    )

    monkeypatch.setattr(
        manifest_module,
        "archive_state_manifest",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("native manifest must not run")),
    )

    manifest = manifest_module.archive_state_manifest_for_evidence(evidence)
    assert manifest.ok
    assert manifest.source == "sevenzip_worker_extract"
    assert manifest.files[0]["crc32"] == 0x3610A686


def test_output_inventory_scans_once_and_merges_worker_crc(monkeypatch):
    calls = []

    def fake_scan(path):
        calls.append(path)
        return {
            "exists": True,
            "is_dir": True,
            "file_count": 1,
            "dir_count": 0,
            "total_size": 5,
            "transient_file_count": 0,
            "unreadable_count": 0,
            "files": [{"path": "a.txt", "size": 5}],
        }

    monkeypatch.setattr(_output_stats, "_native_scan_output_tree", fake_scan)
    evidence = SimpleNamespace(output_dir="out", worker_result=_worker_result())

    inventory = _output_stats.output_inventory_for_evidence(evidence)
    assert _output_stats.output_stats_for_evidence(evidence).file_count == 1
    assert _output_stats.output_files_for_evidence(evidence)[0]["crc32"] == 0x3610A686
    assert inventory.worker_crc_available
    assert calls == ["out"]


def test_worker_output_crc_replaces_output_file_reread():
    archive_files = [{"path": "a.txt", "size": 5, "has_crc": True, "crc32": 0x3610A686}]
    output_files = ({"path": "a.txt", "size": 5, "crc32": 0x3610A686},)

    assert _can_use_worker_output_crc(archive_files, output_files, True)
    result = _worker_crc_match_result(archive_files, list(output_files))
    assert result["status"] == "ok"
    assert result["mismatches"] == []
    assert result["coverage"]["completeness"] == 1.0


def test_verification_pipeline_uses_worker_source_and_output_evidence(monkeypatch, tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("a.txt", b"hello")
    output = tmp_path / "out"
    output.mkdir()
    (output / "a.txt").write_bytes(b"hello")
    task = ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        key="worker-evidence",
        main_path=str(archive),
        all_parts=[str(archive)],
        detected_ext="zip",
    )
    extraction = ExtractionResult(
        success=True,
        archive=str(archive),
        out_dir=str(output),
        all_parts=[str(archive)],
        diagnostics={"result": _worker_result()},
    )
    monkeypatch.setattr(
        manifest_module,
        "archive_state_manifest",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("source must not be reread")),
    )
    monkeypatch.setattr(
        archive_test_crc_module,
        "_match_archive_output_crc_coverage",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("output must not be reread")),
    )

    result = VerificationScheduler({
        "verification": {"enabled": True, "methods": [{"name": "archive_test_crc"}]}
    }).verify(task, extraction)

    assert result.decision_hint == "accept"
    assert result.completeness == 1.0
