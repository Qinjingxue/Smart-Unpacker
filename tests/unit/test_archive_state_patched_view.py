import struct
import zipfile
import gzip
import io
import tarfile

from sunpack.analysis.scheduler import ArchiveAnalysisScheduler
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.diagnosis import diagnose_repair_job
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules.archive_carrier_crop import attach_native_crop_patch_plans
from sunpack.repair.pipeline.modules.gzip.trailing_junk_trim import GzipTrailingJunkTrim
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules.tar.checksum_fix import TarHeaderChecksumFix
from sunpack.repair.pipeline.modules.zip._rebuild import rebuild_zip_from_source
from sunpack.repair.pipeline.modules.zip.trailing_junk_trim import ZipTrailingJunkTrim
from sunpack.support.archive_state_view import ArchiveStateByteView


def test_archive_state_byte_view_applies_replace_truncate_append(tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"abcdefjunk")
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[
            PatchPlan(operations=[
                PatchOperation.replace_bytes(offset=1, data=b"ZZ"),
                PatchOperation(op="truncate", offset=6),
                PatchOperation.append_bytes(b"tail"),
            ])
        ],
    )

    view = ArchiveStateByteView(state)

    assert view.size == 10
    assert view.read_at(0, 20) == b"aZZdeftail"
    assert view.read_tail(4) == b"tail"


def test_archive_state_byte_view_applies_delete_insert(tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"prefixARCHIVEtail")
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="rar")
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[
            PatchPlan(operations=[
                PatchOperation.delete_range(offset=0, size=6),
                PatchOperation(op="truncate", offset=7),
                PatchOperation(op="insert", offset=7, data_b64="IQ=="),
            ])
        ],
    )

    assert ArchiveStateByteView(state).to_bytes() == b"ARCHIVE!"


def test_analysis_reads_non_empty_patch_state(tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", "hello")
    data = bytearray(archive.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    assert eocd >= 0
    struct.pack_into("<H", data, eocd + 10, 99)
    archive.write_bytes(bytes(data))

    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(archive), format_hint="zip")
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[PatchPlan(operations=[PatchOperation.replace_bytes(offset=eocd + 10, data=struct.pack("<H", 1))])],
    )
    bag = FactBag()
    task = ArchiveTask(fact_bag=bag, score=10, main_path=str(archive), all_parts=[str(archive)], detected_ext="zip")
    task.set_archive_state(state)

    report = ArchiveAnalysisScheduler({"analysis": {"fuzzy": {"enabled": False}}}).analyze_task(task)

    assert report.selected
    assert report.selected[0].format == "zip"
    assert report.selected[0].status == "extractable"


def test_zip_repair_module_reads_patched_source_state(tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.txt", "hello")
    raw = archive.read_bytes()
    eocd = raw.rfind(b"PK\x05\x06")
    damaged = raw + b"junk"
    archive.write_bytes(damaged)

    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(archive), format_hint="zip")
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[PatchPlan(operations=[PatchOperation(op="truncate", offset=eocd + 22)])],
    )
    job = RepairJob(
        source_input={"kind": "file", "path": str(archive), "format_hint": "zip"},
        format="zip",
        damage_flags=["trailing_junk"],
        archive_state=state,
    )

    result = ZipTrailingJunkTrim().repair(
        job,
        RepairDiagnosis(format="zip", confidence=0.9, categories=("boundary_repair",), repairable=True),
        str(tmp_path),
        {},
    )

    assert result.status == "unrepairable"
    assert "no trailing bytes" in result.message


def test_stream_repair_module_reads_patched_state_for_materialized_output(tmp_path):
    patched = gzip.compress(b"payload") + b"junk"
    source = tmp_path / "raw.gz"
    source.write_bytes(b"\0" * len(patched))
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="gzip")
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[PatchPlan(operations=[PatchOperation.replace_bytes(offset=0, data=patched)])],
    )
    job = RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "gzip"},
        format="gzip",
        damage_flags=["trailing_junk"],
        workspace=str(tmp_path / "repair"),
        archive_state=state,
    )

    result = GzipTrailingJunkTrim().repair(
        job,
        diagnose_repair_job(job),
        str(tmp_path / "repair"),
        {},
    )

    assert result.ok
    assert result.repaired_input is not None
    with open(result.repaired_input["path"], "rb") as handle:
        assert gzip.decompress(handle.read()) == b"payload"


def test_stream_repair_module_can_return_virtual_patch_candidate(tmp_path):
    source = tmp_path / "raw.gz"
    source.write_bytes(gzip.compress(b"payload") + b"junk")
    job = RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "gzip"},
        format="gzip",
        damage_flags=["trailing_junk"],
        workspace=str(tmp_path / "repair"),
    )

    result = GzipTrailingJunkTrim().repair(
        job,
        diagnose_repair_job(job),
        str(tmp_path / "repair"),
        {"virtual_patch_candidate": True},
    )

    assert result.ok
    assert result.repaired_input == {
        "kind": "archive_state",
        "patch_digest": result.repaired_state.effective_patch_digest(),
        "format_hint": "gzip",
    }
    assert gzip.decompress(ArchiveStateByteView(result.repaired_state).to_bytes()) == b"payload"


def test_tar_checksum_fix_can_return_virtual_patch_candidate(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo("payload.txt")
        payload = b"hello"
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    data = bytearray(buffer.getvalue())
    data[148:156] = b"000000\0 "
    source = tmp_path / "bad.tar"
    source.write_bytes(bytes(data))
    job = RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "tar"},
        format="tar",
        damage_flags=["tar_checksum_bad"],
        workspace=str(tmp_path / "repair"),
    )

    result = TarHeaderChecksumFix().repair(
        job,
        diagnose_repair_job(job),
        str(tmp_path / "repair"),
        {"virtual_patch_candidate": True},
    )

    assert result.ok
    repaired = ArchiveStateByteView(result.repaired_state).to_bytes()
    with tarfile.open(fileobj=io.BytesIO(repaired), mode="r:") as tar:
        assert tar.extractfile("payload.txt").read() == b"hello"


def test_native_crop_metadata_can_become_virtual_patch_candidate(tmp_path):
    source = tmp_path / "carrier.bin"
    source.write_bytes(b"prefixARCHIVEtail")
    job = RepairJob(
        source_input={"kind": "file", "path": str(source), "format_hint": "rar"},
        format="rar",
        damage_flags=["carrier_prefix"],
    )
    diagnosis = RepairDiagnosis(format="rar", confidence=0.8, categories=("boundary_repair",), repairable=True)
    native_result = {
        "status": "repaired",
        "format": "rar",
        "candidates": [{
            "name": "crop",
            "status": "repaired",
            "format": "rar",
            "offset": 6,
            "end_offset": 13,
            "output_bytes": 7,
            "confidence": 0.9,
            "actions": ["crop_embedded_archive_from_carrier"],
        }],
    }

    attach_native_crop_patch_plans(native_result, job, "rar_carrier_crop_deep_recovery")
    candidates = candidates_from_native_result(
        "rar_carrier_crop_deep_recovery",
        native_result,
        job,
        diagnosis,
        native_key="native_archive_deep_repair",
        prefer_patch_plan=True,
    )

    assert len(candidates) == 1
    assert candidates[0].repaired_input["kind"] == "archive_state"
    state = ArchiveState.from_dict(candidates[0].plan["archive_state"])
    assert ArchiveStateByteView(state).to_bytes() == b"ARCHIVE"


def test_native_zip_rebuild_accepts_patched_state_bytes_source(tmp_path):
    archive = tmp_path / "virtual.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("inside.txt", "ok")
    patched = archive.read_bytes()
    archive.write_bytes(b"\0" * len(patched))
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(archive), format_hint="zip")
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[PatchPlan(operations=[PatchOperation.replace_bytes(offset=0, data=patched)])],
    )
    job = RepairJob(
        source_input={"kind": "file", "path": str(archive), "format_hint": "zip"},
        format="zip",
        archive_state=state,
    )
    rebuilt = tmp_path / "rebuilt.zip"

    scan = rebuild_zip_from_source(source_input_for_job(job), rebuilt)

    assert scan.entries == 1
    with zipfile.ZipFile(rebuilt) as zf:
        assert zf.read("inside.txt") == b"ok"
