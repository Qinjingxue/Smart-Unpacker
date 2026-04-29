import io
import zipfile

from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.result import ExtractionResult
from sunpack.verification import VerificationScheduler


def test_archive_crc_reads_patched_state_not_raw_archive_path(tmp_path):
    zip_bytes = _zip_bytes({"good.txt": b"hello"})
    archive = tmp_path / "virtual.zip"
    archive.write_bytes(b"\0" * len(zip_bytes))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "good.txt").write_text("hello", encoding="utf-8")
    task = _patched_task(archive, zip_bytes)
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])

    verification = _scheduler([{"name": "archive_test_crc"}]).verify(task, result)

    assert verification.decision_hint == "accept"
    assert verification.assessment_status == "complete"
    assert verification.archive_coverage.expected_files == 1
    assert verification.archive_coverage.complete_files == 1
    assert verification.steps[0].status == "passed"


def test_expected_name_and_manifest_size_are_derived_from_patched_state(tmp_path):
    zip_bytes = _zip_bytes({"present.txt": b"ok", "missing.bin": b"123456"})
    archive = tmp_path / "virtual.zip"
    archive.write_bytes(b"\0" * len(zip_bytes))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "present.txt").write_text("ok", encoding="utf-8")
    task = _patched_task(archive, zip_bytes)
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])

    verification = _scheduler([
        {"name": "expected_name_presence"},
        {"name": "manifest_size_match", "file_count_abs_tolerance": 0, "size_abs_tolerance_bytes": 0},
    ]).verify(task, result)

    assert verification.decision_hint == "repair"
    assert verification.archive_coverage.expected_files == 2
    assert verification.archive_coverage.missing_files == 1
    assert {issue.code for issue in verification.issues} >= {
        "fail.expected_names_missing",
        "fail.manifest_file_count_under",
        "fail.manifest_size_under",
    }


def test_archive_crc_keeps_file_coverage_when_source_payload_is_damaged(tmp_path):
    zip_bytes = _zip_bytes({"good.txt": b"hello", "bad.bin": b"payload"})
    archive = tmp_path / "payload-damaged.zip"
    archive.write_bytes(zip_bytes.replace(b"payload", b"PAYLOAD", 1))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "good.txt").write_text("hello", encoding="utf-8")
    (out_dir / "bad.bin").write_bytes(b"payload")
    task = ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        key=archive.name,
        main_path=str(archive),
        all_parts=[str(archive)],
        detected_ext="zip",
    )
    result = ExtractionResult(success=True, archive=str(archive), out_dir=str(out_dir), all_parts=[str(archive)])

    verification = _scheduler([{"name": "archive_test_crc"}]).verify(task, result)

    assert verification.source_integrity == "payload_damaged"
    assert verification.archive_coverage.expected_files == 2
    assert verification.archive_coverage.complete_files == 2
    assert not [issue for issue in verification.issues if issue.code == "fail.archive_crc_test_failed"]


def _patched_task(archive, patched_bytes: bytes) -> ArchiveTask:
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(archive), format_hint="zip")
    state = ArchiveState.from_archive_input(
        descriptor,
        patches=[PatchPlan(operations=[PatchOperation.replace_bytes(offset=0, data=patched_bytes)])],
    )
    task = ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        key=archive.name,
        main_path=str(archive),
        all_parts=[str(archive)],
        detected_ext="zip",
    )
    task.set_archive_state(state)
    return task


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _scheduler(methods):
    return VerificationScheduler({
        "verification": {
            "enabled": True,
            "methods": methods,
        }
    })
