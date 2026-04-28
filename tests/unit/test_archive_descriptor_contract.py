from pathlib import Path

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, ArchiveInputRange
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.repair.job import RepairJob


def test_archive_task_exposes_default_descriptor_from_compat_fields(tmp_path):
    first = tmp_path / "sample.7z.001"
    second = tmp_path / "sample.7z.002"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    task = ArchiveTask(
        fact_bag=FactBag(),
        score=10,
        main_path=str(first),
        all_parts=[str(first), str(second)],
        logical_name="sample",
        detected_ext="7z",
    )

    descriptor = task.archive_input()

    assert descriptor.open_mode == "native_volumes"
    assert descriptor.format_hint == "7z"
    assert descriptor.part_paths() == [str(first), str(second)]
    assert task.archive_descriptor().relation.is_split is True


def test_archive_task_set_descriptor_updates_current_compat_facts(tmp_path):
    archive = tmp_path / "carrier.bin"
    archive.write_bytes(b"junkPK")
    task = ArchiveTask(fact_bag=FactBag(), score=10, main_path=str(archive), all_parts=[str(archive)])
    descriptor = ArchiveInputDescriptor(
        entry_path=str(archive),
        open_mode="file_range",
        format_hint="zip",
        parts=[ArchiveInputPart(path=str(archive), range=ArchiveInputRange(str(archive), start=4, end=None))],
    )

    task.set_archive_input(descriptor)

    assert task.fact_bag.get("archive.input")["open_mode"] == "file_range"
    assert task.fact_bag.get("archive.current_entry_path") == str(archive)
    assert task.fact_bag.get("archive.current_member_paths") == [str(archive)]
    assert task.archive_input().to_legacy_source_input() == {
        "kind": "file_range",
        "path": str(archive),
        "start": 4,
        "format_hint": "zip",
    }


def test_archive_task_path_mapping_updates_archive_input(tmp_path):
    old = tmp_path / "old.zip"
    new = tmp_path / "new.zip"
    old.write_bytes(b"old")
    new.write_bytes(b"new")
    task = ArchiveTask(fact_bag=FactBag(), score=10, main_path=str(old), all_parts=[str(old)])
    task.set_archive_input(ArchiveInputDescriptor.from_parts(archive_path=str(old), format_hint="zip"))

    task.apply_path_mapping({str(old): str(new)})

    assert task.main_path == str(new)
    assert task.archive_input().entry_path == str(new)
    assert task.fact_bag.get("archive.current_entry_path") == str(new)


def test_repair_job_archive_input_prefers_typed_descriptor(tmp_path):
    source = tmp_path / "fixed.zip"
    source.write_bytes(b"zip")
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
    job = RepairJob(
        source_input={"kind": "file", "path": "legacy.bin", "format_hint": "rar"},
        format="rar",
        source_descriptor=descriptor,
    )

    assert job.archive_input().entry_path == str(source)
    assert job.archive_input().format_hint == "zip"
