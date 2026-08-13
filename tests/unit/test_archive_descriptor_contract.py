from pathlib import Path

from sunpack.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, ArchiveInputRange
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.task_scan import direct_file_task
from sunpack.coordinator.target_groups import relation_group_to_fact_bag
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.relations import RelationsScheduler
from sunpack.relations.internal.group_builder import RelationsGroupBuilder
from sunpack.repair.job import RepairJob


def test_archive_task_exposes_default_descriptor_from_task_paths(tmp_path):
    first = tmp_path / "sample.7z.001"
    second = tmp_path / "sample.7z.002"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    task = direct_file_task(str(first), all_parts=[str(first), str(second)])

    descriptor = task.archive_input()

    assert descriptor.open_mode == "native_volumes"
    assert descriptor.format_hint == "7z"
    assert descriptor.part_paths() == [str(first), str(second)]
    assert [part.canonical_name for part in descriptor.parts] == ["sample.7z.001", "sample.7z.002"]
    assert task.archive_descriptor().relation.is_split is True


def test_obfuscated_rar_names_use_part_number_fallback(tmp_path):
    first = tmp_path / "488.part1.rar123"
    second = tmp_path / "488.part2.rar123"
    first.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"x" * 64)
    second.write_bytes(b"x" * 72)

    groups = RelationsScheduler().build_candidate_groups(DirectoryScanner(str(tmp_path)).scan())
    group = next(group for group in groups if group.kind == "split_archive")
    assert {Path(path).name for path in group.all_paths} == {first.name, second.name}
    assert [volume.number for volume in group.split_volumes] == [1, 2]


def test_plain_name_sfx_does_not_attach_raw_camouflaged_volumes(tmp_path):
    stub = tmp_path / "bundle.exe"
    first = tmp_path / "bundle.7z.001.camouflage"
    second = tmp_path / "bundle.7z.002.camouflage"
    for path in (stub, first, second):
        path.write_bytes(b"x" * 64)

    entries, complete, _, _ = RelationsGroupBuilder().build_split_volume_entries(
        str(stub), [str(stub), str(first), str(second)]
    )
    assert entries == []
    assert complete is None


def test_archive_task_from_detection_fact_bag_carries_empty_archive_state(tmp_path):
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"zip")
    bag = FactBag()
    bag.set("candidate.entry_path", str(archive))
    bag.set("candidate.member_paths", [str(archive)])
    bag.set("candidate.logical_name", "sample")
    bag.set("file.detected_ext", "zip")

    task = ArchiveTask.from_fact_bag(bag, score=10)

    state = task.fact_bag.get("archive.state")
    assert state["kind"] == "archive_state"
    assert state["source"]["entry_path"] == str(archive)
    assert state["source"]["format_hint"] == "zip"
    assert state["patches"] == []


def test_archive_task_set_descriptor_updates_archive_state(tmp_path):
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
    assert task.archive_state().source.entry_path == str(archive)
    assert task.archive_state().source.part_paths() == [str(archive)]
    assert task.archive_input().to_source_input() == {
        "kind": "file_range",
        "path": str(archive),
        "start": 4,
        "format_hint": "zip",
    }
    assert task.fact_bag.get("archive.state")["source"]["open_mode"] == "file_range"
    assert task.fact_bag.get("archive.patch_stack") == []


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
    assert task.archive_state().source.entry_path == str(new)
    assert task.fact_bag.get("archive.state")["source"]["entry_path"] == str(new)


def test_archive_state_round_trips_descriptor_and_patch_stack(tmp_path):
    archive = tmp_path / "bad.zip"
    archive.write_bytes(b"zip")
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(archive), format_hint="zip", logical_name="bad")
    patch = PatchPlan(
        operations=[PatchOperation(op="replace_range", offset=12, size=2, data_b64="AAA=")],
        provenance={"module": "zip.eocd"},
        confidence=0.9,
    )

    state = ArchiveState.from_archive_input(descriptor, patches=[patch])
    restored = ArchiveState.from_dict(state.to_dict(), archive_path=str(archive), part_paths=[str(archive)])

    assert restored.source.entry_path == str(archive)
    assert restored.to_archive_input_descriptor().format_hint == "zip"
    assert restored.patches[0].operations[0].offset == 12
    assert restored.effective_patch_digest() == state.effective_patch_digest()


def test_repair_job_archive_input_prefers_typed_descriptor(tmp_path):
    source = tmp_path / "fixed.zip"
    source.write_bytes(b"zip")
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(source), format_hint="zip")
    job = RepairJob(
        source_input={"kind": "file", "path": "unused.bin", "format_hint": "rar"},
        format="rar",
        source_descriptor=descriptor,
    )

    assert job.archive_input().entry_path == str(source)
    assert job.archive_input().format_hint == "zip"
