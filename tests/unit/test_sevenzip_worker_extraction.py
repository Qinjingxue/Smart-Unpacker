import subprocess

import pytest

from smart_unpacker.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, ArchiveInputRange
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.scheduler import ExtractionScheduler
from smart_unpacker.support.resources import get_sevenzip_worker_path
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
