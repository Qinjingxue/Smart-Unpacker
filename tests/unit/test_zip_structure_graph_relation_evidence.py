from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from repair_training.derive_archives import _write_zip_data_descriptor
from sunpack.detection.pipeline.processors.modules.format_structure.zip_structure_graph import inspect_zip_structure_graph
from sunpack.repair.pipeline.modules.zip._directory import find_eocd, parse_central_directory_entries


def test_zip_structure_graph_flags_relation_points_to_cd_side(tmp_path: Path):
    archive = _basic_zip(tmp_path)
    _mutate_cd_flags(archive, xor_value=0x08)

    graph = inspect_zip_structure_graph(str(archive), identity=("flags", archive.stat().st_size, archive.stat().st_mtime_ns))
    relation = _first_relation(graph, "field_relation_mismatch")

    assert relation["source_field"] == "central_directory.flags"
    assert relation["target_field"] == "local_header.flags"
    assert relation["likely_bad_side"] == "central_directory.flags"
    assert graph["summary"]["central_directory_flags_likely_bad_count"] >= 1


def test_zip_structure_graph_local_header_offset_target_evidence(tmp_path: Path):
    archive = _basic_zip(tmp_path)
    _mutate_cd_local_header_offset(archive, replacement=1)

    graph = inspect_zip_structure_graph(str(archive), identity=("offset", archive.stat().st_size, archive.stat().st_mtime_ns))
    relation = _first_relation(graph, "local_header_offset_target_mismatch")

    assert relation["field"] == "central_directory.local_header_offset"
    assert relation["target_field"] == "local_header.signature"
    assert relation["target_kind"] != "local_header"
    assert graph["summary"]["bad_local_header_target_signature_count"] >= 1


def test_zip_structure_graph_descriptor_crc_relation_evidence(tmp_path: Path):
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.txt").write_text("hello descriptor crc\n", encoding="utf-8")
    archive = tmp_path / "descriptor.zip"
    _write_zip_data_descriptor(source, archive, 6)
    _mutate_descriptor_crc(archive)

    graph = inspect_zip_structure_graph(str(archive), identity=("descriptor", archive.stat().st_size, archive.stat().st_mtime_ns))
    relation = _first_relation(graph, "data_descriptor_crc_mismatch")

    assert relation["field"] == "data_descriptor.crc"
    assert relation["source_field"] == "data_descriptor.crc"
    assert relation["target_field"] == "central_directory.crc"
    assert relation["likely_bad_side"] == "data_descriptor.crc"
    assert relation["payload_matches_cd"] is True
    assert graph["summary"]["descriptor_crc_likely_bad_count"] >= 1


def _basic_zip(tmp_path: Path) -> Path:
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "hello\n")
    return archive


def _entries(path: Path):
    data = path.read_bytes()
    eocd = find_eocd(data)
    assert eocd is not None
    physical_cd = eocd.offset - eocd.cd_size
    entries = parse_central_directory_entries(data, physical_cd, expected_end=physical_cd + eocd.cd_size)
    assert entries
    return data, entries


def _mutate_cd_flags(path: Path, *, xor_value: int) -> None:
    data, entries = _entries(path)
    payload = bytearray(data)
    offset = entries[0].offset + 8
    flags = struct.unpack_from("<H", payload, offset)[0]
    struct.pack_into("<H", payload, offset, flags ^ xor_value)
    path.write_bytes(bytes(payload))


def _mutate_cd_local_header_offset(path: Path, *, replacement: int) -> None:
    data, entries = _entries(path)
    payload = bytearray(data)
    struct.pack_into("<I", payload, entries[0].offset + 42, replacement)
    path.write_bytes(bytes(payload))


def _mutate_descriptor_crc(path: Path) -> None:
    payload = bytearray(path.read_bytes())
    offset = payload.find(b"PK\x07\x08")
    assert offset >= 0
    crc_offset = offset + 4
    current = struct.unpack_from("<I", payload, crc_offset)[0]
    struct.pack_into("<I", payload, crc_offset, current ^ 0xCAFEBABE)
    path.write_bytes(bytes(payload))


def _first_relation(graph: dict, kind: str) -> dict:
    for item in graph.get("relation_violations") or []:
        if item.get("kind") == kind:
            return item
    raise AssertionError(f"missing relation violation {kind}: {graph}")
