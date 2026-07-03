from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zlib

import pytest
import zstandard

from sunpack.repair.model.diagnosis.atomic_format_graph import DEFINITIONS
from sunpack.repair.model.diagnosis.graph_dispatcher import build_diagnosis_graph_sample_for_format


sunpack_native = pytest.importorskip("sunpack_native")


def _rar5_block(header_type: int, body: bytes = b"\x00") -> bytes:
    header = bytes([header_type, 0]) + body
    size = bytes([len(header)])
    crc = zlib.crc32(size + header).to_bytes(4, "little")
    return crc + size + header


def _sample_results(tmp_path):
    payload = b"semantic native fields\n" * 200
    paths = {
        "gzip": tmp_path / "sample.gz",
        "bzip2": tmp_path / "sample.bz2",
        "xz": tmp_path / "sample.xz",
        "zstd": tmp_path / "sample.zst",
        "tar": tmp_path / "sample.tar",
        "rar": tmp_path / "sample.rar",
    }
    paths["gzip"].write_bytes(gzip.compress(payload))
    paths["bzip2"].write_bytes(bz2.compress(payload))
    paths["xz"].write_bytes(lzma.compress(payload, format=lzma.FORMAT_XZ))
    paths["zstd"].write_bytes(zstandard.ZstdCompressor(write_checksum=True).compress(payload))
    with tarfile.open(paths["tar"], "w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("payload.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    file_body = b"\x00\x00\x00\x00\x00\x01a"
    paths["rar"].write_bytes(
        b"Rar!\x1a\x07\x01\x00"
        + _rar5_block(1)
        + _rar5_block(2, file_body)
        + _rar5_block(3, file_body)
        + _rar5_block(4, b"")
        + _rar5_block(5)
    )
    return {
        "rar": sunpack_native.inspect_rar_structure(str(paths["rar"])),
        "tar": sunpack_native.inspect_tar_header_structure(str(paths["tar"])),
        **{
            fmt: sunpack_native.inspect_compression_stream_structure(str(paths[fmt]))
            for fmt in ("gzip", "bzip2", "xz", "zstd")
        },
    }


def test_native_parsers_emit_every_semantic_graph_field(tmp_path):
    results = _sample_results(tmp_path)

    for fmt, result in results.items():
        expected = {field.path for field in DEFINITIONS[fmt].fields}
        assert set(result["semantic_fields"]) == expected
        assert not result["semantic_missing_fields"]
        assert expected <= set(result)


def test_native_semantic_fields_map_one_to_one_to_theory_nodes(tmp_path):
    results = _sample_results(tmp_path)

    for fmt, result in results.items():
        sample = build_diagnosis_graph_sample_for_format(fmt, {
            "format": fmt,
            "sample_id": f"native-{fmt}",
            "knowledge_payload": {"format": {fmt: {"structure": result}}},
        })
        mapped = {
            edge.target.removeprefix(f"theory:{fmt}:")
            for edge in sample.graph.edges
            if edge.edge_type == "observes_theory"
        }
        assert {field.path for field in DEFINITIONS[fmt].fields} <= mapped


@pytest.mark.parametrize(
    ("fmt", "compress", "suffix"),
    [
        ("gzip", gzip.compress, ".gz"),
        ("bzip2", bz2.compress, ".bz2"),
        ("xz", lambda data: lzma.compress(data, format=lzma.FORMAT_XZ), ".xz"),
        ("zstd", zstandard.ZstdCompressor().compress, ".zst"),
    ],
)
def test_native_stream_parsers_report_trailing_data(tmp_path, fmt, compress, suffix):
    path = tmp_path / f"trailing{suffix}"
    path.write_bytes(compress(b"payload" * 100) + b"JUNK")

    result = sunpack_native.inspect_compression_stream_structure(str(path))

    assert result["archive.trailing_data"] == 4
    assert "trailing_junk" in result["damage_flags"]
    sample = build_diagnosis_graph_sample_for_format(fmt, {
        "format": fmt,
        "sample_id": f"trailing-{fmt}",
        "knowledge_payload": {"format": {fmt: {"structure": result}}},
    })
    assert sample.labels.root_case_labels == ["trailing_junk"]


@pytest.mark.parametrize(
    ("compress", "suffix"),
    [
        (gzip.compress, ".gz"),
        (bz2.compress, ".bz2"),
        (lambda data: lzma.compress(data, format=lzma.FORMAT_XZ), ".xz"),
        (zstandard.ZstdCompressor().compress, ".zst"),
    ],
)
def test_native_stream_structure_decode_is_bounded_for_high_ratio_input(tmp_path, compress, suffix):
    path = tmp_path / f"bounded{suffix}"
    path.write_bytes(compress(b"A" * (10 * 1024 * 1024)))

    result = sunpack_native.inspect_compression_stream_structure(str(path))

    assert result["plausible"] is True
    assert result["validation_complete"] is False
    assert not {"gzip_footer_bad", "bzip2_block_bad", "xz_structural_validation_failed", "zstd_frame_bad"}.intersection(
        result["damage_flags"]
    )
