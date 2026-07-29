import bz2
import gzip
import lzma

import zstandard

from sunpack.analysis import ArchiveAnalyzer, CompressionStreamProbeOptions, PatchedAnalysisSource
from sunpack.analysis.structure_pipeline.modules.compression_streams import GzipAnalysisModule
from sunpack.analysis.view import PatchedBinaryView
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchOperation, PatchPlan
from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.modules.format_structure.compression_stream import (
    process_compression_stream_structure,
)


def _compressed_samples(payload: bytes):
    return {
        "gzip": gzip.compress(payload),
        "bzip2": bz2.compress(payload),
        "xz": lzma.compress(payload, format=lzma.FORMAT_XZ),
        "zstd": zstandard.ZstdCompressor(write_checksum=True).compress(payload),
    }


def test_public_compression_capability_preserves_full_detection_validation(tmp_path):
    for fmt, data in _compressed_samples(b"payload" * 100).items():
        path = tmp_path / fmt
        path.write_bytes(data)

        raw = ArchiveAnalyzer().probe_compression_stream(str(path)).to_raw_dict()

        assert raw["format"] == fmt
        assert raw["magic_matched"] is True
        assert raw["plausible"] is True
        assert raw["validation_complete"] is True
        assert raw["confidence"] == "strong"
        assert raw["archive.trailing_data"] == 0
        assert raw["boundary_confidence"] == "high"
        assert raw["integrity_confidence"] == "high"


def test_header_only_view_never_claims_full_validation(tmp_path):
    path = tmp_path / "payload.gz"
    path.write_bytes(gzip.compress(b"payload" * 100))
    state = ArchiveState.from_archive_input(
        ArchiveInputDescriptor.from_parts(archive_path=str(path), format_hint="gzip"),
        patches=[PatchPlan(operations=[PatchOperation.replace_bytes(
            offset=0,
            data=b"\x1f",
            expected=b"\x1f",
        )])],
    )
    view = PatchedBinaryView(state)

    raw = ArchiveAnalyzer().probe_compression_stream(
        PatchedAnalysisSource(state),
        CompressionStreamProbeOptions(format="gzip"),
    ).to_raw_dict()

    assert raw["magic_matched"] is True
    assert raw["plausible"] is True
    assert raw["validation_complete"] is False
    evidence = GzipAnalysisModule().analyze(view, {"embedded_candidates": []}, {})
    assert evidence.status == "damaged"
    assert "validation_incomplete" in evidence.segments[0].damage_flags


def test_compression_detection_projects_public_analysis_observation(tmp_path):
    path = tmp_path / "payload.gz"
    path.write_bytes(gzip.compress(b"payload" * 100))
    facts = FactBag()
    facts.set("file.path", str(path))
    context = FactProcessorContext(facts, "compression.stream_structure", {}, {}, None)

    raw = process_compression_stream_structure(context)

    assert raw["format"] == "gzip"
    assert raw["validation_complete"] is True
    assert raw["confidence"] == "strong"
    assert raw["archive.trailing_data"] == 0
