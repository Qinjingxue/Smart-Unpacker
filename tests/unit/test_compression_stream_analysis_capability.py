import bz2
import gzip
import lzma
import random

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
from sunpack.detection.pipeline.rules.precheck.compression_stream_accept import (
    CompressionStreamAcceptRule,
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
        assert raw["structure_status"] == "complete"
        assert raw["structure_validation_complete"] is True
        assert raw["boundary_exact"] is True
        assert raw["integrity_status"] == "verified"
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
    assert raw["structure_status"] == "incomplete"
    assert raw["structure_validation_complete"] is False
    assert raw["boundary_exact"] is False
    evidence = GzipAnalysisModule().analyze(view, {"embedded_candidates": []}, {})
    assert evidence.status == "damaged"
    assert "structure_validation_incomplete" in evidence.segments[0].damage_flags


def test_compression_detection_projects_public_analysis_observation(tmp_path):
    path = tmp_path / "payload.gz"
    path.write_bytes(gzip.compress(b"payload" * 100))
    facts = FactBag()
    facts.set("file.path", str(path))
    context = FactProcessorContext(facts, "compression.stream_structure", {}, {}, None)

    raw = process_compression_stream_structure(context)

    assert raw["format"] == "gzip"
    assert raw["structure_validation_complete"] is True
    assert raw["boundary_exact"] is True
    assert raw["confidence"] == "strong"
    assert raw["archive.trailing_data"] == 0


def test_public_zstd_probe_preserves_complete_structure_across_old_threshold(tmp_path):
    threshold = 4 * 1024 * 1024
    for file_size in (threshold, threshold + 1):
        path = tmp_path / f"threshold-{file_size}.zst"
        path.write_bytes(zstandard.ZstdCompressor().compress(b"threshold payload"))
        with path.open("r+b") as handle:
            handle.seek(file_size - 1)
            handle.write(b"\x00")

        raw = ArchiveAnalyzer().probe_compression_stream(str(path)).to_raw_dict()

        assert raw["validation_scope"] == "complete_structure"
        assert raw["structure_status"] == "complete"
        assert raw["structure_validation_complete"] is True
        assert raw["boundary_exact"] is True
        assert raw["integrity_status"] == "not_present"
        assert raw["archive.trailing_data"] > 0


def test_large_real_streams_have_exact_structure_and_precheck_accepts(tmp_path):
    payload = random.Random(20260822).randbytes(5 * 1024 * 1024)
    for fmt, data in _compressed_samples(payload).items():
        assert len(data) > 4 * 1024 * 1024
        path = tmp_path / fmt
        path.write_bytes(data)

        raw = ArchiveAnalyzer().probe_compression_stream(str(path)).to_raw_dict()

        assert raw["validation_scope"] == "complete_structure"
        assert raw["structure_status"] == "complete"
        assert raw["structure_validation_complete"] is True
        assert raw["boundary_exact"] is True
        assert raw["segment_end"] == len(data)
        assert raw["archive.trailing_data"] == 0
        assert raw["integrity_status"] == "deferred"
        assert raw["integrity_validation_complete"] is False

        facts = FactBag()
        facts.set("compression.stream_structure", raw)
        effect = CompressionStreamAcceptRule().evaluate(facts, {})
        assert effect.decision == "accept"
