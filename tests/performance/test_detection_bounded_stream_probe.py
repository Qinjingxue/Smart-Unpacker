import pytest
import zstandard

from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.modules.format_structure.compression_stream import (
    inspect_compression_stream_structure,
)
from sunpack.detection.pipeline.rules.scoring.compression_stream_identity import (
    CompressionStreamIdentityScoreRule,
)


FULL_STREAM_STRUCTURE_MAX_BYTES = 4 * 1024 * 1024


def test_large_stream_uses_bounded_native_structure_probe(tmp_path):
    path = tmp_path / "large.gz"
    with path.open("wb") as handle:
        handle.write(b"\x1f\x8b\x08\x00" + b"\x00" * 28)
        handle.seek(128 * 1024 * 1024 - 1)
        handle.write(b"\x00")

    result = inspect_compression_stream_structure(str(path))

    assert result["validation_scope"] == "bounded_structure"
    assert result["validation_complete"] is False


@pytest.mark.parametrize(
    ("file_size", "bounded"),
    [
        (FULL_STREAM_STRUCTURE_MAX_BYTES, False),
        (FULL_STREAM_STRUCTURE_MAX_BYTES + 1, True),
    ],
)
def test_zstd_scoring_handles_fields_on_both_sides_of_bounded_probe_threshold(tmp_path, file_size, bounded):
    path = tmp_path / "threshold.zst"
    path.write_bytes(zstandard.ZstdCompressor().compress(b"threshold payload"))
    with path.open("r+b") as handle:
        handle.seek(file_size - 1)
        handle.write(b"\x00")

    result = inspect_compression_stream_structure(str(path))

    assert (result.get("validation_scope") == "bounded_structure") is bounded
    if bounded:
        assert result["frame.sequence"] == "unavailable"
    else:
        assert isinstance(result["frame.sequence"], int)

    bag = FactBag()
    bag.set("file.path", str(path))
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.logical_name", path.name)
    bag.set("compression.stream_structure", result)

    effect = CompressionStreamIdentityScoreRule().evaluate(bag, {})

    assert effect.decision == "score"
    assert effect.score >= 6
