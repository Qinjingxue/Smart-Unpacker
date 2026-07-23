from sunpack.detection.pipeline.processors.modules.format_structure.compression_stream import (
    inspect_compression_stream_structure,
)


def test_large_stream_uses_bounded_native_structure_probe(tmp_path):
    path = tmp_path / "large.gz"
    with path.open("wb") as handle:
        handle.write(b"\x1f\x8b\x08\x00" + b"\x00" * 28)
        handle.seek(128 * 1024 * 1024 - 1)
        handle.write(b"\x00")

    result = inspect_compression_stream_structure(str(path))

    assert result["validation_scope"] == "bounded_structure"
    assert result["validation_complete"] is False
