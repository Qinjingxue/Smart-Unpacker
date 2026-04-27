from smart_unpacker.repair.pipeline.modules import _common


def test_load_source_bytes_reads_file_range(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"0123456789")

    data = _common.load_source_bytes({"kind": "file_range", "path": str(source), "start": 2, "end": 7})

    assert data == b"23456"


def test_load_source_bytes_concatenates_ranges(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"abcdefghij")

    data = _common.load_source_bytes({
        "kind": "concat_ranges",
        "ranges": [
            {"path": str(source), "start": 0, "end": 3},
            {"path": str(source), "start": 7},
        ],
    })

    assert data == b"abchij"


def test_write_candidate_uses_same_api(tmp_path):
    path = _common.write_candidate(b"candidate", str(tmp_path / "workspace"), "out.bin")

    assert open(path, "rb").read() == b"candidate"


def test_copy_range_to_file_streaming_helper(tmp_path):
    source = tmp_path / "source.bin"
    output = tmp_path / "output.bin"
    source.write_bytes(b"0123456789")

    path = _common.copy_range_to_file(str(source), 3, 8, str(output))

    assert path == str(output)
    assert output.read_bytes() == b"34567"


def test_concat_ranges_to_file_streaming_helper(tmp_path):
    source = tmp_path / "source.bin"
    output = tmp_path / "output.bin"
    source.write_bytes(b"abcdefghij")

    path = _common.concat_ranges_to_file(
        [
            {"path": str(source), "start": 1, "end": 4},
            {"path": str(source), "start": 8},
        ],
        str(output),
    )

    assert path == str(output)
    assert output.read_bytes() == b"bcdij"


def test_patch_file_streaming_helper(tmp_path):
    source = tmp_path / "source.bin"
    output = tmp_path / "output.bin"
    source.write_bytes(b"abcdef")

    path = _common.patch_file(str(source), [{"offset": 2, "data": b"ZZ"}], str(output))

    assert path == str(output)
    assert output.read_bytes() == b"abZZef"
