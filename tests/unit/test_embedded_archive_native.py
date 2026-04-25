from smart_unpacker.detection.pipeline.processors.modules import embedded_archive


def test_native_carrier_archive_fast_path_is_used(tmp_path, monkeypatch):
    target = tmp_path / "image.png"
    target.write_bytes(b"\x89PNGdataIEND\xaeB`\x82payload")
    calls = []

    def fake_native(path, carrier_ext, archive_magics, file_size, tail_window, prefix_window, full_scan_max, deep_scan):
        calls.append({
            "path": path,
            "carrier_ext": carrier_ext,
            "archive_magics": archive_magics,
            "file_size": file_size,
            "tail_window": tail_window,
            "prefix_window": prefix_window,
            "full_scan_max": full_scan_max,
            "deep_scan": deep_scan,
        })
        return {"detected_ext": ".7z", "offset": 99, "scan_scope": "tail"}

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_CARRIER_ARCHIVE", fake_native)

    result = embedded_archive._find_after_carrier(
        str(target),
        ".png",
        target.stat().st_size,
        {"carrier_scan_tail_window_bytes": 8, "carrier_scan_full_scan_max_bytes": 0},
    )

    assert result == {"detected_ext": ".7z", "offset": 99, "scan_scope": "tail"}
    assert calls
    assert calls[0]["carrier_ext"] == ".png"
    assert calls[0]["tail_window"] == 8


def test_native_carrier_archive_failure_falls_back_to_python(tmp_path, monkeypatch):
    target = tmp_path / "image.png"
    target.write_bytes(b"\x89PNGdataIEND\xaeB`\x82" + b"PK\x03\x04" + b"payload")

    def failing_native(*_args, **_kwargs):
        raise RuntimeError("native scan unavailable")

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_CARRIER_ARCHIVE", failing_native)

    result = embedded_archive._find_after_carrier(
        str(target),
        ".png",
        target.stat().st_size,
        {"carrier_scan_tail_window_bytes": 64},
    )

    assert result["detected_ext"] == ".zip"
    assert result["scan_scope"] == "tail"


def test_native_carrier_tail_fast_path_is_used(tmp_path, monkeypatch):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9payload")
    calls = []

    def fake_native(path, markers, archive_magics, tail_start, file_size, allow_full_scan):
        calls.append({
            "path": path,
            "markers": markers,
            "archive_magics": archive_magics,
            "tail_start": tail_start,
            "file_size": file_size,
            "allow_full_scan": allow_full_scan,
        })
        return {"detected_ext": ".7z", "offset": 99, "scan_scope": "tail"}

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_AFTER_MARKERS", fake_native)

    result = embedded_archive._find_tail_after_markers_layered(
        str(target),
        (b"\xff\xd9",),
        target.stat().st_size,
        {"carrier_scan_tail_window_bytes": 8, "carrier_scan_full_scan_max_bytes": 8},
    )

    assert result == {"detected_ext": ".7z", "offset": 99, "scan_scope": "tail"}
    assert calls
    assert calls[0]["allow_full_scan"] is False


def test_carrier_full_scan_is_disabled_by_default(tmp_path, monkeypatch):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9payload")
    calls = []

    def fake_native(path, markers, archive_magics, tail_start, file_size, allow_full_scan):
        calls.append(allow_full_scan)
        return None

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_AFTER_MARKERS", fake_native)

    result = embedded_archive._find_tail_after_markers_layered(
        str(target),
        (b"\xff\xd9",),
        target.stat().st_size,
        {"carrier_scan_tail_window_bytes": 64},
    )

    assert result is None
    assert calls == [False]


def test_python_carrier_tail_marker_without_magic_skips_full_scan(tmp_path, monkeypatch):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image" + b"PK\x03\x04" + b"\xff\xd9payload")

    def unexpected_full_scan(*_args, **_kwargs):
        raise AssertionError("tail EOF without following archive magic should stop carrier scanning")

    monkeypatch.setenv("SMART_UNPACKER_DISABLE_NATIVE", "1")
    monkeypatch.setattr(embedded_archive, "_stream_find_tail_after_markers", unexpected_full_scan)

    result = embedded_archive._find_tail_after_markers_layered(
        str(target),
        (b"\xff\xd9",),
        target.stat().st_size,
        {
            "carrier_scan_tail_window_bytes": 64,
            "carrier_scan_full_scan_max_bytes": 1024,
        },
    )

    assert result is None


def test_python_carrier_tail_uses_earlier_marker_when_payload_contains_marker(tmp_path, monkeypatch):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9" + b"PK\x03\x04payload\xff\xd9tail")

    def unexpected_full_scan(*_args, **_kwargs):
        raise AssertionError("tail scan should find the archive after the earlier carrier EOF")

    monkeypatch.setenv("SMART_UNPACKER_DISABLE_NATIVE", "1")
    monkeypatch.setattr(embedded_archive, "_stream_find_tail_after_markers", unexpected_full_scan)

    result = embedded_archive._find_tail_after_markers_layered(
        str(target),
        (b"\xff\xd9",),
        target.stat().st_size,
        {
            "carrier_scan_tail_window_bytes": 64,
            "carrier_scan_full_scan_max_bytes": 1024,
        },
    )

    assert result == {"detected_ext": ".zip", "offset": 9, "scan_scope": "tail"}


def test_carrier_prefix_scan_detects_early_rar_payload_by_default(tmp_path, monkeypatch):
    target = tmp_path / "image.jpg"
    target.write_bytes(
        b"\xff\xd8image-padding"
        + (b"x" * 1024)
        + b"\xff\xd9"
        + b"Rar!\x1a\x07\x01\x00"
        + b"encrypted-looking-payload"
        + b"\xff\xd9"
        + (b"tail" * 1024)
    )

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)

    result = embedded_archive._find_tail_after_markers_layered(
        str(target),
        (b"\xff\xd9",),
        target.stat().st_size,
        {
            "carrier_scan_tail_window_bytes": 128,
            "carrier_scan_prefix_window_bytes": 2048,
            "carrier_scan_full_scan_max_bytes": 0,
        },
    )

    expected_offset = target.read_bytes().find(b"Rar!\x1a\x07\x01\x00")
    assert result == {"detected_ext": ".rar", "offset": expected_offset, "scan_scope": "prefix"}


def test_native_carrier_tail_failure_falls_back_to_python(tmp_path, monkeypatch):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9" + b"7z\xbc\xaf\x27\x1c" + b"payload")

    def failing_native(*_args, **_kwargs):
        raise RuntimeError("native scan unavailable")

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_AFTER_MARKERS", failing_native)

    result = embedded_archive._find_tail_after_markers_layered(
        str(target),
        (b"\xff\xd9",),
        target.stat().st_size,
        {"carrier_scan_tail_window_bytes": 64, "carrier_scan_full_scan_max_bytes": 64},
    )

    assert result["detected_ext"] == ".7z"
    assert result["scan_scope"] == "tail"


def test_native_carrier_tail_no_hit_skips_python_fallback(tmp_path, monkeypatch):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9payload")

    def no_hit_native(*_args, **_kwargs):
        return None

    def unexpected_python_fallback(*_args, **_kwargs):
        raise AssertionError("native no-hit should be trusted")

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_AFTER_MARKERS", no_hit_native)
    monkeypatch.setattr(embedded_archive, "_find_tail_after_markers_in_range", unexpected_python_fallback)

    result = embedded_archive._find_tail_after_markers_layered(
        str(target),
        (b"\xff\xd9",),
        target.stat().st_size,
        {"carrier_scan_tail_window_bytes": 64, "carrier_scan_full_scan_max_bytes": 64},
    )

    assert result is None


def test_native_carrier_tail_can_be_disabled(tmp_path, monkeypatch):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9" + b"7z\xbc\xaf\x27\x1c" + b"payload")

    def unexpected_native(*_args, **_kwargs):
        raise AssertionError("native scan should be disabled")

    monkeypatch.setenv("SMART_UNPACKER_DISABLE_NATIVE", "1")
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_AFTER_MARKERS", unexpected_native)

    result = embedded_archive._find_tail_after_markers_layered(
        str(target),
        (b"\xff\xd9",),
        target.stat().st_size,
        {"carrier_scan_tail_window_bytes": 64, "carrier_scan_full_scan_max_bytes": 64},
    )

    assert result["detected_ext"] == ".7z"
    assert result["scan_scope"] == "tail"


def test_native_loose_magic_scan_fast_path_is_used(tmp_path, monkeypatch):
    target = tmp_path / "payload.bin"
    target.write_bytes(b"prefix")
    calls = []

    def fake_native(path, archive_magics, min_offset, max_hits, end_offset):
        calls.append({
            "path": path,
            "archive_magics": archive_magics,
            "min_offset": min_offset,
            "max_hits": max_hits,
            "end_offset": end_offset,
        })
        return [{"detected_ext": ".zip", "offset": 123}]

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_MAGICS_ANYWHERE", fake_native)

    result = embedded_archive._stream_find_tail_magics_anywhere(
        str(target),
        min_offset=4,
        max_hits=2,
        end_offset=64,
    )

    assert result == [{"detected_ext": ".zip", "offset": 123}]
    assert calls
    assert calls[0]["min_offset"] == 4
    assert calls[0]["max_hits"] == 2
    assert calls[0]["end_offset"] == 64


def test_native_loose_magic_scan_no_hit_skips_python_fallback(tmp_path, monkeypatch):
    target = tmp_path / "payload.bin"
    target.write_bytes(b"prefix")

    def no_hit_native(*_args, **_kwargs):
        return []

    def unexpected_python_match(*_args, **_kwargs):
        raise AssertionError("native no-hit should be trusted")

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_MAGICS_ANYWHERE", no_hit_native)
    monkeypatch.setattr(embedded_archive, "_match_tail_magic", unexpected_python_match)

    result = embedded_archive._stream_find_tail_magics_anywhere(
        str(target),
        min_offset=0,
        max_hits=2,
    )

    assert result == []


def test_native_loose_magic_scan_failure_falls_back_to_python(tmp_path, monkeypatch):
    target = tmp_path / "payload.bin"
    target.write_bytes(b"prefix" + b"7z\xbc\xaf\x27\x1c" + b"tail")

    def failing_native(*_args, **_kwargs):
        raise RuntimeError("native scan unavailable")

    monkeypatch.delenv("SMART_UNPACKER_DISABLE_NATIVE", raising=False)
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_MAGICS_ANYWHERE", failing_native)

    result = embedded_archive._stream_find_tail_magics_anywhere(
        str(target),
        min_offset=0,
        max_hits=2,
    )

    assert result == [{"detected_ext": ".7z", "offset": 6}]


def test_native_loose_magic_scan_can_be_disabled(tmp_path, monkeypatch):
    target = tmp_path / "payload.bin"
    target.write_bytes(b"prefix" + b"PK\x03\x04" + b"tail")

    def unexpected_native(*_args, **_kwargs):
        raise AssertionError("native scan should be disabled")

    monkeypatch.setenv("SMART_UNPACKER_DISABLE_NATIVE", "1")
    monkeypatch.setattr(embedded_archive, "_NATIVE_SCAN_MAGICS_ANYWHERE", unexpected_native)

    result = embedded_archive._stream_find_tail_magics_anywhere(
        str(target),
        min_offset=0,
        max_hits=2,
    )

    assert result == [{"detected_ext": ".zip", "offset": 6}]
