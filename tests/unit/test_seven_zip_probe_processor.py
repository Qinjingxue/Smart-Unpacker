from sunpack.contracts.detection import FactBag
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.modules.confirmation import seven_zip_probe
from sunpack.support.sevenzip_bridge import NativeArchiveProbe, STATUS_OK


def _probe_result():
    return NativeArchiveProbe(
        status=STATUS_OK,
        is_archive=True,
        is_encrypted=True,
        is_broken=False,
        checksum_error=False,
        offset=0,
        item_count=0,
        archive_type="rar",
        message="wrong password",
    )


def test_probe_reuses_known_embedded_offset_and_format(tmp_path, monkeypatch):
    carrier = tmp_path / "carrier.jpg"
    carrier.write_bytes(b"jpeg-prefix-rar")
    bag = FactBag()
    bag.set("file.path", str(carrier))
    bag.set("file.probe_offset", 11)
    bag.set("file.detected_ext", ".rar")
    calls = []

    def fake_probe(path, part_paths=None, archive_input=None):
        calls.append((path, part_paths, archive_input))
        return _probe_result()

    monkeypatch.setattr(seven_zip_probe, "cached_probe_archive", fake_probe)
    context = FactProcessorContext(bag, "7z.probe", {}, {})

    result = seven_zip_probe.process_7z_probe(context)

    assert result["is_archive"] is True
    assert result["offset"] == 11
    assert calls == [(str(carrier), [str(carrier)], {
        "kind": "archive_input",
        "entry_path": str(carrier),
        "open_mode": "file_range",
        "format_hint": "rar",
        "parts": [{"path": str(carrier), "role": "main", "start": 11}],
        "segment": {"start": 11, "source": "detection"},
    })]


def test_probe_keeps_whole_file_path_without_known_offset(tmp_path, monkeypatch):
    archive = tmp_path / "sample.rar"
    archive.write_bytes(b"rar")
    bag = FactBag()
    bag.set("file.path", str(archive))
    calls = []

    def fake_probe(path, part_paths=None, archive_input=None):
        calls.append(archive_input)
        return _probe_result()

    monkeypatch.setattr(seven_zip_probe, "cached_probe_archive", fake_probe)
    context = FactProcessorContext(bag, "7z.probe", {}, {})

    seven_zip_probe.process_7z_probe(context)

    assert calls == [None]
