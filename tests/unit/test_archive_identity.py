import zipfile

from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.detection.pipeline.processors.modules.embedded_archive import analyze_embedded_archive
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection.pipeline.processors.modules.archive_identity import (
    analyze_archive_magic_start,
    build_archive_identity,
)
from smart_unpacker.detection import DetectionScheduler
from tests.helpers.detection_config import with_detection_pipeline


def _identity_config():
    return {
        "identity_scan_exts": [".7z", ".zip", ".rar", ".gz", ".bz2", ".xz", ".001"],
        "carrier_exts": [".jpg", ".pdf", ".gif", ".webp"],
        "ambiguous_resource_exts": [".bin", ".exe"],
        "loose_scan_min_tail_bytes": 1,
    }


def _rule_config():
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[
        {
            "name": "archive_identity",
            "enabled": True,
            **_identity_config(),
        }
    ])


def test_archive_identity_detects_magic_start_7z(tmp_path):
    target = tmp_path / "payload.dat"
    target.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * 128)

    magic = analyze_archive_magic_start(str(target), target.read_bytes()[:16])
    identity = build_archive_identity(str(target), magic_bytes=target.read_bytes()[:16])

    assert identity["is_archive_like"] is True
    assert identity["format"] == "7z"
    assert identity["detected_ext"] == ".7z"
    assert identity["offset"] == 0
    assert identity["mode"] == "magic_start"
    assert identity["confidence"] == "strong"


def test_archive_identity_detects_rar_and_zip_magic(tmp_path):
    rar = tmp_path / "payload.one"
    zip_path = tmp_path / "payload.two"
    rar.write_bytes(b"Rar!\x1a\x07\x01\x00" + b"x" * 128)
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("x", "payload")

    rar_identity = build_archive_identity(str(rar), magic_bytes=rar.read_bytes()[:16])
    zip_identity = build_archive_identity(str(zip_path), magic_bytes=zip_path.read_bytes()[:16])

    assert rar_identity["format"] == "rar"
    assert rar_identity["detected_ext"] == ".rar"
    assert zip_identity["format"] == "zip"
    assert zip_identity["detected_ext"] == ".zip"
    assert zip_identity["zip_local_header"]["plausible"] is True


def test_archive_identity_detects_carrier_tail(tmp_path):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9" + b"7z\xbc\xaf\x27\x1c" + b"x" * 64)

    embedded = analyze_embedded_archive(str(target), target.stat().st_size, _identity_config())
    identity = build_archive_identity(str(target), embedded_analysis=embedded)

    assert identity["format"] == "7z"
    assert identity["mode"] == "carrier_tail"
    assert identity["confidence"] == "strong"


def test_archive_identity_detects_gif_carrier_after_real_trailer(tmp_path):
    target = tmp_path / "image.gif"
    target.write_bytes(b"GIF89a\x01\x00\x01\x00\x00\x00\x00;" + b"7z\xbc\xaf\x27\x1c" + b"x" * 64)

    embedded = analyze_embedded_archive(str(target), target.stat().st_size, _identity_config())
    identity = build_archive_identity(str(target), embedded_analysis=embedded)

    assert embedded["scan_scope"] == "after_gif_trailer"
    assert identity["format"] == "7z"
    assert identity["mode"] == "carrier_tail"


def test_archive_identity_detects_sfx_hint_for_exe_loose_scan(tmp_path):
    target = tmp_path / "setup.exe"
    target.write_bytes(b"MZ" + b"x" * 256 + b"7z\xbc\xaf\x27\x1c" + b"x" * 64)

    embedded = analyze_embedded_archive(str(target), target.stat().st_size, _identity_config())
    identity = build_archive_identity(str(target), embedded_analysis=embedded)

    assert identity["format"] == "7z"
    assert identity["mode"] == "sfx_hint"
    assert identity["confidence"] == "medium"
    assert identity["requires_confirmation"] is True


def test_archive_identity_rule_sets_detected_facts(tmp_path):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9" + b"Rar!\x1a\x07\x00" + b"x" * 64)
    bag = FactBag()

    decision = DetectionScheduler(_rule_config()).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert bag.get("file.detected_ext") == ".rar"
    assert bag.get("file.probe_offset") > 0
    assert bag.get("file.embedded_archive_found") is True


def test_archive_identity_rule_detects_magic_start_on_ambiguous_extension(tmp_path):
    target = tmp_path / "payload.bin"
    target.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * 128)
    bag = FactBag()
    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[
        {"name": "archive_identity", "enabled": True, **_identity_config()},
    ])

    decision = DetectionScheduler(config).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert bag.get("file.detected_ext") == ".7z"
    assert bag.get("archive.identity").get("mode") == "magic_start"
