import zipfile

from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection import DetectionScheduler
from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.detection.pipeline.processors.modules.embedded_payload.embedded_archive import analyze_embedded_archive
from tests.helpers.detection_config import with_detection_pipeline


def _payload_config():
    return {
        "carrier_exts": [".jpg", ".pdf", ".gif", ".webp"],
        "ambiguous_resource_exts": [".bin"],
        "loose_scan_min_tail_bytes": 1,
    }


def _payload_rule_config():
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[
        {
            "name": "embedded_payload_identity",
            "enabled": True,
            **_payload_config(),
        }
    ])


def test_embedded_payload_identity_rule_sets_detected_facts(tmp_path):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9" + b"Rar!\x1a\x07\x00" + b"x" * 64)
    bag = FactBag()

    decision = DetectionScheduler(_payload_rule_config()).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert decision.matched_rules == ["embedded_payload_identity"]
    assert bag.get("file.detected_ext") == ".rar"
    assert bag.get("file.probe_offset") > 0
    assert bag.get("file.embedded_archive_found") is True


def test_embedded_payload_identity_detects_gif_carrier_after_real_trailer(tmp_path):
    target = tmp_path / "image.gif"
    target.write_bytes(b"GIF89a\x01\x00\x01\x00\x00\x00\x00;" + b"7z\xbc\xaf\x27\x1c" + b"x" * 64)

    embedded = analyze_embedded_archive(str(target), target.stat().st_size, _payload_config())

    assert embedded["scan_scope"] == "after_gif_trailer"
    assert embedded["detected_ext"] == ".7z"


def test_embedded_payload_identity_ignores_exe_loose_scan_sfx_semantics(tmp_path):
    target = tmp_path / "setup.exe"
    target.write_bytes(b"MZ" + b"x" * 256 + b"7z\xbc\xaf\x27\x1c" + b"x" * 64)
    bag = FactBag()
    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=[
        {
            "name": "embedded_payload_identity",
            "enabled": True,
            **_payload_config(),
            "ambiguous_resource_exts": [".exe"],
        },
    ])

    decision = DetectionScheduler(config).evaluate(bag, FactProvider(str(target)))

    assert bag.get("embedded_archive.analysis").get("found") is True
    assert bag.get("embedded_archive.analysis").get("mode") == "loose_scan"
    assert decision.should_extract is False
    assert decision.matched_rules == []


def test_zip_magic_start_is_scored_by_zip_structure_identity(tmp_path):
    target = tmp_path / "payload.bin"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("x", "payload")
    bag = FactBag()
    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 6, "maybe_archive_threshold": 3},
    }, scoring=[
        {"name": "zip_structure_identity", "enabled": True},
    ])

    decision = DetectionScheduler(config).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert decision.matched_rules == ["zip_structure_identity"]
    assert bag.get("file.detected_ext") == ".zip"
