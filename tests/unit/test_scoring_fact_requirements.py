from smart_unpacker.detection.pipeline.facts.provider import FactProvider
from smart_unpacker.contracts.detection import FactBag
from smart_unpacker.detection import DetectionScheduler
from tests.helpers.detection_config import with_detection_pipeline


def _config(scoring_rules):
    return with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 5, "maybe_archive_threshold": 3},
    }, scoring=scoring_rules)


def test_archive_identity_checks_magic_but_embedded_analysis_stays_empty_for_unmatched_extension(tmp_path, monkeypatch):
    target = tmp_path / "notes.txt"
    target.write_bytes(b"plain text")
    bag = FactBag()

    decision = DetectionScheduler(_config([
        {"name": "archive_identity", "enabled": True, "carrier_exts": [".jpg"], "ambiguous_resource_exts": [".bin"]},
    ])).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is False
    assert bag.has("file.magic_bytes")
    assert bag.get("embedded_archive.analysis").get("found") is False


def test_scoring_fact_requirement_collects_embedded_archive_for_matched_extension(tmp_path):
    target = tmp_path / "image.jpg"
    target.write_bytes(b"\xff\xd8image\xff\xd9" + b"7z\xbc\xaf\x27\x1c" + (b"payload" * 1024))
    bag = FactBag()

    decision = DetectionScheduler(_config([
        {"name": "archive_identity", "enabled": True, "carrier_exts": [".jpg"], "ambiguous_resource_exts": []},
    ])).evaluate(bag, FactProvider(str(target)))

    assert decision.should_extract is True
    assert bag.has("embedded_archive.analysis")


def test_empty_scoring_fact_requirements_keep_required_facts_unconditional(tmp_path, monkeypatch):
    target = tmp_path / "archive.zip"
    target.write_bytes(b"PK\x03\x04")
    counts = {"file.magic_bytes": 0}
    original_fill_fact = FactProvider.fill_fact

    def counting_fill_fact(self, fact_bag, fact_name):
        if fact_name in counts:
            counts[fact_name] += 1
        return original_fill_fact(self, fact_bag, fact_name)

    monkeypatch.setattr(FactProvider, "fill_fact", counting_fill_fact)

    decision = DetectionScheduler(_config([
        {"name": "archive_identity", "enabled": True},
    ])).evaluate(FactBag(), FactProvider(str(target)))

    assert decision.should_extract is True
    assert counts["file.magic_bytes"] == 1


def test_archive_identity_ignores_exe_loose_scan_after_collecting_inputs(tmp_path, monkeypatch):
    target = tmp_path / "setup.exe"
    target.write_bytes(b"MZ" + b"x" * 256 + b"7z\xbc\xaf\x27\x1c" + b"x" * 64)
    collected = []
    original_fill_fact = FactProvider.fill_fact

    def counting_fill_fact(self, fact_bag, fact_name):
        if fact_name in {"file.magic_bytes", "embedded_archive.analysis", "archive.identity"}:
            collected.append(fact_name)
        return original_fill_fact(self, fact_bag, fact_name)

    monkeypatch.setattr(FactProvider, "fill_fact", counting_fill_fact)

    bag = FactBag()
    decision = DetectionScheduler(_config([
        {
            "name": "archive_identity",
            "enabled": True,
            "identity_scan_exts": [".zip", ".7z", ".rar"],
            "carrier_exts": [],
            "ambiguous_resource_exts": [".exe"],
            "loose_scan_min_tail_bytes": 1,
        },
    ])).evaluate(bag, FactProvider(str(target)))

    assert decision.decision == "not_archive"
    assert set(collected) == {"file.magic_bytes"}
    assert bag.has("file.magic_bytes")
    assert bag.has("embedded_archive.analysis")
    assert bag.get("embedded_archive.analysis").get("found") is True
    assert bag.get("archive.identity").get("is_archive_like") is False
