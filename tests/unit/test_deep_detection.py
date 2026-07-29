import gzip

from sunpack.analysis.engine import AnalysisEngine
from sunpack.contracts.detection import FactBag
from sunpack.detection.options import DetectionOptions
from sunpack.detection.scheduler import DetectionScheduler


def test_deep_detection_bypasses_rules_and_preserves_all_stream_segments(tmp_path, monkeypatch):
    first = gzip.compress(b"first payload")
    gap = b"invalid bytes between valid streams"
    second = gzip.compress(b"second payload")
    path = tmp_path / "gzip-invalid-gzip.bin"
    path.write_bytes(first + gap + second)
    second_offset = len(first) + len(gap)

    bag = FactBag()
    bag.set("file.path", str(path))
    bag.set("candidate.entry_path", str(path))
    scheduler = DetectionScheduler({}, options=DetectionOptions(deep_scan=True))
    monkeypatch.setattr(
        scheduler.rule_manager,
        "evaluate_pool",
        lambda _bags: (_ for _ in ()).throw(AssertionError("normal rules must be bypassed")),
    )

    decision = scheduler.evaluate_bag(bag)

    assert decision.should_extract is True
    assert decision.decision_stage == "deep_detection"
    assert [item["offset"] for item in bag.get("embedded_archive.analysis")["candidates"]] == [
        0,
        second_offset,
    ]

    report = AnalysisEngine().analyze_path(
        str(path),
        initial_prepass=bag.get("analysis.signature_prepass"),
    )
    gzip_evidence = next(item for item in report.evidences if item.format == "gzip")
    assert [(item.start_offset, item.end_offset) for item in gzip_evidence.segments] == [
        (0, len(first)),
        (second_offset, second_offset + len(second)),
    ]


def test_deep_detection_reports_no_candidate_without_running_rules(tmp_path, monkeypatch):
    path = tmp_path / "plain.bin"
    path.write_bytes(b"not an archive")
    bag = FactBag()
    bag.set("file.path", str(path))
    scheduler = DetectionScheduler({}, options=DetectionOptions(deep_scan=True))
    monkeypatch.setattr(
        scheduler.rule_manager,
        "evaluate_pool",
        lambda _bags: (_ for _ in ()).throw(AssertionError("normal rules must be bypassed")),
    )

    decision = scheduler.evaluate_bag(bag)

    assert decision.should_extract is False
    assert decision.decision == "not_archive"
    assert decision.decision_stage == "deep_detection"
    assert bag.get("analysis.signature_prepass")["full_scan_complete"] is True
