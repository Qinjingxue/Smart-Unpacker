from packrelic.coordinator.scanner import ScanOrchestrator
from tests.helpers.detection_config import with_detection_pipeline


def test_scan_reports_misnamed_split_parts_consistently(tmp_path):
    first = tmp_path / "rj081295.7z.001"
    normal_2 = tmp_path / "rj081295"
    normal_3 = tmp_path / "rj081295.7z"
    fuzzy_4 = tmp_path / "95.7z.005"
    fuzzy_5 = tmp_path / "rj0815.7"

    for path in (first, normal_2, normal_3, fuzzy_4, fuzzy_5):
        path.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * (1024 * 1024))

    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 1, "maybe_archive_threshold": 1},
    }, scoring=[
        {"name": "extension", "enabled": True, "extension_score_groups": [{"score": 1, "extensions": [".001", ".7z"]}]},
    ])

    results = ScanOrchestrator(config).scan(str(tmp_path))

    assert len(results) == 1
    assert results[0].main_path == str(first)
    assert results[0].all_parts == [str(first), str(normal_2), str(normal_3), str(fuzzy_4), str(fuzzy_5)]
    assert [
        (item["path"], item["number"], item["source"])
        for item in results[0].fact_bag.get("relation.split_volumes")
    ] == [
        (str(first), 1, "standard"),
        (str(normal_2), 2, "candidate"),
        (str(normal_3), 3, "candidate"),
        (str(fuzzy_4), 4, "candidate"),
        (str(fuzzy_5), 5, "candidate"),
    ]
