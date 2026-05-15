import json
from pathlib import Path

from repair_training.build_features import main as build_features_main
from repair_training.collect_damage_rows import collect_damage_row
from sunpack.repair.scheduler import RepairScheduler


def test_collect_damage_row_uses_location_only_targets(monkeypatch, tmp_path):
    called_candidates = False

    def fail_candidates(*args, **kwargs):
        nonlocal called_candidates
        called_candidates = True
        raise AssertionError("damage row collector must not generate repair candidates")

    monkeypatch.setattr(RepairScheduler, "generate_repair_candidates", fail_candidates)
    monkeypatch.setattr(
        "repair_training.collect_damage_rows.observe_damage_runtime",
        lambda job, *, workspace, config=None: (
            {
                "format": "zip",
                "archive_state": {"patch_digest": "digest", "patches": []},
                "runtime_context": {
                    "archive_state": {"patch_depth": 0, "patch_digest": "digest"},
                    "analysis_summary": {"format": "zip", "confidence": 1.0},
                    "analysis_native_probe": {"format": "zip"},
                    "extraction_summary": {"has_failure": True, "failure_kind": "bad"},
                    "verification_summary": {"completeness": 0.0},
                },
            },
            {"state_digest": "digest", "patch_depth": 0},
        ),
    )

    damaged = tmp_path / "bad.zip"
    damaged.write_bytes(b"PK\x03\x04bad")
    record = {
        "sample_id": "sample",
        "query_id": "sample:0",
        "format": "zip",
        "damage_profile": "unit",
        "damaged_input": {"kind": "file", "path": str(damaged), "format_hint": "zip"},
        "corruption_plan": [
            {"zone": "zip.eocd.cd_offset", "offset": 1, "size": 4},
            {"zone": "archive.tail", "offset": 10, "size": 2},
        ],
    }

    row = collect_damage_row(record, workspace=tmp_path / "workspace")
    labels = set(row["damage_analysis_target"]["damage_labels"])

    assert labels == {"zone:eocd", "field:eocd.cd_offset", "zone:tail", "field:tail.trailing_bytes"}
    assert all(label.startswith(("zone:", "field:")) for label in labels)
    assert row["damage_analysis_input"]["runtime_context"]["archive_state"]["patch_depth"] == 0
    assert "candidate" not in json.dumps(row["damage_analysis_input"]).lower()
    assert not called_candidates


def test_damage_rows_build_features_location_only(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "repair_training.collect_damage_rows.observe_damage_runtime",
        lambda job, *, workspace, config=None: (
            {
                "format": "zip",
                "archive_state": {"patch_digest": "digest", "patches": []},
                "runtime_context": {
                    "archive_state": {"patch_depth": 0, "patch_digest": "digest"},
                    "analysis_summary": {"format": "zip", "confidence": 1.0},
                    "analysis_native_probe": {"format": "zip"},
                    "extraction_summary": {"has_failure": True, "failure_kind": "bad"},
                    "verification_summary": {"completeness": 0.0},
                },
            },
            {"state_digest": "digest", "patch_depth": 0},
        ),
    )
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    damaged = tmp_path / "bad.zip"
    damaged.write_bytes(b"PK\x03\x04bad")
    rows = [
        collect_damage_row(
            {
                "sample_id": f"sample{i}",
                "format": "zip",
                "damaged_input": {"kind": "file", "path": str(damaged), "format_hint": "zip"},
                "corruption_plan": [{"zone": "zip.eocd.cd_offset" if i % 2 == 0 else "archive.tail", "offset": i, "size": 4}],
            },
            workspace=tmp_path / f"workspace{i}",
        )
        for i in range(4)
    ]
    with (datasets / "damage_rows.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    assert build_features_main(["--format", "zip", "--model", "damage_analysis", "--run-dir", str(run_dir)]) == 0
    schema = json.loads((run_dir / "features" / "damage_analysis" / "label_schema.json").read_text(encoding="utf-8"))

    assert schema["labels"]
    assert all(label.startswith(("zone:", "field:")) for label in schema["labels"])
