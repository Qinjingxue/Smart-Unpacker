import json
from pathlib import Path

import pytest

from repair_training.core import cleanup
from repair_training.core.damage_eval import evaluate_predictions, leakage_report
from repair_training.core.damage_feature_analysis import analyze_damage_features
from repair_training.core.damage_model_inference import DamageAnalysisModel, select_labels
from repair_training.core.plugin import TrainingFeatureSpec, TrainingFormatPlugin


def test_constant_damage_model_predicts_scores(tmp_path):
    model_dir = tmp_path / "model"
    (model_dir / "models").mkdir(parents=True)
    _write_json(model_dir / "feature_schema.json", {
        "feature_names": [],
        "categorical_maps": {},
        "label_schema": {"labels": ["zone:eocd"]},
    })
    _write_json(model_dir / "label_schema.json", {"labels": ["zone:eocd"]})
    _write_json(model_dir / "models.json", {"zone:eocd": "models/zone_eocd.constant.json"})
    _write_json(model_dir / "models" / "zone_eocd.constant.json", {"constant_probability": 0.75})

    model = DamageAnalysisModel(model_dir=model_dir, plugin=TrainingFormatPlugin(format_name="zip", default_run_name="x"))
    scores = model.predict_rows([{"knowledge_payload": {}}])[0]

    assert scores["zone:eocd"] == 0.75
    assert select_labels(scores, threshold=0.5) == ["zone:eocd"]


def test_damage_eval_metrics_and_leakage_detection():
    predictions = [
        {"true_labels": ["zone:eocd", "field:eocd.cd_offset"], "predicted_labels": ["zone:eocd"], "scores": {"zone:eocd": 0.9}},
        {"true_labels": ["zone:tail"], "predicted_labels": ["zone:tail"], "scores": {"zone:tail": 0.9}},
    ]
    metrics = evaluate_predictions(predictions)
    leak = leakage_report([
        {"knowledge_payload": {"source": {"input": {"format_hint": "zip"}}}},
        {"knowledge_payload": {"corruption_plan": []}},
    ])

    assert metrics["zone_micro_f1"] > 0.99
    assert metrics["field_micro_f1"] == 0.0
    assert not leak["ok"]
    assert leak["leak_count"] == 1


def test_damage_feature_analysis_filters_by_feature_spec(tmp_path):
    rows_path = tmp_path / "damage_rows.jsonl"
    predictions_path = tmp_path / "predictions.jsonl"
    output = tmp_path / "report"
    rows = [
        {
            "sample_id": "s1",
            "metadata": {"damage_profile": "payload"},
            "damage_analysis_target": {"damage_labels": ["field:payload.compressed_data"]},
            "knowledge_payload": {
                "format": {"zip": {"structure": {"runtime": {"payload_content_failure_observed": True}}}},
            },
        },
        {
            "sample_id": "s2",
            "metadata": {"damage_profile": "split"},
            "damage_analysis_target": {"damage_labels": ["field:split_volume.missing_range"]},
            "knowledge_payload": {
                "format": {"zip": {"structure": {"runtime": {"payload_content_failure_observed": False}}}},
            },
        },
    ]
    predictions = [
        {
            "sample_id": "s1",
            "true_labels": ["field:payload.compressed_data"],
            "predicted_labels": [],
            "scores": {"field:payload.compressed_data": 0.4},
            "threshold": 0.5,
        }
    ]
    _write_jsonl(rows_path, rows)
    _write_jsonl(predictions_path, predictions)
    plugin = TrainingFormatPlugin(
        format_name="zip",
        default_run_name="x",
        damage_feature_spec=lambda: TrainingFeatureSpec(
                include_prefixes=("format.zip.structure.",),
                ignore_prefixes=("format.zip.raw_structure.",),
        ),
        diagnostic_focus_labels=lambda: ["field:payload.compressed_data"],
        diagnostic_profile_pairs=lambda: [("payload", "split")],
            diagnostic_feature_groups=lambda: {"runtime": ["format.zip.structure.runtime."]},
    )

    summary = analyze_damage_features(
        rows_path=rows_path,
        predictions_path=predictions_path,
        output_dir=output,
        plugin=plugin,
    )
    report = json.loads((output / "label_feature_correlation.json").read_text(encoding="utf-8"))
    hard_cases = [json.loads(line) for line in (output / "hard_case_feature_report.jsonl").read_text(encoding="utf-8").splitlines()]

    assert summary["feature_groups"]["runtime"]["feature_count"] == 1
    assert "field:payload.compressed_data" in report
    assert report["field:payload.compressed_data"]["top_positive_features"][0]["feature"].endswith("payload_content_failure_observed")
    assert hard_cases[0]["missing_labels"] == ["field:payload.compressed_data"]
    assert "raw_structure" not in json.dumps(report)


def test_cleanup_refuses_outside_root_and_uses_powershell(monkeypatch, tmp_path):
    root = tmp_path / "root"
    target = root / "tmp"
    target.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return None

    monkeypatch.setattr(cleanup.os, "name", "nt")
    monkeypatch.setattr(cleanup.subprocess, "run", fake_run)

    assert cleanup.remove_tree_fast(target, root=root) is False
    assert calls
    assert "Remove-Item -LiteralPath" in calls[0][4]
    with pytest.raises(ValueError):
        cleanup.remove_tree_fast(outside, root=root)


def _write_json(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
