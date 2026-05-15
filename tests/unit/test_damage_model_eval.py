import json
from pathlib import Path

import pytest

from repair_training.core import cleanup
from repair_training.core.damage_eval import evaluate_predictions, leakage_report
from repair_training.core.damage_model_inference import DamageAnalysisModel, select_labels
from repair_training.core.plugin import TrainingFormatPlugin


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
    scores = model.predict_rows([{"damage_analysis_input": {}}])[0]

    assert scores["zone:eocd"] == 0.75
    assert select_labels(scores, threshold=0.5) == ["zone:eocd"]


def test_damage_eval_metrics_and_leakage_detection():
    predictions = [
        {"true_labels": ["zone:eocd", "field:eocd.cd_offset"], "predicted_labels": ["zone:eocd"], "scores": {"zone:eocd": 0.9}},
        {"true_labels": ["zone:tail"], "predicted_labels": ["zone:tail"], "scores": {"zone:tail": 0.9}},
    ]
    metrics = evaluate_predictions(predictions)
    leak = leakage_report([
        {"damage_analysis_input": {"runtime_context": {"archive_state": {"patch_depth": 0, "state": {"patches": []}}}}},
        {"damage_analysis_input": {"corruption_plan": []}},
    ])

    assert metrics["zone_micro_f1"] > 0.99
    assert metrics["field_micro_f1"] == 0.0
    assert not leak["ok"]
    assert leak["leak_count"] == 1


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
