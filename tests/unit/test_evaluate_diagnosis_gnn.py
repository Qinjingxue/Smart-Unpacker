import json
from pathlib import Path

import pytest

from repair_training.diagnosis.graph_rows import main as build_graphs_main
from repair_training.diagnosis.evaluation import main as evaluate_main
from repair_training.__main__ import train_main


pytest.importorskip("torch")
pytest.importorskip("torch_geometric")


def test_evaluate_diagnosis_gnn_outputs_metrics_and_predictions(tmp_path: Path):
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    rows = [
        {
            "sample_id": "a",
            "format": "zip",
            "knowledge_payload": {
                "analysis": {"summary": {"format": "zip"}},
                "source": {"input": {"entry_path": "a.zip"}},
                "format": {"zip": {"structure": {"graph": {"summary": {"file_size": 10}}}}},
            },
            "damage_analysis_target": {"damage_labels": ["field:eocd.cd_offset", "zone:eocd"]},
        },
        {
            "sample_id": "b",
            "format": "zip",
            "knowledge_payload": {
                "analysis": {"summary": {"format": "zip"}},
                "source": {"input": {"entry_path": "b.zip"}},
                "format": {"zip": {"structure": {"graph": {"summary": {"file_size": 12}}}}},
            },
            "damage_analysis_target": {"damage_labels": []},
        },
    ] * 4
    rows_path = datasets / "rows.jsonl"
    rows_path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    build_graphs_main([
        "--format", "auto",
        "--input", str(rows_path),
        "--output", str(datasets / "diagnosis_graph_rows.jsonl"),
        "--summary-output", str(run_dir / "reports" / "diagnosis_graph_summary.json"),
    ])
    train_main(["--format", "zip", "--model", "diagnosis_gnn", "--run-dir", str(run_dir), "--device", "cpu"])
    output = run_dir / "reports" / "diagnosis_gnn_eval"

    assert evaluate_main([
        "--format", "zip",
        "--input", str(datasets / "diagnosis_graph_rows.jsonl"),
        "--model-dir", str(run_dir / "models" / "diagnosis_gnn"),
        "--output", str(output),
        "--device", "cpu",
    ]) == 0

    assert (output / "diagnosis_gnn_metrics.json").is_file()
    assert (output / "diagnosis_gnn_predictions.jsonl").is_file()
