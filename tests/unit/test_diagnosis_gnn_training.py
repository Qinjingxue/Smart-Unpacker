import json
from pathlib import Path

import pytest

from repair_training.build_diagnosis_graphs import main as build_graphs_main
from repair_training.train import main as train_main


pytest.importorskip("torch")
pytest.importorskip("torch_geometric")


def test_diagnosis_gnn_train_cli_writes_artifacts(tmp_path: Path):
    run_dir = tmp_path / "run"
    datasets = run_dir / "datasets"
    datasets.mkdir(parents=True)
    rows = []
    for index in range(8):
        rows.append({
            "sample_id": f"sample:{index}",
            "format": "zip",
            "knowledge_payload": {
                "analysis": {"summary": {"format": "zip"}},
                "source": {"input": {"entry_path": f"{index}.zip"}},
                "format": {
                    "zip": {
                        "structure": {
                            "graph": {
                                "summary": {
                                    "file_size": 10,
                                    "central_directory_offset_delta": 4 if index % 2 else 0,
                                }
                            }
                        }
                    }
                },
            },
            "damage_analysis_target": {"damage_labels": ["field:eocd.cd_offset"] if index % 2 else []},
        })
    rows_path = datasets / "rows.jsonl"
    rows_path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    build_graphs_main([
        "--format", "auto",
        "--input", str(rows_path),
        "--output", str(datasets / "diagnosis_graph_rows.jsonl"),
        "--summary-output", str(run_dir / "reports" / "diagnosis_graph_summary.json"),
    ])

    assert train_main([
        "--format", "zip",
        "--model", "diagnosis_gnn",
        "--run-dir", str(run_dir),
        "--device", "cpu",
    ]) == 0

    assert (run_dir / "models" / "diagnosis_gnn" / "model.pt").is_file()
    assert (run_dir / "models" / "diagnosis_gnn" / "model_card.json").is_file()
    assert (run_dir / "models" / "diagnosis_gnn" / "train_metrics.json").is_file()
