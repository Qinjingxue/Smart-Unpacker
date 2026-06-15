import json
from pathlib import Path

from repair_training.diagnosis.graph_rows import main as build_diagnosis_graphs_main
from repair_training.data.io import read_jsonl


def test_build_diagnosis_graphs_cli_smoke(tmp_path: Path):
    rows = [
        {
            "sample_id": "a",
            "format": "zip",
            "knowledge_payload": {
                "analysis": {"summary": {"format": "zip"}},
                "source": {"input": {"entry_path": "a.zip"}},
                "format": {"zip": {"structure": {"graph": {"summary": {"file_size": 10}}}}},
            },
            "damage_analysis_target": {"damage_labels": ["field:eocd.cd_offset"]},
        },
        {
            "sample_id": "b",
            "format": "zip",
            "knowledge_payload": {
                "analysis": {"summary": {"format": "zip"}},
                "source": {"input": {"entry_path": "b.zip"}},
                "format": {"zip": {"structure": {"graph": {"summary": {"file_size": 20}}}}},
            },
            "normal_label": 1,
        },
    ]
    input_path = tmp_path / "rows.jsonl"
    output_path = tmp_path / "datasets" / "diagnosis_graph_rows.jsonl"
    summary_path = tmp_path / "reports" / "diagnosis_graph_summary.json"
    input_path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

    assert build_diagnosis_graphs_main([
        "--format", "auto",
        "--input", str(input_path),
        "--output", str(output_path),
        "--summary-output", str(summary_path),
    ]) == 0

    output_rows = read_jsonl(output_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert len(output_rows) == 2
    assert summary["rows"] == 2
    assert summary["formats"] == {"zip": 2}
    assert summary["unsupported_count"] == 0
    assert summary["node_layer_counts"]["theory"] > 0
