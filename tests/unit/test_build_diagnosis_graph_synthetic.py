import json
from pathlib import Path

from repair_training.build_diagnosis_graphs import main as build_graphs_main
from repair_training.build_diagnosis_graph_synthetic import main as synthetic_main


def test_build_diagnosis_graph_synthetic_writes_strong_labels(tmp_path: Path):
    rows_path = tmp_path / "clean_rows.jsonl"
    graph_path = tmp_path / "clean_graphs.jsonl"
    synthetic_path = tmp_path / "synthetic_graphs.jsonl"
    rows_path.write_text(json.dumps({
        "sample_id": "clean",
        "format": "zip",
        "knowledge_payload": {
            "analysis": {"summary": {"format": "zip"}},
            "source": {"input": {"entry_path": "clean.zip"}},
            "format": {"zip": {"structure": {"graph": {"summary": {"file_size": 10}}}}},
        },
    }), encoding="utf-8")
    assert build_graphs_main([
        "--format", "auto",
        "--input", str(rows_path),
        "--output", str(graph_path),
        "--summary-output", str(tmp_path / "graph_summary.json"),
    ]) == 0

    assert synthetic_main([
        "--format", "zip",
        "--input", str(graph_path),
        "--output", str(synthetic_path),
        "--summary-output", str(tmp_path / "synthetic_summary.json"),
        "--per-sample", "2",
    ]) == 0

    rows = [json.loads(line) for line in synthetic_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(rows) == 2
    labels = rows[0]["labels"]
    assert labels["root_cause"]["cause_node_ids"]
    assert labels["root_cause"]["field_labels"]
    assert labels["theory_alignment"]["theory_node_ids"]
    assert labels["theory_alignment"]["theory_edge_ids"]
    assert labels["auxiliary"]["synthetic"] is True
