import pytest

from repair_training.core.diagnosis_graph.dispatcher import build_diagnosis_graph_sample
from repair_training.core.diagnosis_gnn.model import build_diagnosis_gnn_model
from repair_training.core.diagnosis_gnn.tensorize import metadata_from_samples, tensorize_sample


pytest.importorskip("torch")
pytest.importorskip("torch_geometric")


def test_diagnosis_gnn_forward_outputs_cause_and_theory_logits():
    sample = build_diagnosis_graph_sample({
        "sample_id": "forward",
        "format": "zip",
        "knowledge_payload": {
            "analysis": {"summary": {"format": "zip"}},
            "source": {"input": {"entry_path": "forward.zip"}},
            "format": {"zip": {"structure": {"graph": {"summary": {"file_size": 10}}}}},
        },
        "damage_analysis_target": {"damage_labels": ["field:eocd.cd_offset"]},
    })
    data = tensorize_sample(sample)
    model = build_diagnosis_gnn_model(metadata=metadata_from_samples([sample]), config={"hidden_dim": 16, "layers": 1})

    out = model(data.x_dict, data.edge_index_dict)

    assert out["cause"].shape[0] == data["cause"].x.shape[0]
    assert out["theory"].shape[0] == data["theory"].x.shape[0]
    assert "theory_edge" in out
    assert out["theory_edge"].ndim == 1
