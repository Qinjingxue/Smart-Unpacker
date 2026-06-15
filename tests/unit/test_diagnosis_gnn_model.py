import pytest

from sunpack.repair.model.diagnosis.graph_dispatcher import build_diagnosis_graph_sample
from sunpack.repair.model.diagnosis.model import build_diagnosis_gnn_model
from sunpack.repair.model.diagnosis.tensorize import metadata_from_samples, tensorize_sample


pytest.importorskip("torch")
pytest.importorskip("torch_geometric")


def test_diagnosis_hgt_forward_outputs_cause_and_theory_logits():
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
    model = build_diagnosis_gnn_model(
        metadata=metadata_from_samples([sample]),
        config={"arch": "hgt", "hidden_dim": 16, "layers": 1, "heads": 2},
    )

    out = model(data.x_dict, data.edge_index_dict)

    assert out["cause"].shape[0] == data["cause"].x.shape[0]
    assert out["theory"].shape[0] == data["theory"].x.shape[0]
    assert out["root_case"].shape[-1] == 26
    assert out["root_evidence"].shape == out["root_case"].shape
    assert out["root_transition_gain"].shape == out["root_case"].shape
    assert "theory_edge" in out
    assert out["theory_edge"].ndim == 1


def test_diagnosis_gnn_rejects_unknown_architecture():
    sample = build_diagnosis_graph_sample({
        "sample_id": "bad-arch",
        "format": "zip",
        "knowledge_payload": {
            "analysis": {"summary": {"format": "zip"}},
            "source": {"input": {"entry_path": "bad.zip"}},
        },
    })
    with pytest.raises(ValueError, match="unsupported DiagnosisGNN architecture"):
        build_diagnosis_gnn_model(metadata=metadata_from_samples([sample]), config={"arch": "nope"})
