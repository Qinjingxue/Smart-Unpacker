import pytest

from sunpack.repair.model.diagnosis.graph_dispatcher import build_diagnosis_graph_sample
from sunpack.repair.model.diagnosis.tensorize import THEORY_DEPENDS_EDGE_TYPE, metadata_for_sample, tensorize_sample


pytest.importorskip("torch")
pytest.importorskip("torch_geometric")


def _sample():
    return build_diagnosis_graph_sample({
        "sample_id": "gnn",
        "format": "zip",
        "knowledge_payload": {
            "analysis": {"summary": {"format": "zip"}},
            "source": {"input": {"entry_path": "gnn.zip"}},
            "format": {
                "zip": {
                    "structure": {
                        "graph": {
                            "summary": {"file_size": 10, "central_directory_offset_delta": 4},
                            "violations": [{"field": "eocd.cd_offset", "kind": "bad_reference", "delta": 4}],
                        }
                    }
                }
            },
        },
        "damage_analysis_target": {"damage_labels": ["field:eocd.cd_offset", "zone:eocd"]},
    })


def test_diagnosis_gnn_tensorize_preserves_node_types_and_labels():
    sample = _sample()
    data = tensorize_sample(sample)
    metadata = metadata_for_sample(sample)

    assert {"observation", "theory", "cause"}.issubset(set(data.node_types))
    assert data["cause"].x.shape[0] == len(metadata.cause_node_ids)
    assert data["cause"].y.sum().item() >= 1
    assert data["theory"].y_alignment.sum().item() >= 1
    assert data[THEORY_DEPENDS_EDGE_TYPE].edge_label.sum().item() >= 1
    assert len(metadata.theory_edge_ids) == data[THEORY_DEPENDS_EDGE_TYPE].edge_label.shape[0]
    assert any(edge_type[1] == "observes_theory" for edge_type in data.edge_types)


def test_diagnosis_gnn_tensorize_reads_root_hypothesis_targets():
    row = _sample().to_dict()
    row["labels"]["auxiliary"]["root_transition_gain_targets"] = {"eocd.cd_offset": 0.75}
    row["labels"]["auxiliary"]["root_evidence_targets"] = {"eocd.cd_offset": 1.0}
    from sunpack.repair.model.diagnosis.graph_schema import DiagnosisGraphSample

    data = tensorize_sample(DiagnosisGraphSample.from_dict(row))

    assert data.root_transition_gain_y.sum().item() == pytest.approx(0.75)
    assert data.root_transition_gain_mask.sum().item() == 1
    assert data.root_evidence_y.sum().item() == pytest.approx(1.0)
    assert data.root_evidence_mask.sum().item() == 1
