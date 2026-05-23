from repair_training.build_diagnosis_evidence_rows import add_evidence_targets
from repair_training.build_diagnosis_root_probe_rows import build_probe_training_rows


def _graph_row():
    return {
        "schema_version": "diagnosis_graph_v1",
        "format": "zip",
        "sample_id": "sample-a",
        "source": {},
        "graph": {"nodes": [], "edges": [], "graph_features": {}},
        "labels": {
            "root_case": {"labels": ["eocd.cd_size"]},
            "root_cause": {"cause_node_ids": [], "field_labels": [], "zone_labels": []},
            "theory_alignment": {"theory_node_ids": [], "theory_edge_ids": []},
            "propagated_symptoms": {"field_labels": [], "zone_labels": [], "theory_node_ids": [], "theory_edge_ids": []},
            "auxiliary": {},
        },
    }


def test_build_probe_training_rows_adds_transition_and_evidence_targets():
    rows, summary = build_probe_training_rows([
        _graph_row()
    ], [
        {
            "graph_sample_id": "sample-a",
            "candidate_root": "eocd.cd_size",
            "recovery_delta": 0.6,
            "ak_consistency_delta": 0.3,
            "evidence_delta": 0.3,
        },
        {
            "graph_sample_id": "sample-a",
            "candidate_root": "payload.compressed_data",
            "recovery_delta": 0.0,
            "ak_consistency_delta": 0.0,
            "evidence_delta": 0.0,
        },
    ], hard_label_margin=0.1)

    auxiliary = rows[0]["labels"]["auxiliary"]
    assert auxiliary["root_transition_gain_targets"]["eocd.cd_size"] > 0.0
    assert auxiliary["root_evidence_targets"]["eocd.cd_size"] == 0.3
    assert rows[0]["labels"]["root_case"]["labels"] == ["eocd.cd_size"]
    assert summary["covered_rows"] == 1


def test_add_evidence_targets_from_existing_root_labels():
    row = add_evidence_targets(_graph_row())

    targets = row["labels"]["auxiliary"]["root_evidence_targets"]
    assert targets["eocd.cd_size"] == 1.0
    assert targets["central_directory.compressed_size"] == 0.0
    assert len(targets) == 26
