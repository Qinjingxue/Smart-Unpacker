from repair_training.core.diagnosis_graph.dispatcher import build_diagnosis_graph_sample


def _zip_payload() -> dict:
    return {
        "analysis": {"summary": {"format": "zip"}},
        "source": {"input": {"format_hint": "zip", "entry_path": "sample.zip"}},
        "format": {
            "zip": {
                "structure": {
                    "graph": {
                        "summary": {
                            "archive_readable": True,
                            "central_directory_offset_delta": 18,
                            "entry_count_delta": 1,
                            "file_size": 192,
                            "cd_entry_count": 1,
                            "local_header_offset_violation_count": 1,
                            "sfx_prefix_len": 0,
                        },
                        "violations": [
                            {
                                "field": "central_directory.local_header_offset",
                                "kind": "bad_reference",
                                "severity": "high",
                                "delta": -18,
                            }
                        ],
                        "explanations": [
                            {
                                "field": "eocd.cd_offset",
                                "kind": "sfx_prefix_adjustment",
                                "applies": True,
                                "delta": 18,
                            }
                        ],
                    }
                }
            }
        },
        "extraction": {"result": {"success": False}, "failure": {"failure_kind": "corrupted_data"}},
        "verification": {"summary": {"assessment_status": "partial", "completeness": 0.0}},
    }


def test_zip_diagnosis_graph_clean_has_three_layers_and_no_root_cause():
    sample = build_diagnosis_graph_sample({
        "sample_id": "clean",
        "format": "zip",
        "normal_label": 1,
        "knowledge_payload": _zip_payload(),
    })

    layers = {node.node_layer for node in sample.graph.nodes}
    assert layers == {"observation", "theory", "cause"}
    assert sample.labels.cause_node_ids == []
    assert sample.labels.auxiliary["clean"] is True
    assert any(edge.edge_type == "observes_theory" for edge in sample.graph.edges)


def test_zip_diagnosis_graph_maps_damage_labels_to_cause_and_theory():
    sample = build_diagnosis_graph_sample({
        "sample_id": "damaged",
        "format": "zip",
        "knowledge_payload": _zip_payload(),
        "damage_analysis_target": {
            "damage_labels": [
                "field:central_directory.local_header_offset",
                "zone:central_directory",
            ]
        },
        "metadata": {"damage_profile": "unit_profile"},
    })

    assert "field:central_directory.local_header_offset" in sample.labels.field_labels
    assert "zone:central_directory" in sample.labels.zone_labels
    assert "cause:field:central_directory.local_header_offset" in sample.labels.cause_node_ids
    assert "theory:zip.central_directory.local_header_offset" in sample.labels.theory_node_ids
    assert any("central_directory.local_header_offset" in edge_id or "central_directory_local_header_offset" in edge_id for edge_id in sample.labels.theory_edge_ids)
    assert sample.labels.auxiliary["damage_profile"] == "unit_profile"


def test_zip_diagnosis_graph_maps_relation_violation_to_both_theory_sides():
    payload = _zip_payload()
    payload["format"]["zip"]["structure"]["graph"]["violations"] = [
        {
            "kind": "field_relation_mismatch",
            "field": "central_directory.flags",
            "source_field": "central_directory.flags",
            "target_field": "local_header.flags",
            "relation": "matches_field",
            "likely_bad_side": "central_directory.flags",
            "evidence_confidence": 0.9,
        }
    ]
    sample = build_diagnosis_graph_sample({
        "sample_id": "relation",
        "format": "zip",
        "knowledge_payload": payload,
        "damage_analysis_target": {"damage_labels": ["field:central_directory.flags"]},
    })

    observation = next(
        node for node in sample.graph.nodes
        if node.node_layer == "observation" and node.node_type == "violation"
    )
    assert "central_directory.flags->local_header.flags" in observation.field_path
    assert observation.features["likely_bad_side"] == "central_directory.flags"
    mapped_targets = {
        edge.target for edge in sample.graph.edges
        if edge.source == observation.node_id and edge.edge_type == "observes_theory"
    }
    assert "theory:zip.central_directory.flags" in mapped_targets
    assert "theory:zip.local_header.flags" in mapped_targets


def test_zip_diagnosis_graph_is_stable():
    row = {"sample_id": "stable", "format": "zip", "knowledge_payload": _zip_payload()}
    first = build_diagnosis_graph_sample(row).to_dict()
    second = build_diagnosis_graph_sample(row).to_dict()

    assert first == second
