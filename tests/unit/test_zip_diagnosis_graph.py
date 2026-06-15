from sunpack.repair.model.diagnosis.graph_dispatcher import build_diagnosis_graph_sample


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

    assert "central_directory.local_header_offset" in sample.labels.root_case_labels
    assert "field:central_directory.local_header_offset" in sample.labels.field_labels
    assert "zone:central_directory" not in sample.labels.zone_labels
    assert "cause:root_case:central_directory.local_header_offset" in sample.labels.cause_node_ids
    assert "theory:zip.central_directory.local_header_offset" in sample.labels.theory_node_ids
    assert any("central_directory.local_header_offset" in edge_id or "central_directory_local_header_offset" in edge_id for edge_id in sample.labels.theory_edge_ids)
    assert sample.labels.auxiliary["damage_profile"] == "unit_profile"


def test_zip_diagnosis_graph_prefers_actionable_root_labels_over_injected_roots():
    sample = build_diagnosis_graph_sample({
        "sample_id": "actionable",
        "format": "zip",
        "knowledge_payload": _zip_payload(),
        "actionable_root_labels": ["eocd.cd_size"],
        "damage_analysis_target": {
            "damage_labels": [
                "field:eocd.cd_size",
                "field:local_header.signature",
                "field:local_header.method",
                "field:sfx_prefix.bytes",
            ]
        },
    })

    assert sample.labels.root_case_labels == ["eocd.cd_size"]
    assert sample.labels.field_labels == ["field:eocd.cd_size"]
    assert sample.labels.auxiliary["actionable_label_source"] == "actionable_root_labels"
    assert set(sample.labels.auxiliary["injected_cause"]) == {
        "eocd.cd_size",
        "local_header.signature",
        "compression_method",
        "sfx_prefix.bytes",
    }


def test_zip_diagnosis_graph_maps_relation_violation_direction_separately_from_context():
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
    direction_targets = {
        edge.target for edge in sample.graph.edges
        if edge.source == observation.node_id and edge.edge_type == "observes_root_direction"
    }
    assert "theory:zip.central_directory.flags" in mapped_targets
    assert "theory:zip.local_header.flags" not in mapped_targets
    assert "theory:zip.central_directory.flags" in direction_targets


def test_zip_diagnosis_graph_local_header_signature_direction_does_not_promote_offset():
    payload = _zip_payload()
    payload["format"]["zip"]["structure"]["graph"]["violations"] = [
        {
            "kind": "local_header_signature_mismatch",
            "field": "local_header.signature",
            "source_field": "central_directory.local_header_offset",
            "target_field": "local_header.signature",
            "relation": "points_to",
            "likely_bad_side": "local_header.signature",
            "evidence_confidence": 0.9,
        }
    ]
    sample = build_diagnosis_graph_sample({
        "sample_id": "local-signature-direction",
        "format": "zip",
        "knowledge_payload": payload,
        "damage_analysis_target": {"damage_labels": ["field:local_header.signature"]},
    })

    observation = next(
        node for node in sample.graph.nodes
        if node.node_layer == "observation" and node.node_type == "violation"
    )
    mapped_targets = {
        edge.target for edge in sample.graph.edges
        if edge.source == observation.node_id and edge.edge_type == "observes_theory"
    }
    direction_targets = {
        edge.target for edge in sample.graph.edges
        if edge.source == observation.node_id and edge.edge_type == "observes_root_direction"
    }
    assert "theory:zip.local_header.signature" in mapped_targets
    assert "theory:zip.local_header.signature" in direction_targets
    assert "theory:zip.central_directory.local_header_offset" not in mapped_targets


def test_zip_diagnosis_graph_does_not_promote_violation_likely_bad_side_to_root():
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
        "sample_id": "symptom-only",
        "format": "zip",
        "knowledge_payload": payload,
    })

    assert sample.labels.field_labels == []
    assert sample.labels.cause_node_ids == []
    assert "field:central_directory.flags" in sample.labels.symptom_field_labels
    assert sample.labels.auxiliary["has_observed_symptoms"] is True


def test_zip_diagnosis_graph_canonicalizes_fine_fields_to_repair_roots():
    sample = build_diagnosis_graph_sample({
        "sample_id": "repair-root",
        "format": "zip",
        "knowledge_payload": _zip_payload(),
        "damage_analysis_target": {
            "damage_labels": [
                "field:central_directory.method",
                "field:local_header.method",
                "field:central_directory.filename",
                "field:local_header.extra",
                "field:zip64.extra",
                "field:central_directory.external_attributes",
                "field:tail.comment",
            ]
        },
    })

    assert "field:compression_method" in sample.labels.field_labels
    assert "field:entry_name" in sample.labels.field_labels
    assert "field:generic_extra_field" in sample.labels.field_labels
    assert "field:zip64.uncompressed_size" in sample.labels.field_labels
    assert "compression_method" in sample.labels.root_case_labels
    assert "entry_name" in sample.labels.root_case_labels
    assert "generic_extra_field" in sample.labels.root_case_labels
    assert "zip64.uncompressed_size" in sample.labels.root_case_labels
    assert "field:central_directory.method" not in sample.labels.field_labels
    assert "field:local_header.method" not in sample.labels.field_labels
    assert "field:central_directory.external_attributes" not in sample.labels.field_labels
    assert "field:tail.comment" not in sample.labels.field_labels
    assert "cause:root_case:compression_method" in sample.labels.cause_node_ids


def test_zip_diagnosis_graph_is_stable():
    row = {"sample_id": "stable", "format": "zip", "knowledge_payload": _zip_payload()}
    first = build_diagnosis_graph_sample(row).to_dict()
    second = build_diagnosis_graph_sample(row).to_dict()

    assert first == second
