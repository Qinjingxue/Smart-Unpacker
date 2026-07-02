import pytest

from sunpack.repair.model.diagnosis.graph_dispatcher import (
    UnsupportedDiagnosisGraphFormat,
    build_diagnosis_graph_sample_for_format,
    detect_graph_format,
)


def test_diagnosis_graph_dispatcher_detects_format_priority():
    assert detect_graph_format({"format": "zip", "knowledge_payload": {}}) == "zip"
    assert detect_graph_format({
        "knowledge_payload": {"analysis": {"summary": {"format": "zip"}}}
    }) == "zip"
    assert detect_graph_format({
        "knowledge_payload": {"source": {"input": {"format_hint": "zip"}}}
    }) == "zip"
    assert detect_graph_format({"knowledge_payload": {"format": {"zip": {}}}}) == "zip"
    assert detect_graph_format({
        "knowledge_payload": {"source": {"input": {"entry_path": "a/b/c.zip"}}}
    }) == "zip"


def test_diagnosis_graph_dispatcher_rejects_unknown_and_unsupported():
    assert detect_graph_format({"format": "7z"}) == "7z"

    with pytest.raises(UnsupportedDiagnosisGraphFormat):
        detect_graph_format({"knowledge_payload": {"source": {"input": {"entry_path": "a.bin"}}}})


def test_seven_zip_diagnosis_graph_preserves_private_field_semantics():
    sample = build_diagnosis_graph_sample_for_format("7z", {
        "sample_id": "seven_zip_case",
        "format": "7z",
        "damage_flags": ["folder_bind_pairs_bad", "encoded_header_coder_properties_bad"],
        "seven_zip_structure_features": {"solid_archive": True, "folder_count": 2},
    })

    assert sample.format == "7z"
    assert sample.labels.root_case_labels == [
        "encoded_header_coder_properties_bad",
        "folder_bind_pairs_bad",
    ]
    assert "cause:7z:folder_graph" in sample.labels.cause_node_ids
    assert any(node.field_path == "format.7z.folder_bind_pairs_bad" for node in sample.graph.nodes)
