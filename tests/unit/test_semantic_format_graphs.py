from __future__ import annotations

import pytest

from sunpack.analysis.knowledge import _format_structure_payload
from sunpack.repair.model.diagnosis.atomic_format_graph import DEFINITIONS
from sunpack.repair.model.diagnosis.graph_dispatcher import build_diagnosis_graph_sample_for_format


FORMAT_CASES = (
    (
        "rar",
        "rar_file_header_crc_bad",
        ("block.header_crc32", "block.header_size", "validates"),
        "header_crc_ok",
        "block.header_crc32",
    ),
    (
        "tar",
        "tar_checksum_bad",
        ("member.header.size", "member.payload.span", "bounds"),
        "member_size",
        "member.header.size",
    ),
    (
        "gzip",
        "gzip_footer_bad",
        ("member.trailer.crc32", "member.decoded_content", "validates"),
        "footer_crc",
        "member.trailer.crc32",
    ),
    (
        "bzip2",
        "bzip2_block_bad",
        ("stream.combined_crc32", "block.crc32", "folds_in_order"),
        "block_crc",
        "block.crc32",
    ),
    (
        "xz",
        "xz_footer_crc_bad",
        ("stream.footer.backward_size", "index.indicator", "points_to_index"),
        "backward_size",
        "stream.footer.backward_size",
    ),
    (
        "zstd",
        "zstd_frame_bad",
        ("block.header.size", "block.content", "bounds"),
        "block_size",
        "block.header.size",
    ),
)


@pytest.mark.parametrize("fmt,flag,expected_dependency,observation_path,expected_field", FORMAT_CASES)
def test_semantic_format_graphs_preserve_private_fields_and_dependencies(
    fmt,
    flag,
    expected_dependency,
    observation_path,
    expected_field,
):
    sample = build_diagnosis_graph_sample_for_format(fmt, {
        "format": fmt,
        "sample_id": f"{fmt}-semantic",
        "knowledge_payload": {
            "damage_flags": [flag],
            "format": {fmt: {observation_path: 7}},
        },
    })

    dependency_edges = {
        (
            edge.source.removeprefix(f"theory:{fmt}:"),
            edge.target.removeprefix(f"theory:{fmt}:"),
            edge.features.get("relation"),
        )
        for edge in sample.graph.edges
        if edge.edge_type == "theory_depends_on"
    }
    assert expected_dependency in dependency_edges
    assert sample.labels.root_case_labels == [flag]
    assert sample.graph.graph_features["semantic_graph"] is True
    assert sample.graph.graph_features["specification"] == DEFINITIONS[fmt].specification

    expected_theory_id = f"theory:{fmt}:{expected_field}"
    observation_edges = [
        edge for edge in sample.graph.edges
        if edge.edge_type == "observes_theory" and edge.target == expected_theory_id
    ]
    assert observation_edges


@pytest.mark.parametrize("fmt", sorted(DEFINITIONS))
def test_semantic_format_definitions_are_closed_and_have_real_dependencies(fmt):
    definition = DEFINITIONS[fmt]
    field_paths = {item.path for item in definition.fields}

    assert definition.specification.startswith("https://")
    assert len(definition.fields) >= 13
    assert len(definition.dependencies) >= 10
    assert all(item.source in field_paths and item.target in field_paths for item in definition.dependencies)
    assert all(roots and set(roots) <= field_paths for roots in definition.flag_roots.values())


def test_xz_footer_damage_labels_dependent_index_semantics_as_symptoms():
    sample = build_diagnosis_graph_sample_for_format("xz", {
        "format": "xz",
        "sample_id": "xz-footer",
        "damage_flags": ["xz_footer_crc_bad"],
    })

    assert "format.xz.stream.footer.backward_size" in sample.labels.symptom_field_labels
    assert any(
        edge.features.get("relation") == "validates"
        and edge.source == "theory:xz:stream.footer.crc32"
        for edge in sample.graph.edges
    )


def test_zstd_single_segment_semantics_capture_conditional_header_layout():
    sample = build_diagnosis_graph_sample_for_format("zstd", {
        "format": "zstd",
        "sample_id": "zstd-layout",
        "damage_flags": ["zstd_window_descriptor_missing"],
    })

    relations = {
        (edge.source, edge.target, edge.features.get("relation"))
        for edge in sample.graph.edges
        if edge.edge_type == "theory_depends_on"
    }
    assert (
        "theory:zstd:frame.header.single_segment_flag",
        "theory:zstd:frame.header.window_descriptor",
        "gates_absence",
    ) in relations
    assert (
        "theory:zstd:frame.header.single_segment_flag",
        "theory:zstd:frame.header.content_size",
        "requires_presence",
    ) in relations


def test_native_structure_details_are_preserved_for_semantic_graph_observations():
    details = {
        "format": "xz",
        "header_crc_ok": True,
        "footer_crc_ok": False,
        "damage_flags": ["xz_footer_crc_bad"],
    }

    assert _format_structure_payload("xz", details) == {
        "header_crc_ok": True,
        "footer_crc_ok": False,
        "damage_flags": ["xz_footer_crc_bad"],
    }


def test_nested_native_damage_flags_drive_semantic_labels_and_mapping_edges():
    sample = build_diagnosis_graph_sample_for_format("tar", {
        "format": "tar",
        "sample_id": "nested-native-flags",
        "knowledge_payload": {
            "format": {
                "tar": {
                    "structure": {
                        "damage_flags": ["tar_checksum_bad"],
                        "checksum_ok": False,
                    },
                },
            },
        },
    })

    assert sample.labels.root_case_labels == ["tar_checksum_bad"]
    assert any(
        edge.edge_type == "observes_theory"
        and edge.target == "theory:tar:member.header.checksum"
        for edge in sample.graph.edges
    )
