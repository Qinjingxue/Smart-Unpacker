from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from repair_training.core.diagnosis_graph.labels import (
    field_from_label,
    label_zone,
    safe_node_token,
)
from repair_training.core.diagnosis_graph.schema import (
    DiagnosisEdge,
    DiagnosisLabels,
    DiagnosisNode,
    GraphFragment,
)
from repair_training.core.features import damage_labels_for_row, oracle_damage_labels_for_row, uncertain_labels_for_row
from repair_training.formats.zip.plugin import ZIP_FIELD_LABELS, ZIP_ZONE_LABELS


FORMAT = "zip"

THEORY_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("eocd.cd_offset", "eocd", "offset_field"),
    ("eocd.cd_size", "eocd", "size_field"),
    ("eocd.entry_count", "eocd", "count_field"),
    ("eocd.comment_length", "eocd", "size_field"),
    ("central_directory.span", "central_directory", "span"),
    ("central_directory.entry_count", "central_directory", "count_field"),
    ("central_directory.local_header_offset", "central_directory", "offset_field"),
    ("central_directory.flags", "central_directory", "flag_field"),
    ("central_directory.filename", "central_directory", "name_field"),
    ("central_directory.crc", "central_directory", "crc_field"),
    ("central_directory.compressed_size", "central_directory", "size_field"),
    ("local_header.signature", "local_header", "signature"),
    ("local_header.flags", "local_header", "flag_field"),
    ("local_header.filename", "local_header", "name_field"),
    ("local_header.crc", "local_header", "crc_field"),
    ("local_header.compressed_size", "local_header", "size_field"),
    ("payload.span", "payload", "span"),
    ("payload.crc_region", "payload", "crc_field"),
    ("payload.compressed_data", "payload", "payload"),
    ("data_descriptor.record", "data_descriptor", "record"),
    ("data_descriptor.crc", "data_descriptor", "crc_field"),
    ("data_descriptor.size", "data_descriptor", "size_field"),
    ("zip64.extra", "zip64", "extra_field"),
    ("zip64.extra_length", "zip64", "size_field"),
    ("zip64.uncompressed_size", "zip64", "size_field"),
    ("zip64.locator", "zip64", "locator"),
    ("zip64.eocd", "zip64", "eocd"),
    ("tail.trailing_bytes", "tail", "tail"),
    ("tail.comment", "tail", "comment"),
    ("sfx_prefix.bytes", "sfx_prefix", "prefix"),
    ("split_volume.missing_range", "split_volume", "missing_range"),
)

THEORY_FIELD_SET = {field for field, _, _ in THEORY_FIELDS}
ZONE_TO_THEORY = {
    zone: [field for field, field_zone, _ in THEORY_FIELDS if field_zone == zone]
    for zone in ZIP_ZONE_LABELS
}

THEORY_DEPENDENCIES: tuple[tuple[str, str, str], ...] = (
    ("eocd.cd_offset", "central_directory.span", "points_to"),
    ("eocd.cd_size", "central_directory.span", "owns_span"),
    ("eocd.entry_count", "central_directory.entry_count", "counts"),
    ("eocd.comment_length", "tail.comment", "bounds"),
    ("central_directory.local_header_offset", "local_header.signature", "points_to"),
    ("central_directory.flags", "local_header.flags", "matches_field"),
    ("central_directory.flags", "data_descriptor.record", "expects_descriptor"),
    ("central_directory.filename", "local_header.filename", "matches_field"),
    ("central_directory.crc", "local_header.crc", "matches_field"),
    ("central_directory.crc", "payload.crc_region", "validates"),
    ("central_directory.compressed_size", "local_header.compressed_size", "matches_field"),
    ("central_directory.compressed_size", "payload.span", "owns_span"),
    ("local_header.compressed_size", "payload.span", "owns_span"),
    ("data_descriptor.record", "payload.span", "describes_payload"),
    ("data_descriptor.crc", "central_directory.crc", "matches_field"),
    ("data_descriptor.size", "central_directory.compressed_size", "matches_field"),
    ("data_descriptor.size", "payload.span", "describes_payload"),
    ("zip64.extra", "central_directory.compressed_size", "overrides"),
    ("zip64.extra", "central_directory.local_header_offset", "overrides"),
    ("zip64.extra_length", "zip64.extra", "bounds"),
    ("zip64.uncompressed_size", "payload.span", "matches_payload"),
    ("zip64.locator", "zip64.eocd", "points_to"),
    ("tail.trailing_bytes", "eocd.comment_length", "bounds"),
    ("sfx_prefix.bytes", "eocd.cd_offset", "shifts_offset"),
    ("sfx_prefix.bytes", "central_directory.local_header_offset", "shifts_offset"),
    ("split_volume.missing_range", "payload.span", "removes_span"),
    ("split_volume.missing_range", "central_directory.local_header_offset", "propagates_to"),
)

THEORY_EDGE_BY_ENDPOINT: dict[tuple[str, str], str] = {
    (source, target): f"edge:theory_depends_on:{safe_node_token(f'theory:zip.{source}')}:{safe_node_token(f'theory:zip.{target}')}"
    for source, target, _relation in THEORY_DEPENDENCIES
}

FIELD_TO_THEORY_EDGES: dict[str, tuple[str, ...]] = {
    "central_directory.local_header_offset": (
        THEORY_EDGE_BY_ENDPOINT[("central_directory.local_header_offset", "local_header.signature")],
        THEORY_EDGE_BY_ENDPOINT[("sfx_prefix.bytes", "central_directory.local_header_offset")],
        THEORY_EDGE_BY_ENDPOINT[("zip64.extra", "central_directory.local_header_offset")],
    ),
    "central_directory.flags": (
        THEORY_EDGE_BY_ENDPOINT[("central_directory.flags", "local_header.flags")],
        THEORY_EDGE_BY_ENDPOINT[("central_directory.flags", "data_descriptor.record")],
    ),
    "central_directory.compressed_size": (
        THEORY_EDGE_BY_ENDPOINT[("central_directory.compressed_size", "local_header.compressed_size")],
        THEORY_EDGE_BY_ENDPOINT[("central_directory.compressed_size", "payload.span")],
        THEORY_EDGE_BY_ENDPOINT[("zip64.extra", "central_directory.compressed_size")],
    ),
    "central_directory.crc": (
        THEORY_EDGE_BY_ENDPOINT[("central_directory.crc", "local_header.crc")],
        THEORY_EDGE_BY_ENDPOINT[("central_directory.crc", "payload.crc_region")],
        THEORY_EDGE_BY_ENDPOINT[("data_descriptor.crc", "central_directory.crc")],
    ),
    "payload.crc_region": (
        THEORY_EDGE_BY_ENDPOINT[("central_directory.crc", "payload.crc_region")],
    ),
    "payload.compressed_data": (
        THEORY_EDGE_BY_ENDPOINT[("central_directory.compressed_size", "payload.span")],
        THEORY_EDGE_BY_ENDPOINT[("local_header.compressed_size", "payload.span")],
        THEORY_EDGE_BY_ENDPOINT[("data_descriptor.record", "payload.span")],
    ),
    "data_descriptor.record": (
        THEORY_EDGE_BY_ENDPOINT[("central_directory.flags", "data_descriptor.record")],
        THEORY_EDGE_BY_ENDPOINT[("data_descriptor.record", "payload.span")],
    ),
    "data_descriptor.size": (
        THEORY_EDGE_BY_ENDPOINT[("data_descriptor.size", "central_directory.compressed_size")],
        THEORY_EDGE_BY_ENDPOINT[("data_descriptor.size", "payload.span")],
    ),
    "zip64.extra": (
        THEORY_EDGE_BY_ENDPOINT[("zip64.extra", "central_directory.compressed_size")],
        THEORY_EDGE_BY_ENDPOINT[("zip64.extra", "central_directory.local_header_offset")],
    ),
    "zip64.extra_length": (
        THEORY_EDGE_BY_ENDPOINT[("zip64.extra_length", "zip64.extra")],
        THEORY_EDGE_BY_ENDPOINT[("zip64.extra", "central_directory.compressed_size")],
        THEORY_EDGE_BY_ENDPOINT[("zip64.extra", "central_directory.local_header_offset")],
    ),
    "zip64.uncompressed_size": (
        THEORY_EDGE_BY_ENDPOINT[("zip64.extra", "central_directory.compressed_size")],
        THEORY_EDGE_BY_ENDPOINT[("zip64.uncompressed_size", "payload.span")],
    ),
    "zip64.locator": (
        THEORY_EDGE_BY_ENDPOINT[("zip64.locator", "zip64.eocd")],
    ),
    "zip64.eocd": (
        THEORY_EDGE_BY_ENDPOINT[("zip64.locator", "zip64.eocd")],
        THEORY_EDGE_BY_ENDPOINT[("eocd.entry_count", "central_directory.entry_count")],
        THEORY_EDGE_BY_ENDPOINT[("eocd.cd_size", "central_directory.span")],
        THEORY_EDGE_BY_ENDPOINT[("eocd.cd_offset", "central_directory.span")],
    ),
    "tail.trailing_bytes": (
        THEORY_EDGE_BY_ENDPOINT[("tail.trailing_bytes", "eocd.comment_length")],
    ),
    "sfx_prefix.bytes": (
        THEORY_EDGE_BY_ENDPOINT[("sfx_prefix.bytes", "eocd.cd_offset")],
        THEORY_EDGE_BY_ENDPOINT[("sfx_prefix.bytes", "central_directory.local_header_offset")],
    ),
    "split_volume.missing_range": (
        THEORY_EDGE_BY_ENDPOINT[("split_volume.missing_range", "payload.span")],
        THEORY_EDGE_BY_ENDPOINT[("split_volume.missing_range", "central_directory.local_header_offset")],
    ),
}

PROFILE_ROOT_FIELD_OVERRIDES: dict[str, tuple[str, ...]] = {
    "zip_zip64_extra_size_mismatch": (
        "zip64.extra_length",
        "zip64.uncompressed_size",
    ),
    "compound_duplicate_descriptor_name_conflict": (
        "central_directory.flags",
        "data_descriptor.record",
    ),
    "compound_descriptor_fake_span_flags_cd_offset": (
        "central_directory.compressed_size",
        "central_directory.flags",
        "central_directory.local_header_offset",
        "data_descriptor.record",
    ),
}

PROPAGATED_SYMPTOM_FIELDS = {
    "central_directory.external_attributes",
}

SUMMARY_TO_THEORY = {
    "central_directory_offset_delta": ("eocd.cd_offset", "central_directory.span"),
    "central_directory_size_delta": ("eocd.cd_size", "central_directory.span"),
    "declared_central_directory_size": ("eocd.cd_size", "central_directory.span"),
    "eocd_cd_size_mismatch_count": ("eocd.cd_size", "central_directory.span"),
    "entry_count_delta": ("eocd.entry_count", "central_directory.entry_count"),
    "local_header_offset_violation_count": ("central_directory.local_header_offset",),
    "central_local_flags_mismatch_count": ("central_directory.flags", "local_header.flags"),
    "central_local_flags_relation_mismatch_count": ("central_directory.flags", "local_header.flags", "data_descriptor.record"),
    "central_directory_flags_likely_bad_count": ("central_directory.flags", "data_descriptor.record"),
    "local_header_flags_likely_bad_count": ("local_header.flags", "data_descriptor.record"),
    "flags_relation_ambiguous_count": ("central_directory.flags", "local_header.flags"),
    "central_local_name_mismatch_count": ("central_directory.filename", "local_header.filename"),
    "central_local_crc_mismatch_count": ("central_directory.crc", "local_header.crc", "payload.crc_region"),
    "central_local_compressed_size_mismatch_count": ("central_directory.compressed_size", "local_header.compressed_size", "payload.span"),
    "descriptor_conflict_count": ("data_descriptor.record", "data_descriptor.crc", "data_descriptor.size"),
    "bad_local_header_target_signature_count": ("central_directory.local_header_offset", "local_header.signature"),
    "local_header_offset_points_to_descriptor_or_payload_count": ("central_directory.local_header_offset", "data_descriptor.record", "payload.span"),
    "local_header_offset_points_outside_archive_count": ("central_directory.local_header_offset",),
    "descriptor_crc_cd_mismatch_count": ("data_descriptor.crc", "central_directory.crc"),
    "descriptor_crc_payload_mismatch_count": ("data_descriptor.crc", "payload.crc_region"),
    "descriptor_crc_likely_bad_count": ("data_descriptor.crc",),
    "descriptor_record_mismatch_count": ("data_descriptor.record",),
    "descriptor_size_mismatch_count": ("data_descriptor.size", "payload.span"),
    "central_directory_compressed_size_likely_bad_count": ("central_directory.compressed_size", "payload.span"),
    "span_conflict_count": ("payload.span",),
    "trailing_bytes_after_eocd": ("tail.trailing_bytes", "eocd.comment_length"),
    "sfx_prefix_len": ("sfx_prefix.bytes", "eocd.cd_offset", "central_directory.local_header_offset"),
    "zip64_extra_mismatch_count": ("zip64.extra", "zip64.extra_length", "zip64.uncompressed_size"),
    "zip64_extra_length_mismatch_count": ("zip64.extra_length", "zip64.extra"),
    "zip64_uncompressed_size_mismatch_count": ("zip64.uncompressed_size", "payload.span"),
    "zip64_extra_present_count": ("zip64.extra",),
    "zip64_locator_mismatch_count": ("zip64.locator", "zip64.eocd"),
    "zip64_eocd_mismatch_count": ("zip64.eocd", "central_directory.span", "central_directory.entry_count"),
    "zip64_eocd_field_mismatch_count": ("zip64.eocd", "central_directory.span", "central_directory.entry_count"),
    "zip64_locator_present": ("zip64.locator",),
    "zip64_eocd_present": ("zip64.eocd",),
    "split_volume_missing_range_evidence_count": ("split_volume.missing_range",),
}

OBSERVATION_PREFIXES = (
    ("format.zip.structure.graph.summary", "summary"),
    ("format.zip.structure.summary", "summary"),
    ("extraction.failure", "extraction_failure"),
    ("extraction.result", "extraction_result"),
    ("verification.summary", "verification_summary"),
    ("verification.coverage_breakdown", "verification_coverage"),
    ("analysis.summary", "analysis_summary"),
)


@dataclass(frozen=True)
class ZipDiagnosisGraphPlugin:
    format_name: str = FORMAT

    def build_theory_graph(self) -> GraphFragment:
        nodes = [
            _theory_node(field=field, zone=zone, node_type=node_type)
            for field, zone, node_type in THEORY_FIELDS
        ]
        edges = [
            _edge(
                "theory_depends_on",
                _theory_id(source),
                _theory_id(target),
                relation=relation,
            )
            for source, target, relation in THEORY_DEPENDENCIES
        ]
        edges.extend(_same_zone_edges(nodes))
        return GraphFragment(nodes=nodes, edges=edges)

    def build_observation_graph(self, knowledge_payload: dict[str, Any]) -> GraphFragment:
        nodes: list[DiagnosisNode] = []
        features = _zip_graph_features(knowledge_payload)
        for prefix, node_type in OBSERVATION_PREFIXES:
            payload = _nested_path(knowledge_payload, prefix)
            if isinstance(payload, dict):
                for path, value in _flatten_scalars(payload, prefix=prefix).items():
                    nodes.append(_observation_node(path, value, node_type=node_type))
        graph = _nested(knowledge_payload, "format", "zip", "structure", "graph") or {}
        for index, item in enumerate(_graph_violation_items(graph)):
            if isinstance(item, dict):
                nodes.append(_list_observation_node("format.zip.structure.graph.violations", index, item, node_type="violation"))
        for index, item in enumerate(graph.get("explanations") or []):
            if isinstance(item, dict):
                nodes.append(_list_observation_node("format.zip.structure.graph.explanations", index, item, node_type="explanation"))
        return GraphFragment(nodes=_dedupe_nodes(nodes), graph_features=features)

    def build_mapping_edges(self, knowledge_payload: dict[str, Any]) -> list[DiagnosisEdge]:
        edges: list[DiagnosisEdge] = []
        for prefix, _node_type in OBSERVATION_PREFIXES:
            payload = _nested_path(knowledge_payload, prefix)
            if not isinstance(payload, dict):
                continue
            for path in _flatten_scalars(payload, prefix=prefix):
                for theory_field in _theory_targets_for_observation(path):
                    edges.append(_edge("observes_theory", _obs_id(path), _theory_id(theory_field)))
                    edges.append(_edge("theory_explains_obs", _theory_id(theory_field), _obs_id(path)))
        graph = _nested(knowledge_payload, "format", "zip", "structure", "graph") or {}
        for index, item in enumerate(_graph_violation_items(graph)):
            if not isinstance(item, dict):
                continue
            obs_id = _list_obs_id("format.zip.structure.graph.violations", index, item)
            for theory_field in _theory_targets_for_violation(item):
                edges.append(_edge("observes_theory", obs_id, _theory_id(theory_field), evidence="violation"))
                edges.append(_edge("theory_explains_obs", _theory_id(theory_field), obs_id, evidence="violation"))
        for index, item in enumerate(graph.get("explanations") or []):
            if not isinstance(item, dict):
                continue
            obs_id = _list_obs_id("format.zip.structure.graph.explanations", index, item)
            for theory_field in _theory_targets_for_field(str(item.get("field") or "")):
                edges.append(_edge("observes_theory", obs_id, _theory_id(theory_field), evidence="explanation"))
                edges.append(_edge("theory_explains_obs", _theory_id(theory_field), obs_id, evidence="explanation"))
        return _dedupe_edges(edges)

    def build_cause_graph(self) -> GraphFragment:
        nodes: list[DiagnosisNode] = []
        edges: list[DiagnosisEdge] = []
        for zone in ZIP_ZONE_LABELS:
            label = f"zone:{zone}"
            nodes.append(_cause_node(label=label, zone=zone, node_type="zone_cause"))
            for field in ZONE_TO_THEORY.get(zone, []):
                edges.append(_edge("cause_affects_theory", _cause_id(label), _theory_id(field)))
                edges.append(_edge("theory_supports_cause", _theory_id(field), _cause_id(label)))
        for field in ZIP_FIELD_LABELS:
            label = f"field:{field}"
            zone = field.split(".", 1)[0]
            nodes.append(_cause_node(label=label, zone=zone, node_type="field_cause", field_path=field))
            for theory_field in _theory_targets_for_field(field):
                edges.append(_edge("cause_affects_theory", _cause_id(label), _theory_id(theory_field)))
                edges.append(_edge("theory_supports_cause", _theory_id(theory_field), _cause_id(label)))
        return GraphFragment(nodes=_dedupe_nodes(nodes), edges=_dedupe_edges(edges))

    def build_labels(self, row: dict[str, Any]) -> DiagnosisLabels:
        root_source_labels = oracle_damage_labels_for_row(row)
        observed_source_labels = damage_labels_for_row(row)
        all_field_labels = sorted(label for label in root_source_labels if label.startswith("field:"))
        all_zone_labels = sorted(label for label in root_source_labels if label.startswith("zone:"))
        observed_field_labels = sorted(label for label in observed_source_labels if label.startswith("field:"))
        observed_zone_labels = sorted(label for label in observed_source_labels if label.startswith("zone:"))
        uncertain = uncertain_labels_for_row(row)
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        field_labels, zone_labels, symptom_field_labels, symptom_zone_labels = _split_root_and_symptom_labels(
            damage_profile=str(metadata.get("damage_profile") or ""),
            field_labels=all_field_labels,
            zone_labels=all_zone_labels,
        )
        symptom_field_labels = sorted(set(symptom_field_labels).union(set(observed_field_labels) - set(field_labels)))
        symptom_zone_labels = sorted(set(symptom_zone_labels).union(set(observed_zone_labels) - set(zone_labels)))
        cause_node_ids = [_cause_id(label) for label in [*field_labels, *zone_labels] if _known_cause_label(label)]
        theory_node_ids: set[str] = set()
        for label in field_labels:
            for field in _theory_targets_for_field(field_from_label(label)):
                theory_node_ids.add(_theory_id(field))
        for label in zone_labels:
            for field in ZONE_TO_THEORY.get(label_zone(label), []):
                theory_node_ids.add(_theory_id(field))
        symptom_theory_node_ids: set[str] = set()
        for label in symptom_field_labels:
            for field in _theory_targets_for_field(field_from_label(label)):
                symptom_theory_node_ids.add(_theory_id(field))
        for label in symptom_zone_labels:
            for field in ZONE_TO_THEORY.get(label_zone(label), []):
                symptom_theory_node_ids.add(_theory_id(field))
        theory_edge_ids = set(_theory_edge_ids_for_labels(field_labels=field_labels, zone_labels=[]))
        symptom_theory_edge_ids = set(_theory_edge_ids_for_labels(field_labels=symptom_field_labels, zone_labels=[]))
        clean = not bool(all_field_labels or all_zone_labels)
        return DiagnosisLabels(
            cause_node_ids=sorted(set(cause_node_ids)),
            field_labels=field_labels,
            zone_labels=zone_labels,
            theory_node_ids=sorted(theory_node_ids),
            theory_edge_ids=sorted(theory_edge_ids),
            symptom_field_labels=symptom_field_labels,
            symptom_zone_labels=symptom_zone_labels,
            symptom_theory_node_ids=sorted(symptom_theory_node_ids),
            symptom_theory_edge_ids=sorted(symptom_theory_edge_ids),
            auxiliary={
                "clean": clean,
                "damage_profile": str(metadata.get("damage_profile") or ""),
                "uncertain_labels": sorted(set(uncertain)),
                "observed_field_labels": observed_field_labels,
                "observed_zone_labels": observed_zone_labels,
                "injected_cause": sorted(set([*field_labels, *zone_labels])),
            },
        )


def get_diagnosis_graph_plugin() -> ZipDiagnosisGraphPlugin:
    return ZipDiagnosisGraphPlugin()


def _theory_node(*, field: str, zone: str, node_type: str) -> DiagnosisNode:
    return DiagnosisNode(
        node_id=_theory_id(field),
        node_layer="theory",
        node_type=node_type,
        format=FORMAT,
        zone=zone,
        field_path=f"zip.{field}",
        features={
            "field": field,
            "field_kind": node_type,
            "is_structural": True,
        },
    )


def _cause_node(*, label: str, zone: str, node_type: str, field_path: str = "") -> DiagnosisNode:
    return DiagnosisNode(
        node_id=_cause_id(label),
        node_layer="cause",
        node_type=node_type,
        format=FORMAT,
        zone=zone,
        field_path=field_path,
        label=label,
        features={"repair_relevant": zone != "unknown"},
    )


def _observation_node(path: str, value: Any, *, node_type: str) -> DiagnosisNode:
    return DiagnosisNode(
        node_id=_obs_id(path),
        node_layer="observation",
        node_type=node_type,
        format=FORMAT,
        zone=_zone_for_path(path),
        field_path=path,
        features=_value_features(value),
    )


def _list_observation_node(prefix: str, index: int, item: dict[str, Any], *, node_type: str) -> DiagnosisNode:
    node_id = _list_obs_id(prefix, index, item)
    field = str(item.get("field") or "")
    relation_path = _relation_observation_path(prefix, index, item)
    return DiagnosisNode(
        node_id=node_id,
        node_layer="observation",
        node_type=node_type,
        format=FORMAT,
        zone=_zone_for_field(field) or _zone_for_path(str(item.get("kind") or "")),
        field_path=relation_path,
        features={
            "field": field,
            "source_field": str(item.get("source_field") or ""),
            "target_field": str(item.get("target_field") or ""),
            "relation": str(item.get("relation") or ""),
            "likely_bad_side": str(item.get("likely_bad_side") or ""),
            "target_kind": str(item.get("target_kind") or ""),
            "kind": str(item.get("kind") or ""),
            "severity": str(item.get("severity") or ""),
            "applies": bool(item.get("applies", False)),
            "valid": bool(item.get("valid", item.get("applies", False))),
            "delta": _float_or_none(item.get("delta")),
            "confidence": _float_or_none(item.get("confidence", item.get("evidence_confidence"))),
        },
    )


def _edge(edge_type: str, source: str, target: str, **features: Any) -> DiagnosisEdge:
    return DiagnosisEdge(
        edge_id=_edge_id(edge_type, source, target),
        edge_type=edge_type,
        source=source,
        target=target,
        features={key: value for key, value in features.items() if value not in (None, "")},
    )


def _same_zone_edges(nodes: list[DiagnosisNode]) -> list[DiagnosisEdge]:
    by_zone: dict[str, list[DiagnosisNode]] = {}
    for node in nodes:
        if node.zone:
            by_zone.setdefault(node.zone, []).append(node)
    edges: list[DiagnosisEdge] = []
    for zone, zone_nodes in by_zone.items():
        for left in zone_nodes:
            for right in zone_nodes:
                if left.node_id < right.node_id:
                    edges.append(_edge("same_zone", left.node_id, right.node_id, zone=zone))
    return edges


def _zip_graph_features(knowledge_payload: dict[str, Any]) -> dict[str, Any]:
    summary = _zip_summary(knowledge_payload)
    return {
        "file_size": _int(summary.get("file_size")),
        "entry_count": _int(summary.get("cd_entry_count")),
        "archive_readable": bool(summary.get("archive_readable", False)),
        "verification_completeness": _float_or_none(_nested(knowledge_payload, "verification", "summary", "completeness")),
        "verification_status": str(_nested(knowledge_payload, "verification", "summary", "assessment_status") or ""),
        "extraction_success": bool(_nested(knowledge_payload, "extraction", "result", "success")),
    }


def _zip_summary(knowledge_payload: dict[str, Any]) -> dict[str, Any]:
    return (
        _nested(knowledge_payload, "format", "zip", "structure", "graph", "summary")
        or _nested(knowledge_payload, "format", "zip", "structure", "summary")
        or {}
    )


def _theory_targets_for_observation(path: str) -> tuple[str, ...]:
    leaf = path.rsplit(".", 1)[-1]
    if leaf in SUMMARY_TO_THEORY:
        return SUMMARY_TO_THEORY[leaf]
    return _theory_targets_for_field(path)


def _theory_targets_for_field(field: str) -> tuple[str, ...]:
    text = str(field or "").lower().replace("zip.", "").replace("-", "_")
    aliases = {
        "central_directory.header": ("central_directory.span",),
        "central_directory.extra": ("zip64.extra",),
        "central_directory.extra_length": ("zip64.extra_length", "zip64.extra"),
        "central_directory.external_attributes": ("central_directory.entry_count",),
        "local_header.header": ("local_header.signature",),
        "local_header.extra": ("zip64.extra",),
        "local_header.extra_length": ("zip64.extra_length", "zip64.extra"),
        "data_descriptor.record": ("data_descriptor.record",),
        "payload.crc_region": ("payload.crc_region", "central_directory.crc"),
        "payload.compressed_data": ("payload.compressed_data", "payload.span"),
        "sfx_prefix.bytes": ("sfx_prefix.bytes", "eocd.cd_offset"),
        "split_volume.missing_range": ("split_volume.missing_range", "payload.span"),
    }
    if text in THEORY_FIELD_SET:
        return (text,)
    if text in aliases:
        return aliases[text]
    for field_name in THEORY_FIELD_SET:
        if field_name in text or text.endswith(field_name.rsplit(".", 1)[-1]):
            return (field_name,)
    zone = _zone_for_field(text)
    if zone:
        return tuple(ZONE_TO_THEORY.get(zone, ()))
    return ()


def _theory_targets_for_violation(item: dict[str, Any]) -> tuple[str, ...]:
    fields: list[str] = []
    for key in ("field", "source_field", "target_field", "likely_bad_side"):
        value = str(item.get(key) or "")
        if value and value != "ambiguous":
            fields.append(value)
    output: set[str] = set()
    for field in fields:
        output.update(_theory_targets_for_field(field))
    return tuple(sorted(output))


def _known_cause_label(label: str) -> bool:
    if label.startswith("zone:"):
        return label.split(":", 1)[1] in ZIP_ZONE_LABELS
    if label.startswith("field:"):
        return label.split(":", 1)[1] in ZIP_FIELD_LABELS
    return False


def zip_theory_id(field: str) -> str:
    return _theory_id(field)


def zip_cause_id(label: str) -> str:
    return _cause_id(label)


def zip_theory_dependency_edge_id(source_field: str, target_field: str) -> str:
    return THEORY_EDGE_BY_ENDPOINT.get((source_field, target_field), _edge_id("theory_depends_on", _theory_id(source_field), _theory_id(target_field)))


def zip_theory_edges_for_field(field: str) -> tuple[str, ...]:
    edge_ids: set[str] = set()
    for theory_field in _theory_targets_for_field(field):
        edge_ids.update(FIELD_TO_THEORY_EDGES.get(theory_field, ()))
        for source, target, _relation in THEORY_DEPENDENCIES:
            if theory_field in {source, target}:
                edge_ids.add(THEORY_EDGE_BY_ENDPOINT[(source, target)])
    return tuple(sorted(edge_ids))


def zip_theory_edges_for_zone(zone: str) -> tuple[str, ...]:
    edge_ids: set[str] = set()
    for field in ZONE_TO_THEORY.get(zone, ()):
        edge_ids.update(zip_theory_edges_for_field(field))
    return tuple(sorted(edge_ids))


def _theory_edge_ids_for_labels(*, field_labels: list[str], zone_labels: list[str]) -> tuple[str, ...]:
    edge_ids: set[str] = set()
    for label in field_labels:
        edge_ids.update(zip_theory_edges_for_field(field_from_label(label)))
    for label in zone_labels:
        root_fields = [field for field in ZONE_TO_THEORY.get(label_zone(label), ()) if f"field:{field}" in field_labels]
        for field in root_fields:
            edge_ids.update(zip_theory_edges_for_field(field))
    return tuple(sorted(edge_ids))


def _split_root_and_symptom_labels(
    *,
    damage_profile: str,
    field_labels: list[str],
    zone_labels: list[str],
) -> tuple[list[str], list[str], list[str], list[str]]:
    observed_fields = {field_from_label(label) for label in field_labels}
    override = PROFILE_ROOT_FIELD_OVERRIDES.get(damage_profile)
    if override:
        root_fields = {field for field in override if field in observed_fields}
    else:
        root_fields = {field for field in observed_fields if field not in PROPAGATED_SYMPTOM_FIELDS}
    symptom_fields = observed_fields - root_fields
    root_zones = {_zone_for_field(field) for field in root_fields if _zone_for_field(field)}
    observed_zones = {label_zone(label) for label in zone_labels}
    symptom_zones = observed_zones - root_zones
    root_field_labels = sorted(f"field:{field}" for field in root_fields if f"field:{field}" in field_labels)
    root_zone_labels = sorted(f"zone:{zone}" for zone in root_zones if f"zone:{zone}" in zone_labels)
    symptom_field_labels = sorted(f"field:{field}" for field in symptom_fields if f"field:{field}" in field_labels)
    symptom_zone_labels = sorted(f"zone:{zone}" for zone in symptom_zones if f"zone:{zone}" in zone_labels)
    return root_field_labels, root_zone_labels, symptom_field_labels, symptom_zone_labels


def _edge_id(edge_type: str, source: str, target: str) -> str:
    return f"edge:{edge_type}:{safe_node_token(source)}:{safe_node_token(target)}"


def _theory_id(field: str) -> str:
    return f"theory:zip.{field}"


def _cause_id(label: str) -> str:
    return f"cause:{label}"


def _obs_id(path: str) -> str:
    return f"obs:{safe_node_token(path)}"


def _list_obs_id(prefix: str, index: int, item: dict[str, Any]) -> str:
    token = safe_node_token(
        f"{prefix}.{index}."
        f"{item.get('kind') or 'item'}."
        f"{item.get('field') or ''}."
        f"{item.get('source_field') or ''}."
        f"{item.get('target_field') or ''}."
        f"{item.get('likely_bad_side') or ''}"
    )
    return f"obs:{token}"


def _graph_violation_items(graph: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in [*(graph.get("violations") or []), *(graph.get("relation_violations") or [])]:
        if not isinstance(item, dict):
            continue
        key = (
            item.get("kind"),
            item.get("field"),
            item.get("source_field"),
            item.get("target_field"),
            item.get("entry_index"),
            item.get("likely_bad_side"),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _relation_observation_path(prefix: str, index: int, item: dict[str, Any]) -> str:
    kind = str(item.get("kind") or "item")
    source = str(item.get("source_field") or "")
    target = str(item.get("target_field") or "")
    likely = str(item.get("likely_bad_side") or "")
    field = str(item.get("field") or "")
    if source or target or likely:
        return f"{prefix}[{index}].{kind}.{source}->{target}.likely:{likely or field}"
    return f"{prefix}[{index}].{field or kind}"


def _zone_for_path(path: str) -> str:
    text = str(path or "").lower()
    for zone in ZIP_ZONE_LABELS:
        if zone in text or zone.replace("_", ".") in text:
            return zone
    if "descriptor" in text:
        return "data_descriptor"
    if "crc" in text:
        return "payload"
    if "filename" in text or "name" in text:
        return "central_directory"
    return "unknown"


def _zone_for_field(field: str) -> str:
    text = str(field or "").lower().replace("zip.", "")
    if not text:
        return ""
    zone = text.split(".", 1)[0]
    if zone in ZIP_ZONE_LABELS:
        return zone
    if zone == "data":
        return "data_descriptor"
    if "descriptor" in text:
        return "data_descriptor"
    return zone if zone in ZIP_ZONE_LABELS else ""


def _value_features(value: Any) -> dict[str, Any]:
    features: dict[str, Any] = {"present": value is not None}
    if isinstance(value, bool):
        features["value_bool"] = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        features["value_numeric"] = float(value)
    else:
        text = str(value)
        features["value_category"] = text[:96]
        features["value_length"] = len(text)
    return features


def _flatten_scalars(value: Any, *, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            output.update(_flatten_scalars(item, prefix=child))
        return output
    if isinstance(value, (list, tuple, set)):
        output[f"{prefix}.count"] = len(value)
        return output
    if value is not None:
        output[prefix] = value
    return output


def _nested_path(value: Any, path: str) -> Any:
    cur = value
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
            continue
        return None
    return cur


def _nested(value: Any, *path: str) -> Any:
    cur = value
    for part in path:
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
            continue
        return None
    return cur


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _dedupe_nodes(nodes: list[DiagnosisNode]) -> list[DiagnosisNode]:
    output: dict[str, DiagnosisNode] = {}
    for node in nodes:
        output.setdefault(node.node_id, node)
    return sorted(output.values(), key=lambda item: (item.node_layer, item.node_id))


def _dedupe_edges(edges: list[DiagnosisEdge]) -> list[DiagnosisEdge]:
    output: dict[str, DiagnosisEdge] = {}
    for edge in edges:
        output.setdefault(edge.edge_id, edge)
    return sorted(output.values(), key=lambda item: (item.edge_type, item.source, item.target, item.edge_id))
