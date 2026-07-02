from __future__ import annotations

from typing import Any

from sunpack.repair.model.diagnosis.graph_labels import safe_node_token
from sunpack.repair.model.diagnosis.graph_schema import (
    DiagnosisEdge,
    DiagnosisLabels,
    DiagnosisNode,
    GraphFragment,
)


FORMAT = "7z"

# Format-private vocabulary.  It is deliberately not merged with ZIP fields.
SEVEN_ZIP_THEORY_FLAGS = (
    "trailing_junk",
    "carrier_prefix",
    "start_header_crc_bad",
    "signature_header_version_bad",
    "next_header_crc_bad",
    "next_header_offset_bad",
    "next_header_size_bad",
    "next_header_repoint_possible",
    "encoded_header_present",
    "encoded_header_stream_crc_bad",
    "encoded_header_coder_properties_bad",
    "pack_stream_offset_bad",
    "pack_stream_size_bad",
    "stream_crc_bad",
    "stream_crc_defined_flag_bad",
    "bad_folder_detected",
    "folder_bind_pairs_bad",
    "folder_stream_counts_bad",
    "unreferenced_folder",
    "empty_stream_flags_bad",
    "unpack_size_bad",
    "file_count_metadata_bad",
    "file_names_utf16_bad",
    "unreferenced_file_record",
    "packed_stream_bad",
    "solid_archive",
    "non_solid_archive",
    "partial_recovery_possible",
    "password_required",
    "wrong_password",
    "split_sidecars_available",
)

CAUSES = ("boundary", "header", "stream", "folder_graph", "file_table", "authentication", "multipart")


class SevenZipDiagnosisGraphPlugin:
    format_name = FORMAT

    def build_theory_graph(self) -> GraphFragment:
        nodes = [
            DiagnosisNode(
                node_id=_theory_id(flag),
                node_layer="theory",
                node_type="seven_zip_constraint",
                format=FORMAT,
                zone=_zone(flag),
                field_path=f"format.7z.{flag}",
                label=flag,
            )
            for flag in SEVEN_ZIP_THEORY_FLAGS
        ]
        return GraphFragment(nodes=nodes)

    def build_observation_graph(self, knowledge_payload: dict[str, Any]) -> GraphFragment:
        flags = _damage_flags(knowledge_payload)
        nodes = [
            DiagnosisNode(
                node_id=_observation_id(f"damage_flags.{flag}"),
                node_layer="observation",
                node_type="damage_flag",
                format=FORMAT,
                zone=_zone(flag),
                field_path=f"damage_flags.{flag}",
                label=flag,
                features={"present": True, "value_bool": True, "confidence": 1.0},
            )
            for flag in flags
        ]
        for path, value in list(_flatten(knowledge_payload).items())[:512]:
            if not _relevant_path(path):
                continue
            nodes.append(DiagnosisNode(
                node_id=_observation_id(path),
                node_layer="observation",
                node_type="seven_zip_observation",
                format=FORMAT,
                zone=_zone(path),
                field_path=path,
                label=path,
                features=_value_features(value),
            ))
        return GraphFragment(nodes=_dedupe_nodes(nodes), graph_features={"format": FORMAT})

    def build_mapping_edges(self, knowledge_payload: dict[str, Any]) -> list[DiagnosisEdge]:
        edges = []
        for flag in _damage_flags(knowledge_payload):
            if flag not in SEVEN_ZIP_THEORY_FLAGS:
                continue
            source = _observation_id(f"damage_flags.{flag}")
            target = _theory_id(flag)
            edges.extend((
                _edge("observes_theory", source, target),
                _edge("theory_explains_obs", target, source),
            ))
        return edges

    def build_cause_graph(self) -> GraphFragment:
        nodes = [
            DiagnosisNode(
                node_id=_cause_id(cause),
                node_layer="cause",
                node_type="seven_zip_damage_family",
                format=FORMAT,
                zone=cause,
                label=cause,
            )
            for cause in CAUSES
        ]
        edges = [
            _edge("cause_affects_theory", _cause_id(_zone(flag)), _theory_id(flag))
            for flag in SEVEN_ZIP_THEORY_FLAGS
            if _zone(flag) in CAUSES
        ]
        return GraphFragment(nodes=nodes, edges=edges)

    def build_labels(self, row: dict[str, Any]) -> DiagnosisLabels:
        payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else row
        flags = [flag for flag in _damage_flags({**payload, **row}) if flag in SEVEN_ZIP_THEORY_FLAGS]
        causes = sorted({_zone(flag) for flag in flags if _zone(flag) in CAUSES})
        return DiagnosisLabels(
            root_case_labels=flags,
            cause_node_ids=[_cause_id(cause) for cause in causes],
            field_labels=[f"format.7z.{flag}" for flag in flags],
            zone_labels=causes,
            theory_node_ids=[_theory_id(flag) for flag in flags],
        )


def _damage_flags(payload: dict[str, Any]) -> list[str]:
    values = []
    for key in ("damage_flags", "runtime_damage_flags"):
        raw = payload.get(key)
        if isinstance(raw, (list, tuple, set)):
            values.extend(str(item) for item in raw if str(item))
    nested = payload.get("repair") if isinstance(payload.get("repair"), dict) else {}
    if isinstance(nested.get("damage_flags"), list):
        values.extend(str(item) for item in nested["damage_flags"] if str(item))
    return sorted(set(values))


def _zone(value: str) -> str:
    text = str(value).lower()
    if any(token in text for token in ("password", "encrypt")):
        return "authentication"
    if any(token in text for token in ("split", "volume", "sidecar")):
        return "multipart"
    if any(token in text for token in ("folder", "coder", "bind")):
        return "folder_graph"
    if any(token in text for token in ("file", "empty_stream", "unreferenced_file")):
        return "file_table"
    if any(token in text for token in ("pack", "stream", "unpack", "solid")):
        return "stream"
    if any(token in text for token in ("header", "signature")):
        return "header"
    return "boundary"


def _relevant_path(path: str) -> bool:
    return path.startswith(("format.7z.", "format.seven_zip.", "seven_zip_", "analysis.", "extraction.", "verification."))


def _flatten(value: Any, *, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            output.update(_flatten(item, prefix=path))
        return output
    if isinstance(value, list):
        return {f"{prefix}.count": len(value)}
    return {prefix: value} if prefix else {}


def _value_features(value: Any) -> dict[str, Any]:
    return {
        "present": value is not None,
        "value_bool": value if isinstance(value, bool) else None,
        "value_numeric": float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0,
        "confidence": 1.0,
    }


def _theory_id(flag: str) -> str:
    return f"theory:7z:{safe_node_token(flag)}"


def _observation_id(path: str) -> str:
    return f"observation:7z:{safe_node_token(path)}"


def _cause_id(cause: str) -> str:
    return f"cause:7z:{safe_node_token(cause)}"


def _edge(edge_type: str, source: str, target: str) -> DiagnosisEdge:
    return DiagnosisEdge(
        edge_id=f"edge:{edge_type}:{safe_node_token(source)}:{safe_node_token(target)}",
        edge_type=edge_type,
        source=source,
        target=target,
    )


def _dedupe_nodes(nodes: list[DiagnosisNode]) -> list[DiagnosisNode]:
    return list({node.node_id: node for node in nodes}.values())
