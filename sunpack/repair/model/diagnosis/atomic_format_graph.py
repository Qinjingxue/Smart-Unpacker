from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any

from sunpack.repair.model.diagnosis.graph_schema import (
    DiagnosisEdge,
    DiagnosisLabels,
    DiagnosisNode,
    GraphFragment,
)


@dataclass(frozen=True)
class AtomicFormatGraphDefinition:
    format_name: str
    flag_zones: dict[str, str]

    @property
    def zones(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.flag_zones.values())))


DEFINITIONS: dict[str, AtomicFormatGraphDefinition] = {
    "rar": AtomicFormatGraphDefinition("rar", {
        "rar_main_header_crc_bad": "main_header", "rar_file_header_crc_bad": "file_header",
        "rar_service_header_crc_bad": "service_header", "rar_end_header_crc_bad": "end_header",
        "missing_end_block": "boundary", "trailing_junk": "boundary", "carrier_prefix": "boundary",
        "rar_file_block_bad": "file_block", "rar_service_block_bad": "service_block",
    }),
    "tar": AtomicFormatGraphDefinition("tar", {
        "tar_checksum_bad": "member_header", "pax_header_bad": "pax_metadata",
        "gnu_longname_bad": "gnu_metadata", "sparse_header_bad": "sparse_metadata",
        "missing_end_block": "boundary", "trailing_junk": "boundary", "probably_truncated": "payload",
    }),
    "gzip": AtomicFormatGraphDefinition("gzip", {
        "gzip_header_crc_bad": "header", "gzip_reserved_flags_set": "header",
        "gzip_footer_bad": "footer", "trailing_junk": "boundary",
        "probably_truncated": "payload", "deflate_resync": "payload",
    }),
    "bzip2": AtomicFormatGraphDefinition("bzip2", {
        "bzip2_block_size_bad": "header", "trailing_junk": "boundary",
        "probably_truncated": "payload", "bzip2_block_bad": "block",
    }),
    "xz": AtomicFormatGraphDefinition("xz", {
        "xz_header_crc_bad": "header", "xz_footer_crc_bad": "footer",
        "trailing_junk": "boundary", "probably_truncated": "payload", "xz_block_bad": "block",
    }),
    "zstd": AtomicFormatGraphDefinition("zstd", {
        "zstd_frame_bad": "frame", "trailing_junk": "boundary",
        "probably_truncated": "frame", "zstd_multiframe_damage": "frame",
    }),
}


class AtomicFormatDiagnosisGraphPlugin:
    def __init__(self, definition: AtomicFormatGraphDefinition):
        self.definition = definition
        self.format_name = definition.format_name

    def build_theory_graph(self) -> GraphFragment:
        return GraphFragment(nodes=[DiagnosisNode(
            node_id=self._theory(flag), node_layer="theory", node_type=f"{self.format_name}_constraint",
            format=self.format_name, zone=zone, field_path=f"format.{self.format_name}.{flag}", label=flag,
        ) for flag, zone in sorted(self.definition.flag_zones.items())])

    def build_observation_graph(self, knowledge_payload: dict[str, Any]) -> GraphFragment:
        flags = self._flags(knowledge_payload)
        nodes = [DiagnosisNode(
            node_id=self._observation(flag), node_layer="observation", node_type="damage_flag",
            format=self.format_name, zone=self.definition.flag_zones.get(flag, "archive"),
            field_path=f"damage_flags.{flag}", label=flag,
            features={"present": True, "value_bool": True, "confidence": 1.0},
        ) for flag in flags]
        format_payload = self._format_payload(knowledge_payload)
        for path, value in list(_flatten(format_payload).items())[:256]:
            nodes.append(DiagnosisNode(
                node_id=self._observation(path), node_layer="observation",
                node_type=f"{self.format_name}_observation", format=self.format_name,
                zone=_zone_for_path(path, self.definition), field_path=f"format.{self.format_name}.{path}",
                label=path, features=_value_features(value),
            ))
        return GraphFragment(nodes=_dedupe(nodes), graph_features={"format": self.format_name})

    def build_mapping_edges(self, knowledge_payload: dict[str, Any]) -> list[DiagnosisEdge]:
        edges: list[DiagnosisEdge] = []
        for flag in self._flags(knowledge_payload):
            if flag not in self.definition.flag_zones:
                continue
            edges.extend((self._edge("observes_theory", self._observation(flag), self._theory(flag)),
                          self._edge("theory_explains_obs", self._theory(flag), self._observation(flag))))
        return edges

    def build_cause_graph(self) -> GraphFragment:
        nodes = [DiagnosisNode(
            node_id=self._cause(zone), node_layer="cause", node_type=f"{self.format_name}_damage_family",
            format=self.format_name, zone=zone, label=zone,
        ) for zone in self.definition.zones]
        edges = [self._edge("cause_affects_theory", self._cause(zone), self._theory(flag))
                 for flag, zone in sorted(self.definition.flag_zones.items())]
        return GraphFragment(nodes=nodes, edges=edges)

    def build_labels(self, row: dict[str, Any]) -> DiagnosisLabels:
        payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else row
        flags = [flag for flag in self._flags({**payload, **row}) if flag in self.definition.flag_zones]
        zones = sorted({self.definition.flag_zones[flag] for flag in flags})
        return DiagnosisLabels(
            root_case_labels=flags, cause_node_ids=[self._cause(zone) for zone in zones],
            field_labels=[f"format.{self.format_name}.{flag}" for flag in flags], zone_labels=zones,
            theory_node_ids=[self._theory(flag) for flag in flags],
        )

    def _flags(self, payload: dict[str, Any]) -> list[str]:
        values: list[Any] = []
        for key in ("damage_flags", "runtime_damage_flags"):
            values.extend(payload.get(key) or [])
        flags_payload = payload.get("flags") if isinstance(payload.get("flags"), dict) else {}
        values.extend(flags_payload.get("repair.damage") or [])
        target = payload.get("damage_analysis_target") if isinstance(payload.get("damage_analysis_target"), dict) else {}
        values.extend(target.get("route_hints") or [])
        for label in target.get("labels") or []:
            if isinstance(label, dict):
                values.append(label.get("zone", {}).get("path") if isinstance(label.get("zone"), dict) else "")
        return sorted({str(value) for value in values if str(value) in self.definition.flag_zones})

    def _format_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        formats = payload.get("format") if isinstance(payload.get("format"), dict) else {}
        value = formats.get(self.format_name)
        return value if isinstance(value, dict) else {}

    def _theory(self, value: str) -> str: return f"theory:{self.format_name}:{value}"
    def _observation(self, value: str) -> str: return f"obs:{self.format_name}:{_token(value)}"
    def _cause(self, value: str) -> str: return f"cause:{self.format_name}:{value}"
    def _edge(self, edge_type: str, source: str, target: str) -> DiagnosisEdge:
        return DiagnosisEdge(edge_id=f"edge:{edge_type}:{_token(source + '|' + target)}", edge_type=edge_type, source=source, target=target)


def get_atomic_format_graph_plugin(format_name: str) -> AtomicFormatDiagnosisGraphPlugin:
    return AtomicFormatDiagnosisGraphPlugin(DEFINITIONS[format_name])


def _token(value: str) -> str:
    return hashlib.sha1(str(value).encode("utf-8")).hexdigest()[:16]


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            output.update(_flatten(item, f"{prefix}.{key}" if prefix else str(key)))
        return output
    if isinstance(value, list):
        return {f"{prefix}.count": len(value)}
    return {prefix: value} if prefix else {}


def _value_features(value: Any) -> dict[str, Any]:
    if isinstance(value, bool): return {"value_bool": value, "present": True}
    if isinstance(value, (int, float)): return {"value_numeric": float(value), "present": True}
    return {"value_hash": _token(str(value)), "present": value is not None}


def _zone_for_path(path: str, definition: AtomicFormatGraphDefinition) -> str:
    return next((zone for flag, zone in definition.flag_zones.items() if flag in path), "archive")


def _dedupe(nodes: list[DiagnosisNode]) -> list[DiagnosisNode]:
    return list({node.node_id: node for node in nodes}.values())
