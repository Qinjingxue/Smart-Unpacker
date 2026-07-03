from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Any

from sunpack.repair.model.diagnosis.graph_schema import (
    DiagnosisEdge,
    DiagnosisLabels,
    DiagnosisNode,
    GraphFragment,
)


@dataclass(frozen=True)
class SemanticField:
    path: str
    zone: str
    node_type: str
    observation_aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class SemanticDependency:
    source: str
    target: str
    relation: str


@dataclass(frozen=True)
class SemanticFormatGraphDefinition:
    format_name: str
    specification: str
    fields: tuple[SemanticField, ...]
    dependencies: tuple[SemanticDependency, ...]
    flag_roots: dict[str, tuple[str, ...]]
    payload_keys: tuple[str, ...] = ()
    _field_by_path: dict[str, SemanticField] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        field_by_path = {item.path: item for item in self.fields}
        if len(field_by_path) != len(self.fields):
            raise ValueError(f"duplicate semantic field in {self.format_name}")
        for dependency in self.dependencies:
            if dependency.source not in field_by_path or dependency.target not in field_by_path:
                raise ValueError(
                    f"unknown semantic dependency endpoint in {self.format_name}: "
                    f"{dependency.source} -> {dependency.target}"
                )
        for flag, roots in self.flag_roots.items():
            missing = [root for root in roots if root not in field_by_path]
            if missing:
                raise ValueError(f"unknown roots for {self.format_name}:{flag}: {missing}")
        object.__setattr__(self, "_field_by_path", field_by_path)

    @property
    def zones(self) -> tuple[str, ...]:
        return tuple(sorted({item.zone for item in self.fields}))

    @property
    def flag_zones(self) -> dict[str, str]:
        """Compatibility projection used by training-material generators."""
        output: dict[str, str] = {}
        for flag, roots in self.flag_roots.items():
            zones = {self.field(root).zone for root in roots}
            output[flag] = sorted(zones)[0] if len(zones) == 1 else "archive"
        return output

    def field(self, path: str) -> SemanticField:
        return self._field_by_path[path]


class SemanticFormatDiagnosisGraphPlugin:
    """Build a format-private semantic graph behind the shared diagnosis graph protocol."""

    def __init__(self, definition: SemanticFormatGraphDefinition):
        self.definition = definition
        self.format_name = definition.format_name

    def build_theory_graph(self) -> GraphFragment:
        nodes = [
            DiagnosisNode(
                node_id=self._theory(item.path),
                node_layer="theory",
                node_type=item.node_type,
                format=self.format_name,
                zone=item.zone,
                field_path=self._field_label(item.path),
                label=item.path,
            )
            for item in self.definition.fields
        ]
        edges = [
            self._edge(
                "theory_depends_on",
                self._theory(item.source),
                self._theory(item.target),
                relation=item.relation,
            )
            for item in self.definition.dependencies
        ]
        return GraphFragment(
            nodes=nodes,
            edges=edges,
            graph_features={
                "format": self.format_name,
                "specification": self.definition.specification,
                "semantic_graph": True,
            },
        )

    def build_observation_graph(self, knowledge_payload: dict[str, Any]) -> GraphFragment:
        nodes: list[DiagnosisNode] = []
        for flag in self._flags(knowledge_payload):
            roots = self.definition.flag_roots.get(flag)
            if not roots:
                continue
            zones = {self.definition.field(root).zone for root in roots}
            nodes.append(DiagnosisNode(
                node_id=self._flag_observation(flag),
                node_layer="observation",
                node_type=f"{self.format_name}_damage_flag",
                format=self.format_name,
                zone=sorted(zones)[0] if len(zones) == 1 else "archive",
                field_path=f"damage_flags.{flag}",
                label=flag,
                features={"present": True, "value_bool": True, "confidence": 1.0},
            ))

        for path, value in list(self._observations(knowledge_payload).items())[:512]:
            targets = self._theory_targets(path)
            zones = {self.definition.field(target).zone for target in targets}
            nodes.append(DiagnosisNode(
                node_id=self._observation(path),
                node_layer="observation",
                node_type=f"{self.format_name}_observation",
                format=self.format_name,
                zone=sorted(zones)[0] if len(zones) == 1 else "archive",
                field_path=f"format.{self.format_name}.{path}",
                label=path,
                features=_value_features(value),
            ))
        return GraphFragment(nodes=_dedupe_nodes(nodes), graph_features={"format": self.format_name})

    def build_mapping_edges(self, knowledge_payload: dict[str, Any]) -> list[DiagnosisEdge]:
        edges: list[DiagnosisEdge] = []
        for flag in self._flags(knowledge_payload):
            for root in self.definition.flag_roots.get(flag, ()):
                edges.extend((
                    self._edge("observes_theory", self._flag_observation(flag), self._theory(root), evidence="damage_flag"),
                    self._edge("theory_explains_obs", self._theory(root), self._flag_observation(flag), evidence="damage_flag"),
                ))
        for path in self._observations(knowledge_payload):
            for target in self._theory_targets(path):
                edges.extend((
                    self._edge("observes_theory", self._observation(path), self._theory(target), evidence="field"),
                    self._edge("theory_explains_obs", self._theory(target), self._observation(path), evidence="field"),
                ))
        return _dedupe_edges(edges)

    def build_cause_graph(self) -> GraphFragment:
        nodes = [
            DiagnosisNode(
                node_id=self._cause(zone),
                node_layer="cause",
                node_type=f"{self.format_name}_damage_zone",
                format=self.format_name,
                zone=zone,
                label=zone,
            )
            for zone in self.definition.zones
        ]
        edges = [
            self._edge("cause_affects_theory", self._cause(item.zone), self._theory(item.path))
            for item in self.definition.fields
        ]
        return GraphFragment(nodes=nodes, edges=edges)

    def build_labels(self, row: dict[str, Any]) -> DiagnosisLabels:
        payload = row.get("knowledge_payload") if isinstance(row.get("knowledge_payload"), dict) else row
        # Read both scopes independently. A scalar row["format"] must not
        # overwrite the structured knowledge_payload["format"] mapping.
        flags = sorted({
            flag
            for source in (payload, row)
            for flag in self._flags(source)
            if flag in self.definition.flag_roots
        })
        roots = sorted({root for flag in flags for root in self.definition.flag_roots[flag]})
        root_set = set(roots)
        relevant_edges = [
            item for item in self.definition.dependencies
            if item.source in root_set or item.target in root_set
        ]
        symptoms = sorted({
            endpoint
            for item in relevant_edges
            for endpoint in (item.source, item.target)
            if endpoint not in root_set
        })
        return DiagnosisLabels(
            root_case_labels=sorted(flags),
            cause_node_ids=sorted({self._cause(self.definition.field(root).zone) for root in roots}),
            field_labels=[self._field_label(root) for root in roots],
            zone_labels=sorted({self.definition.field(root).zone for root in roots}),
            theory_node_ids=[self._theory(root) for root in roots],
            theory_edge_ids=[self._dependency_edge_id(item) for item in relevant_edges],
            symptom_field_labels=[self._field_label(item) for item in symptoms],
            symptom_zone_labels=sorted({self.definition.field(item).zone for item in symptoms}),
            symptom_theory_node_ids=[self._theory(item) for item in symptoms],
            symptom_theory_edge_ids=[self._dependency_edge_id(item) for item in relevant_edges],
            auxiliary={
                "format": self.format_name,
                "specification": self.definition.specification,
            },
        )

    def _observations(self, payload: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        format_payload = payload.get("format") if isinstance(payload.get("format"), dict) else {}
        direct = format_payload.get(self.format_name)
        if isinstance(direct, dict):
            merged.update(_flatten(direct))
        for key in self.definition.payload_keys:
            value = payload.get(key)
            if isinstance(value, dict):
                merged.update(_flatten(value))
        analysis = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else {}
        details = analysis.get("details") if isinstance(analysis.get("details"), dict) else {}
        if str(details.get("format") or "") == self.format_name:
            merged.update(_flatten(details))
        return dict(sorted(merged.items()))

    def _theory_targets(self, observation_path: str) -> tuple[str, ...]:
        normalized = _normalize_path(observation_path)
        scored: list[tuple[int, str]] = []
        for item in self.definition.fields:
            aliases = (item.path, *item.observation_aliases)
            score = max((_alias_score(normalized, _normalize_path(alias)) for alias in aliases), default=0)
            if score:
                scored.append((score, item.path))
        if not scored:
            return ()
        best = max(score for score, _ in scored)
        return tuple(sorted(path for score, path in scored if score == best))

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
                zone = label.get("zone") if isinstance(label.get("zone"), dict) else {}
                values.extend((label.get("label"), zone.get("path")))
        format_payload = payload.get("format") if isinstance(payload.get("format"), dict) else {}
        private_payload = format_payload.get(self.format_name)
        if isinstance(private_payload, dict):
            values.extend(_named_flag_values(private_payload))
        return sorted({str(value) for value in values if str(value) in self.definition.flag_roots})

    def _field_label(self, path: str) -> str:
        return f"format.{self.format_name}.{path}"

    def _theory(self, path: str) -> str:
        return f"theory:{self.format_name}:{path}"

    def _observation(self, path: str) -> str:
        return f"obs:{self.format_name}:field:{_token(path)}"

    def _flag_observation(self, flag: str) -> str:
        return f"obs:{self.format_name}:flag:{_token(flag)}"

    def _cause(self, zone: str) -> str:
        return f"cause:{self.format_name}:{zone}"

    def _dependency_edge_id(self, item: SemanticDependency) -> str:
        return self._edge_id("theory_depends_on", self._theory(item.source), self._theory(item.target))

    def _edge_id(self, edge_type: str, source: str, target: str) -> str:
        return f"edge:{edge_type}:{_token(source + '|' + target)}"

    def _edge(self, edge_type: str, source: str, target: str, **features: Any) -> DiagnosisEdge:
        return DiagnosisEdge(
            edge_id=self._edge_id(edge_type, source, target),
            edge_type=edge_type,
            source=source,
            target=target,
            features={key: value for key, value in features.items() if value not in (None, "")},
        )


def field(path: str, zone: str, node_type: str, *aliases: str) -> SemanticField:
    return SemanticField(path=path, zone=zone, node_type=node_type, observation_aliases=tuple(aliases))


def dependency(source: str, target: str, relation: str) -> SemanticDependency:
    return SemanticDependency(source=source, target=target, relation=relation)


def _token(value: str) -> str:
    return hashlib.sha1(str(value).encode("utf-8")).hexdigest()[:16]


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            output.update(_flatten(item, f"{prefix}.{key}" if prefix else str(key)))
        return output
    if isinstance(value, list):
        output = {f"{prefix}.count": len(value)}
        for index, item in enumerate(value[:64]):
            output.update(_flatten(item, f"{prefix}.{index}"))
        return output
    return {prefix: value} if prefix else {}


def _normalize_path(value: str) -> str:
    return ".".join(part for part in str(value or "").lower().replace("-", "_").split(".") if part)


def _alias_score(path: str, alias: str) -> int:
    if not path or not alias:
        return 0
    if path == alias:
        return 1000 + len(alias)
    if path.endswith(f".{alias}") or alias.endswith(f".{path}"):
        return 700 + min(len(path), len(alias))
    path_parts = set(path.split("."))
    alias_parts = set(alias.split("."))
    overlap = len(path_parts & alias_parts)
    return overlap * 10 if overlap >= 2 else 0


def _value_features(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"value_bool": value, "present": True}
    if isinstance(value, (int, float)):
        return {"value_numeric": float(value), "present": True}
    return {"value_hash": _token(str(value)), "present": value is not None}


def _named_flag_values(value: Any) -> list[Any]:
    output: list[Any] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"damage_flags", "runtime_damage_flags", "route_evidence_flags"}:
                output.extend(item if isinstance(item, list) else [item])
            elif key == "error" and item:
                output.append(item)
            else:
                output.extend(_named_flag_values(item))
    elif isinstance(value, list):
        for item in value:
            output.extend(_named_flag_values(item))
    return output


def _dedupe_nodes(nodes: list[DiagnosisNode]) -> list[DiagnosisNode]:
    return list({node.node_id: node for node in nodes}.values())


def _dedupe_edges(edges: list[DiagnosisEdge]) -> list[DiagnosisEdge]:
    return list({edge.edge_id: edge for edge in edges}.values())
