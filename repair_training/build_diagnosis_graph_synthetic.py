from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json, write_jsonl
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples
from sunpack.model_runtime.diagnosis.graph_labels import safe_node_token
from sunpack.model_runtime.diagnosis.graph_schema import (
    DiagnosisEdge,
    DiagnosisGraph,
    DiagnosisGraphSample,
    DiagnosisLabels,
    DiagnosisNode,
)
from repair_training.core.diagnosis_graph.serialize import diagnosis_graph_summary
from sunpack.model_runtime.diagnosis.graph_validate import validate_diagnosis_graph_sample
from repair_training.core.plugin import normalize_format_name
from sunpack.model_runtime.diagnosis.zip_graph import (
    zip_cause_id,
    zip_theory_dependency_edge_id,
    zip_theory_edges_for_field,
    zip_theory_id,
)


FIELD_SPECS: tuple[str, ...] = (
    "central_directory.local_header_offset",
    "central_directory.flags",
    "central_directory.compressed_size",
    "data_descriptor.record",
    "zip64.extra",
    "zip64.extra_length",
    "zip64.uncompressed_size",
    "zip64.locator",
    "payload.crc_region",
    "payload.compressed_data",
    "tail.trailing_bytes",
    "sfx_prefix.bytes",
    "split_volume.missing_range",
)

RELATION_SPECS: tuple[tuple[str, str], ...] = (
    ("central_directory.local_header_offset", "local_header.signature"),
    ("central_directory.flags", "data_descriptor.record"),
    ("central_directory.compressed_size", "payload.span"),
    ("data_descriptor.record", "payload.span"),
    ("zip64.extra", "central_directory.compressed_size"),
    ("zip64.extra", "central_directory.local_header_offset"),
    ("tail.trailing_bytes", "eocd.comment_length"),
    ("sfx_prefix.bytes", "eocd.cd_offset"),
    ("split_volume.missing_range", "payload.span"),
)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    fmt = normalize_format_name(args.format)
    if fmt != "zip":
        raise SystemExit(f"synthetic diagnosis graphs currently support zip only, got {fmt}")
    clean_samples = read_diagnosis_graph_samples(args.input)
    synthetic = build_synthetic_samples(clean_samples, per_sample=int(args.per_sample), include_compound=not args.no_compound)
    output = Path(args.output)
    write_jsonl(output, [sample.to_dict() for sample in synthetic])
    summary_path = Path(args.summary_output) if args.summary_output else output.parent.parent / "reports" / "diagnosis_graph_synthetic_summary.json"
    summary = {
        **diagnosis_graph_summary(synthetic),
        "input": str(args.input),
        "output": str(output),
        "per_sample": int(args.per_sample),
        "synthetic": True,
    }
    write_json(summary_path, summary)
    print(json.dumps({"output": str(output), "summary": str(summary_path), **summary}, ensure_ascii=False, sort_keys=True))
    return 0


def build_synthetic_samples(
    clean_samples: list[DiagnosisGraphSample],
    *,
    per_sample: int = 3,
    include_compound: bool = True,
) -> list[DiagnosisGraphSample]:
    output: list[DiagnosisGraphSample] = []
    specs = _synthetic_specs(include_compound=include_compound)
    if per_sample <= 0:
        return output
    for sample_index, sample in enumerate(clean_samples):
        if sample.format != "zip":
            continue
        for local_index in range(per_sample):
            spec = specs[(sample_index * per_sample + local_index) % len(specs)]
            synthetic = _inject_spec(sample, spec=spec, local_index=local_index)
            validate_diagnosis_graph_sample(synthetic)
            output.append(synthetic)
    return output


def _synthetic_specs(*, include_compound: bool) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = [{"kind": "field", "fields": [field]} for field in FIELD_SPECS]
    specs.extend({"kind": "relation", "relations": [relation]} for relation in RELATION_SPECS)
    if include_compound:
        specs.extend([
            {"kind": "compound", "fields": ["central_directory.flags"], "relations": [("central_directory.flags", "data_descriptor.record")]},
            {"kind": "compound", "fields": ["central_directory.compressed_size"], "relations": [("central_directory.compressed_size", "payload.span"), ("data_descriptor.record", "payload.span")]},
            {"kind": "compound", "fields": ["zip64.extra", "zip64.extra_length"], "relations": [("zip64.extra", "central_directory.compressed_size")]},
            {"kind": "compound", "fields": ["sfx_prefix.bytes", "tail.trailing_bytes"], "relations": [("sfx_prefix.bytes", "eocd.cd_offset"), ("tail.trailing_bytes", "eocd.comment_length")]},
            {"kind": "compound", "fields": ["split_volume.missing_range", "payload.compressed_data"], "relations": [("split_volume.missing_range", "payload.span")]},
        ])
    return specs


def _inject_spec(sample: DiagnosisGraphSample, *, spec: dict[str, Any], local_index: int) -> DiagnosisGraphSample:
    fields = sorted({str(field) for field in spec.get("fields", [])})
    relations = [(str(source), str(target)) for source, target in spec.get("relations", [])]
    for source, target in relations:
        fields.extend([source, target])
    fields = sorted({_canonical_label_field(field) for field in fields})
    zones = sorted({_zone_for_field(field) for field in fields if _zone_for_field(field)})
    theory_node_ids = sorted({zip_theory_id(field) for field in fields if _has_theory_node(sample, zip_theory_id(field))})
    theory_edge_ids = set()
    for field in fields:
        theory_edge_ids.update(edge_id for edge_id in zip_theory_edges_for_field(field) if _has_edge(sample, edge_id))
    for source, target in relations:
        edge_id = zip_theory_dependency_edge_id(source, target)
        if _has_edge(sample, edge_id):
            theory_edge_ids.add(edge_id)
    cause_labels = [f"field:{field}" for field in fields if _has_cause(sample, zip_cause_id(f"field:{field}"))]
    zone_labels = [f"zone:{zone}" for zone in zones if _has_cause(sample, zip_cause_id(f"zone:{zone}"))]
    cause_node_ids = sorted({zip_cause_id(label) for label in [*cause_labels, *zone_labels] if _has_cause(sample, zip_cause_id(label))})
    injected = {
        "kind": str(spec.get("kind") or "field"),
        "fields": fields,
        "relations": [[source, target] for source, target in relations],
        "theory_edge_ids": sorted(theory_edge_ids),
    }
    node = _synthetic_observation_node(sample, injected=injected, local_index=local_index)
    edges = list(sample.graph.edges)
    for theory_node_id in theory_node_ids:
        edges.append(_edge("observes_theory", node.node_id, theory_node_id, synthetic=True))
        edges.append(_edge("theory_explains_obs", theory_node_id, node.node_id, synthetic=True))
    graph = DiagnosisGraph(
        nodes=_dedupe_nodes([*sample.graph.nodes, node]),
        edges=_dedupe_edges(edges),
        graph_features={**sample.graph.graph_features, "synthetic": True, "synthetic_kind": injected["kind"]},
    )
    labels = DiagnosisLabels(
        cause_node_ids=cause_node_ids,
        field_labels=sorted(cause_labels),
        zone_labels=sorted(zone_labels),
        theory_node_ids=theory_node_ids,
        theory_edge_ids=sorted(theory_edge_ids),
        auxiliary={
            **dict(sample.labels.auxiliary),
            "clean": False,
            "synthetic": True,
            "injected_cause": [injected],
            "base_sample_id": sample.sample_id,
            "damage_profile": f"synthetic_{injected['kind']}",
        },
    )
    return DiagnosisGraphSample(
        format=sample.format,
        sample_id=f"{sample.sample_id}:synthetic:{local_index}:{safe_node_token(json.dumps(injected, sort_keys=True))[:24]}",
        source={**sample.source, "synthetic": True, "base_sample_id": sample.sample_id},
        graph=graph,
        labels=labels,
        schema_version=sample.schema_version,
    )


def _synthetic_observation_node(sample: DiagnosisGraphSample, *, injected: dict[str, Any], local_index: int) -> DiagnosisNode:
    token = safe_node_token(f"{sample.sample_id}.synthetic.{local_index}.{json.dumps(injected, sort_keys=True)}")
    primary_field = (injected.get("fields") or ["unknown"])[0]
    return DiagnosisNode(
        node_id=f"obs:synthetic:{token}",
        node_layer="observation",
        node_type="synthetic_violation",
        format="zip",
        zone=_zone_for_field(str(primary_field)) or "unknown",
        field_path=f"synthetic.{safe_node_token(primary_field)}",
        features={
            "present": True,
            "valid": False,
            "synthetic": True,
            "confidence": 1.0,
            "delta": 1.0,
            "kind": injected.get("kind"),
            "fields": ",".join(injected.get("fields") or []),
            "relations": json.dumps(injected.get("relations") or [], sort_keys=True),
        },
    )


def _edge(edge_type: str, source: str, target: str, **features: Any) -> DiagnosisEdge:
    return DiagnosisEdge(
        edge_id=f"edge:{edge_type}:{safe_node_token(source)}:{safe_node_token(target)}",
        edge_type=edge_type,
        source=source,
        target=target,
        features={key: value for key, value in features.items() if value not in (None, "")},
    )


def _dedupe_nodes(nodes: list[DiagnosisNode]) -> list[DiagnosisNode]:
    return sorted({node.node_id: node for node in nodes}.values(), key=lambda item: (item.node_layer, item.node_id))


def _dedupe_edges(edges: list[DiagnosisEdge]) -> list[DiagnosisEdge]:
    return sorted({edge.edge_id: edge for edge in edges}.values(), key=lambda item: (item.edge_type, item.source, item.target, item.edge_id))


def _has_theory_node(sample: DiagnosisGraphSample, node_id: str) -> bool:
    return any(node.node_id == node_id for node in sample.graph.nodes)


def _has_cause(sample: DiagnosisGraphSample, node_id: str) -> bool:
    return any(node.node_id == node_id for node in sample.graph.nodes)


def _has_edge(sample: DiagnosisGraphSample, edge_id: str) -> bool:
    return any(edge.edge_id == edge_id for edge in sample.graph.edges)


def _canonical_label_field(field: str) -> str:
    text = str(field or "").replace("zip.", "")
    if text == "payload.span":
        return "payload.compressed_data"
    if text == "local_header.signature":
        return "local_header.header"
    if text == "eocd.comment_length":
        return "eocd.comment"
    if text == "eocd.cd_offset":
        return "eocd.cd_offset"
    return text


def _zone_for_field(field: str) -> str:
    text = str(field or "").replace("zip.", "")
    if not text or "." not in text:
        return ""
    zone = text.split(".", 1)[0]
    if zone == "data":
        return "data_descriptor"
    return zone


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build synthetic DiagnosisGraph perturbation rows from clean graph rows.")
    parser.add_argument("--format", default="zip")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary-output", default="")
    parser.add_argument("--per-sample", type=int, default=3)
    parser.add_argument("--no-compound", action="store_true")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
