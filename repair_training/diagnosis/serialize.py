from __future__ import annotations

from collections import Counter
from typing import Any

from repair_training.data.io import write_json, write_jsonl
from sunpack.repair.model.diagnosis.graph_schema import DiagnosisGraphSample


def sample_to_row(sample: DiagnosisGraphSample) -> dict[str, Any]:
    return sample.to_dict()


def write_diagnosis_graph_rows(path: str, samples: list[DiagnosisGraphSample]) -> None:
    write_jsonl(path, [sample.to_dict() for sample in samples])


def diagnosis_graph_summary(samples: list[DiagnosisGraphSample], *, unsupported_count: int = 0) -> dict[str, Any]:
    formats = Counter(sample.format for sample in samples)
    layer_counts: Counter[str] = Counter()
    node_type_counts: Counter[str] = Counter()
    edge_type_counts: Counter[str] = Counter()
    root_cause_counts: Counter[str] = Counter()
    symptom_counts: Counter[str] = Counter()
    theory_alignment_counts: Counter[str] = Counter()
    theory_symptom_counts: Counter[str] = Counter()
    for sample in samples:
        for node in sample.graph.nodes:
            layer_counts[node.node_layer] += 1
            node_type_counts[node.node_type] += 1
        for edge in sample.graph.edges:
            edge_type_counts[edge.edge_type] += 1
        root_cause_counts.update(sample.labels.field_labels)
        root_cause_counts.update(sample.labels.zone_labels)
        symptom_counts.update(sample.labels.symptom_field_labels)
        symptom_counts.update(sample.labels.symptom_zone_labels)
        theory_alignment_counts.update(sample.labels.theory_node_ids)
        theory_symptom_counts.update(sample.labels.symptom_theory_node_ids)
    return {
        "rows": len(samples),
        "formats": dict(sorted(formats.items())),
        "unsupported_count": int(unsupported_count),
        "node_layer_counts": dict(sorted(layer_counts.items())),
        "node_type_counts": dict(sorted(node_type_counts.items())),
        "edge_type_counts": dict(sorted(edge_type_counts.items())),
        "root_cause_label_counts": dict(sorted(root_cause_counts.items())),
        "propagated_symptom_label_counts": dict(sorted(symptom_counts.items())),
        "theory_alignment_counts": dict(sorted(theory_alignment_counts.items())),
        "theory_symptom_counts": dict(sorted(theory_symptom_counts.items())),
    }


def write_diagnosis_graph_summary(path: str, samples: list[DiagnosisGraphSample], *, unsupported_count: int = 0) -> None:
    write_json(path, diagnosis_graph_summary(samples, unsupported_count=unsupported_count))
