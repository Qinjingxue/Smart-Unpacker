import pytest

from sunpack.repair.model.diagnosis.graph_schema import (
    DiagnosisEdge,
    DiagnosisGraph,
    DiagnosisGraphSample,
    DiagnosisLabels,
    DiagnosisNode,
)
from sunpack.repair.model.diagnosis.graph_validate import (
    DiagnosisGraphValidationError,
    validate_diagnosis_graph_sample,
)


def _sample() -> DiagnosisGraphSample:
    return DiagnosisGraphSample(
        format="zip",
        sample_id="sample",
        source={"state_digest": "abc", "patch_depth": 0},
        graph=DiagnosisGraph(
            nodes=[
                DiagnosisNode("obs:a", "observation", "summary", format="zip"),
                DiagnosisNode("theory:a", "theory", "zip_field", format="zip"),
                DiagnosisNode("cause:a", "cause", "field_cause", format="zip", label="field:eocd.cd_offset"),
            ],
            edges=[
                DiagnosisEdge("edge:1", "observes_theory", "obs:a", "theory:a"),
                DiagnosisEdge("edge:2", "theory_supports_cause", "theory:a", "cause:a"),
            ],
        ),
        labels=DiagnosisLabels(
            cause_node_ids=["cause:a"],
            field_labels=["field:eocd.cd_offset"],
            theory_node_ids=["theory:a"],
        ),
    )


def test_diagnosis_graph_schema_roundtrip():
    sample = _sample()
    payload = sample.to_dict()
    restored = DiagnosisGraphSample.from_dict(payload)

    assert restored.to_dict() == payload
    validate_diagnosis_graph_sample(restored)


def test_diagnosis_graph_validator_rejects_duplicate_nodes():
    sample = _sample()
    broken = DiagnosisGraphSample(
        format=sample.format,
        sample_id=sample.sample_id,
        source=sample.source,
        graph=DiagnosisGraph(nodes=[sample.graph.nodes[0], sample.graph.nodes[0]], edges=[]),
        labels=DiagnosisLabels(),
    )

    with pytest.raises(DiagnosisGraphValidationError, match="duplicate"):
        validate_diagnosis_graph_sample(broken)


def test_diagnosis_graph_validator_rejects_missing_edge_target():
    sample = _sample()
    broken = DiagnosisGraphSample(
        format=sample.format,
        sample_id=sample.sample_id,
        source=sample.source,
        graph=DiagnosisGraph(
            nodes=sample.graph.nodes[:1],
            edges=[DiagnosisEdge("edge:bad", "observes_theory", "obs:a", "missing")],
        ),
        labels=DiagnosisLabels(),
    )

    with pytest.raises(DiagnosisGraphValidationError, match="target is missing"):
        validate_diagnosis_graph_sample(broken)
