from __future__ import annotations

from sunpack.model_runtime.diagnosis.graph_dispatcher import (
    UnsupportedDiagnosisGraphFormat,
    build_diagnosis_graph_sample,
    build_diagnosis_graph_sample_for_format,
    detect_graph_format,
)
from sunpack.model_runtime.diagnosis.graph_schema import (
    DIAGNOSIS_GRAPH_SCHEMA_VERSION,
    DiagnosisEdge,
    DiagnosisGraph,
    DiagnosisGraphPlugin,
    DiagnosisGraphSample,
    DiagnosisLabels,
    DiagnosisNode,
    GraphFragment,
)
from sunpack.model_runtime.diagnosis.root_cases import ROOT_CASE_SEMANTICS


DIAGNOSIS_GNN_SEMANTICS = ROOT_CASE_SEMANTICS
DIAGNOSIS_GNN_SCORE_SEMANTICS = "repair_priority"
DIAGNOSIS_GNN_ALGORITHM = "hetero_graphsage"

__all__ = [
    "DIAGNOSIS_GNN_ALGORITHM",
    "DIAGNOSIS_GNN_SCORE_SEMANTICS",
    "DIAGNOSIS_GNN_SEMANTICS",
    "DIAGNOSIS_GRAPH_SCHEMA_VERSION",
    "DiagnosisEdge",
    "DiagnosisGraph",
    "DiagnosisGraphPlugin",
    "DiagnosisGraphSample",
    "DiagnosisLabels",
    "DiagnosisNode",
    "GraphFragment",
    "UnsupportedDiagnosisGraphFormat",
    "build_diagnosis_graph_sample",
    "build_diagnosis_graph_sample_for_format",
    "detect_graph_format",
]
