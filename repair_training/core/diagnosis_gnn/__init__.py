from __future__ import annotations

from repair_training.core.diagnosis_gnn.root_cases import ROOT_CASE_SEMANTICS

DIAGNOSIS_GNN_SEMANTICS = ROOT_CASE_SEMANTICS
DIAGNOSIS_GNN_SCORE_SEMANTICS = "repair_priority"
DIAGNOSIS_GNN_ALGORITHM = "hetero_graphsage"

__all__ = ["DIAGNOSIS_GNN_ALGORITHM", "DIAGNOSIS_GNN_SCORE_SEMANTICS", "DIAGNOSIS_GNN_SEMANTICS"]
