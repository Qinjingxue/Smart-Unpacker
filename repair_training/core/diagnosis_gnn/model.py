from __future__ import annotations

from typing import Any

from repair_training.core.diagnosis_gnn.tensorize import NODE_FEATURE_DIM, THEORY_DEPENDS_EDGE_TYPE, require_pyg

try:  # Keep the package importable when optional GNN deps are absent.
    import torch.nn as _torch_nn
    _BASE_MODULE = _torch_nn.Module
except Exception:  # pragma: no cover - depends on optional training environment
    _BASE_MODULE = object


def require_torch():
    try:
        import torch  # noqa: F401
        import torch.nn as nn  # noqa: F401
    except Exception as exc:  # pragma: no cover
        raise SystemExit(
            "DiagnosisGNN requires torch and torch-geometric. "
            "Install repair_training/requirements-training.txt."
        ) from exc


def build_diagnosis_gnn_model(*, metadata: tuple[list[str], list[tuple[str, str, str]]], config: dict[str, Any] | None = None):
    require_pyg()
    config = dict(config or {})
    return DiagnosisHeteroGraphSAGE(
        metadata=metadata,
        hidden_dim=int(config.get("hidden_dim", 64)),
        layers=int(config.get("layers", 2)),
        dropout=float(config.get("dropout", 0.15)),
    )


class DiagnosisHeteroGraphSAGE(_BASE_MODULE):
    def __init__(
        self,
        *,
        metadata: tuple[list[str], list[tuple[str, str, str]]],
        hidden_dim: int = 64,
        layers: int = 2,
        dropout: float = 0.15,
    ):
        require_pyg()
        import torch.nn as nn
        from torch_geometric.nn import HeteroConv, Linear, SAGEConv

        super().__init__()
        self.metadata = metadata
        self.hidden_dim = int(hidden_dim)
        self.dropout = float(dropout)
        node_types, edge_types = metadata
        self.node_encoders = nn.ModuleDict({
            node_type: Linear(NODE_FEATURE_DIM, self.hidden_dim)
            for node_type in node_types
        })
        self.convs = nn.ModuleList()
        for _ in range(max(1, int(layers))):
            convs = {
                edge_type: SAGEConv((self.hidden_dim, self.hidden_dim), self.hidden_dim)
                for edge_type in edge_types
            }
            self.convs.append(HeteroConv(convs, aggr="sum"))
        self.cause_head = Linear(self.hidden_dim, 1)
        self.theory_head = Linear(self.hidden_dim, 1)
        self.theory_edge_head = nn.Sequential(
            Linear(self.hidden_dim * 2, self.hidden_dim),
            nn.ReLU(),
            Linear(self.hidden_dim, 1),
        )
        self.activation = nn.ReLU()
        self.dropout_layer = nn.Dropout(self.dropout)

    def forward(self, x_dict, edge_index_dict):
        x_dict = {
            node_type: self.activation(self.node_encoders[node_type](x))
            for node_type, x in x_dict.items()
            if node_type in self.node_encoders
        }
        for conv in self.convs:
            out = conv(x_dict, edge_index_dict)
            x_dict = {
                node_type: self.dropout_layer(self.activation(out.get(node_type, x)))
                for node_type, x in x_dict.items()
            }
        cause_logits = self.cause_head(x_dict["cause"]).view(-1)
        theory_logits = self.theory_head(x_dict["theory"]).view(-1)
        theory_edge_logits = self._score_theory_edges(x_dict, edge_index_dict)
        return {"cause": cause_logits, "theory": theory_logits, "theory_edge": theory_edge_logits}

    def _score_theory_edges(self, x_dict, edge_index_dict):
        import torch

        edge_index = edge_index_dict.get(THEORY_DEPENDS_EDGE_TYPE)
        if edge_index is None or edge_index.numel() == 0 or "theory" not in x_dict:
            return torch.empty(0, device=next(self.parameters()).device)
        source = x_dict["theory"][edge_index[0]]
        target = x_dict["theory"][edge_index[1]]
        return self.theory_edge_head(torch.cat([source, target], dim=-1)).view(-1)
