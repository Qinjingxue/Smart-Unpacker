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
    arch = normalize_diagnosis_gnn_arch(config.get("arch") or config.get("algorithm") or "hetero_graphsage")
    common = {
        "metadata": metadata,
        "hidden_dim": int(config.get("hidden_dim", 64)),
        "layers": int(config.get("layers", 2)),
        "dropout": float(config.get("dropout", 0.15)),
    }
    if arch == "hetero_graphsage":
        return DiagnosisHeteroGraphSAGE(**common)
    if arch == "rgcn":
        return DiagnosisRGCN(**common, num_bases=int(config.get("num_bases", 8)))
    if arch == "hgt":
        return DiagnosisHGT(
            **common,
            heads=int(config.get("heads", 4)),
            residual=_bool_config(config.get("residual"), default=True),
            layernorm=_bool_config(config.get("layernorm"), default=True),
        )
    raise ValueError(f"unsupported DiagnosisGNN architecture: {arch}")


def normalize_diagnosis_gnn_arch(value: Any) -> str:
    text = str(value or "hetero_graphsage").strip().lower().replace("-", "_")
    aliases = {
        "graphsage": "hetero_graphsage",
        "sage": "hetero_graphsage",
        "heterosage": "hetero_graphsage",
        "hetero_sage": "hetero_graphsage",
        "r_gcn": "rgcn",
        "hetero_rgcn": "rgcn",
        "heterogeneous_graph_transformer": "hgt",
    }
    text = aliases.get(text, text)
    if text not in {"hetero_graphsage", "rgcn", "hgt"}:
        raise ValueError(f"unsupported DiagnosisGNN architecture: {value!r}")
    return text


def _bool_config(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class _DiagnosisBase(_BASE_MODULE):
    def _init_common_heads(self, hidden_dim: int, dropout: float):
        import torch.nn as nn
        from torch_geometric.nn import Linear

        self.cause_head = Linear(hidden_dim, 1)
        self.theory_head = Linear(hidden_dim, 1)
        self.theory_edge_head = nn.Sequential(
            Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            Linear(hidden_dim, 1),
        )
        self.activation = nn.ReLU()
        self.dropout_layer = nn.Dropout(float(dropout))

    def _score_theory_edges(self, x_dict, edge_index_dict):
        import torch

        edge_index = edge_index_dict.get(THEORY_DEPENDS_EDGE_TYPE)
        if edge_index is None or edge_index.numel() == 0 or "theory" not in x_dict:
            return torch.empty(0, device=next(self.parameters()).device)
        source = x_dict["theory"][edge_index[0]]
        target = x_dict["theory"][edge_index[1]]
        return self.theory_edge_head(torch.cat([source, target], dim=-1)).view(-1)


class DiagnosisHeteroGraphSAGE(_DiagnosisBase):
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
        self._init_common_heads(self.hidden_dim, self.dropout)

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


class DiagnosisRGCN(_DiagnosisBase):
    def __init__(
        self,
        *,
        metadata: tuple[list[str], list[tuple[str, str, str]]],
        hidden_dim: int = 64,
        layers: int = 2,
        dropout: float = 0.15,
        num_bases: int = 8,
    ):
        require_pyg()
        import torch.nn as nn
        from torch_geometric.nn import Linear, RGCNConv

        super().__init__()
        self.metadata = metadata
        self.hidden_dim = int(hidden_dim)
        self.dropout = float(dropout)
        node_types, edge_types = metadata
        self.node_types = list(node_types)
        self.edge_types = [tuple(edge_type) for edge_type in edge_types]
        self.edge_type_to_id = {edge_type: index for index, edge_type in enumerate(self.edge_types)}
        self.node_encoders = nn.ModuleDict({
            node_type: Linear(NODE_FEATURE_DIM, self.hidden_dim)
            for node_type in self.node_types
        })
        self.convs = nn.ModuleList([
            RGCNConv(
                self.hidden_dim,
                self.hidden_dim,
                num_relations=max(1, len(self.edge_types)),
                num_bases=max(1, min(int(num_bases), max(1, len(self.edge_types)))),
            )
            for _ in range(max(1, int(layers)))
        ])
        self._init_common_heads(self.hidden_dim, self.dropout)

    def forward(self, x_dict, edge_index_dict):
        import torch

        encoded = {
            node_type: self.activation(self.node_encoders[node_type](x))
            for node_type, x in x_dict.items()
            if node_type in self.node_encoders
        }
        node_order = [node_type for node_type in self.node_types if node_type in encoded]
        sizes = {node_type: encoded[node_type].shape[0] for node_type in node_order}
        offsets: dict[str, int] = {}
        cursor = 0
        for node_type in node_order:
            offsets[node_type] = cursor
            cursor += sizes[node_type]
        x = torch.cat([encoded[node_type] for node_type in node_order], dim=0)
        edge_indices = []
        edge_type_ids = []
        for edge_type, edge_index in edge_index_dict.items():
            source_type, _, target_type = tuple(edge_type)
            if source_type not in offsets or target_type not in offsets:
                continue
            relation_id = self.edge_type_to_id.get(tuple(edge_type))
            if relation_id is None or edge_index.numel() == 0:
                continue
            shifted = edge_index.clone()
            shifted[0] += offsets[source_type]
            shifted[1] += offsets[target_type]
            edge_indices.append(shifted)
            edge_type_ids.append(torch.full((shifted.shape[1],), relation_id, dtype=torch.long, device=shifted.device))
        if edge_indices:
            edge_index = torch.cat(edge_indices, dim=1)
            edge_type = torch.cat(edge_type_ids, dim=0)
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long, device=x.device)
            edge_type = torch.empty((0,), dtype=torch.long, device=x.device)
        for conv in self.convs:
            x = self.dropout_layer(self.activation(conv(x, edge_index, edge_type)))
        out_dict = {
            node_type: x[offsets[node_type]: offsets[node_type] + sizes[node_type]]
            for node_type in node_order
        }
        cause_logits = self.cause_head(out_dict["cause"]).view(-1)
        theory_logits = self.theory_head(out_dict["theory"]).view(-1)
        theory_edge_logits = self._score_theory_edges(out_dict, edge_index_dict)
        return {"cause": cause_logits, "theory": theory_logits, "theory_edge": theory_edge_logits}


class DiagnosisHGT(_DiagnosisBase):
    def __init__(
        self,
        *,
        metadata: tuple[list[str], list[tuple[str, str, str]]],
        hidden_dim: int = 64,
        layers: int = 2,
        dropout: float = 0.15,
        heads: int = 4,
        residual: bool = True,
        layernorm: bool = True,
    ):
        require_pyg()
        import torch.nn as nn
        from torch_geometric.nn import HGTConv, Linear

        super().__init__()
        self.metadata = metadata
        self.hidden_dim = int(hidden_dim)
        self.dropout = float(dropout)
        self.use_residual = bool(residual)
        self.use_layernorm = bool(layernorm)
        node_types, _edge_types = metadata
        self.node_types = list(node_types)
        self.node_encoders = nn.ModuleDict({
            node_type: Linear(NODE_FEATURE_DIM, self.hidden_dim)
            for node_type in node_types
        })
        self.convs = nn.ModuleList([
            HGTConv(self.hidden_dim, self.hidden_dim, metadata, heads=max(1, int(heads)))
            for _ in range(max(1, int(layers)))
        ])
        if self.use_layernorm:
            self.norms = nn.ModuleList([
                nn.ModuleDict({node_type: nn.LayerNorm(self.hidden_dim) for node_type in node_types})
                for _ in range(max(1, int(layers)))
            ])
        else:
            self.norms = nn.ModuleList()
        self._init_common_heads(self.hidden_dim, self.dropout)

    def forward(self, x_dict, edge_index_dict):
        x_dict = {
            node_type: self.activation(self.node_encoders[node_type](x))
            for node_type, x in x_dict.items()
            if node_type in self.node_encoders
        }
        for index, conv in enumerate(self.convs):
            previous = x_dict
            out = conv(x_dict, edge_index_dict)
            next_dict = {}
            for node_type, x in previous.items():
                value = out.get(node_type, x)
                if self.use_residual and value.shape == x.shape:
                    value = value + x
                value = self.activation(value)
                if self.use_layernorm and node_type in self.norms[index]:
                    value = self.norms[index][node_type](value)
                next_dict[node_type] = self.dropout_layer(value)
            x_dict = next_dict
        cause_logits = self.cause_head(x_dict["cause"]).view(-1)
        theory_logits = self.theory_head(x_dict["theory"]).view(-1)
        theory_edge_logits = self._score_theory_edges(x_dict, edge_index_dict)
        return {"cause": cause_logits, "theory": theory_logits, "theory_edge": theory_edge_logits}
