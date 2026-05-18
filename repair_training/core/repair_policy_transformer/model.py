from __future__ import annotations

from typing import Any

from repair_training.core.repair_policy_transformer.tensorize import ACTION_FEATURE_DIM, EDGE_FEATURE_DIM, MASK_TARGET_DIM, MEMORY_FEATURE_DIM, NODE_FEATURE_DIM, UNCERTAINTY_TARGET_DIM, WORLD_TARGET_DIM, require_torch


def build_repair_policy_transformer(config: dict[str, Any] | None = None):
    require_torch()
    config = dict(config or {})
    return RepairGraphMemoryPolicyTransformer(
        hidden_dim=int(config.get("hidden_dim", 128)),
        heads=int(config.get("heads", 4)),
        layers=int(config.get("layers", 2)),
        dropout=float(config.get("dropout", 0.15)),
    )


class RepairGraphMemoryPolicyTransformer:
    def __new__(cls, *args, **kwargs):
        import torch.nn as nn

        class _Model(nn.Module):
            def __init__(self, hidden_dim: int, heads: int, layers: int, dropout: float):
                super().__init__()
                self.config = {"hidden_dim": hidden_dim, "heads": heads, "layers": layers, "dropout": dropout}
                self.node_in = nn.Linear(NODE_FEATURE_DIM, hidden_dim)
                self.edge_in = nn.Linear(EDGE_FEATURE_DIM, hidden_dim)
                self.memory_in = nn.Linear(MEMORY_FEATURE_DIM, hidden_dim)
                self.action_in = nn.Linear(ACTION_FEATURE_DIM, hidden_dim)
                self.node_update = nn.Sequential(
                    nn.LayerNorm(hidden_dim * 2),
                    nn.Linear(hidden_dim * 2, hidden_dim),
                    nn.GELU(),
                    nn.Dropout(dropout),
                )
                encoder_layer = nn.TransformerEncoderLayer(
                    d_model=hidden_dim,
                    nhead=max(1, heads),
                    dim_feedforward=hidden_dim * 4,
                    dropout=dropout,
                    batch_first=True,
                    activation="gelu",
                )
                self.graph_encoder = nn.TransformerEncoder(encoder_layer, num_layers=max(1, layers))
                self.memory_encoder = nn.TransformerEncoder(encoder_layer, num_layers=max(1, layers))
                self.query_attention = nn.MultiheadAttention(hidden_dim, max(1, heads), dropout=dropout, batch_first=True)
                self.scorer = nn.Sequential(
                    nn.LayerNorm(hidden_dim * 2),
                    nn.Linear(hidden_dim * 2, hidden_dim),
                    nn.GELU(),
                    nn.Dropout(dropout),
                    nn.Linear(hidden_dim, 1),
                )
                self.promising_head = nn.Sequential(
                    nn.LayerNorm(hidden_dim),
                    nn.Linear(hidden_dim, hidden_dim),
                    nn.GELU(),
                    nn.Dropout(dropout),
                    nn.Linear(hidden_dim, 1),
                )
                self.transition_head = nn.Sequential(
                    nn.LayerNorm(hidden_dim * 2),
                    nn.Linear(hidden_dim * 2, hidden_dim),
                    nn.GELU(),
                    nn.Dropout(dropout),
                    nn.Linear(hidden_dim, WORLD_TARGET_DIM),
                )
                self.uncertainty_head = nn.Sequential(
                    nn.LayerNorm(hidden_dim * 2),
                    nn.Linear(hidden_dim * 2, hidden_dim),
                    nn.GELU(),
                    nn.Dropout(dropout),
                    nn.Linear(hidden_dim, UNCERTAINTY_TARGET_DIM),
                )
                self.masked_graph_head = nn.Sequential(
                    nn.LayerNorm(hidden_dim),
                    nn.Linear(hidden_dim, hidden_dim),
                    nn.GELU(),
                    nn.Dropout(dropout),
                    nn.Linear(hidden_dim, MASK_TARGET_DIM),
                )

            def encode_context(self, node_x, memory_x, edge_x=None):
                import torch

                node_h = self.node_in(node_x)
                if edge_x is not None and edge_x.numel() > 0:
                    edge_h = self.edge_in(edge_x)
                    edge_context = edge_h.mean(dim=0, keepdim=True).expand(node_h.shape[0], -1)
                    node_h = node_h + self.node_update(torch.cat([node_h, edge_context], dim=-1))
                    graph_tokens = torch.cat([node_h, edge_h], dim=0)
                else:
                    graph_tokens = node_h
                node_h = self.graph_encoder(graph_tokens.unsqueeze(0)).squeeze(0)
                memory_h = self.memory_encoder(self.memory_in(memory_x).unsqueeze(0)).squeeze(0)
                return node_h if memory_h.numel() == 0 else torch.cat([node_h, memory_h], dim=0)

            def forward(self, node_x, memory_x, action_x, edge_x=None):
                context = self.encode_context(node_x, memory_x, edge_x)
                action_h = self.action_in(action_x).unsqueeze(0)
                attended, _ = self.query_attention(action_h, context.unsqueeze(0), context.unsqueeze(0))
                combined = __import__("torch").cat([action_h.squeeze(0), attended.squeeze(0)], dim=-1)
                return self.scorer(combined).view(-1)

            def forward_all(self, node_x, memory_x, action_x, edge_x=None):
                import torch

                context = self.encode_context(node_x, memory_x, edge_x)
                action_h = self.action_in(action_x).unsqueeze(0)
                attended, _ = self.query_attention(action_h, context.unsqueeze(0), context.unsqueeze(0))
                combined = torch.cat([action_h.squeeze(0), attended.squeeze(0)], dim=-1)
                logits = self.scorer(combined).view(-1)
                pooled = context.mean(dim=0)
                return {
                    "action_logits": logits,
                    "transition": self.transition_head(combined) if combined.numel() > 0 else self.transition_head(torch.cat([pooled, pooled], dim=-1).view(1, -1)),
                    "uncertainty": self.uncertainty_head(combined) if combined.numel() > 0 else self.uncertainty_head(torch.cat([pooled, pooled], dim=-1).view(1, -1)),
                    "masked": self.masked_graph_head(pooled).view(-1),
                    "promising": self.promising_head(pooled).view(1),
                }

            def promising_logit(self, node_x, memory_x, edge_x=None):
                context = self.encode_context(node_x, memory_x, edge_x)
                pooled = context.mean(dim=0)
                return self.promising_head(pooled).view(1)

        return _Model(*args, **kwargs)
