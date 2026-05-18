from __future__ import annotations

from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json
from repair_training.core.repair_policy_transformer import POLICY_TRANSFORMER_ALGORITHM, POLICY_TRANSFORMER_SEMANTICS
from repair_training.core.repair_policy_transformer.dataset import read_policy_graph_samples, split_policy_graph_samples
from repair_training.core.repair_policy_transformer.model import build_repair_policy_transformer
from repair_training.core.repair_policy_transformer.tensorize import NODE_FEATURE_DIM, tensorize_sample


DEFAULT_CONFIG = {
    "hidden_dim": 128,
    "heads": 4,
    "layers": 2,
    "dropout": 0.15,
    "epochs": 1,
    "lr": 1e-3,
    "weight_decay": 1e-4,
}


def train_repair_policy_transformer(
    *,
    input_path: str | Path,
    model_dir: str | Path,
    run_id: str = "",
    format_name: str = "zip",
    config: dict[str, Any] | None = None,
    device: str = "auto",
) -> dict[str, Any]:
    try:
        import torch
        import torch.nn.functional as F
    except Exception as exc:  # pragma: no cover
        raise SystemExit("RepairPolicyTransformer training requires torch.") from exc
    config = {**DEFAULT_CONFIG, **dict(config or {})}
    samples = read_policy_graph_samples(input_path)
    if not samples:
        raise SystemExit(f"no policy graph samples found: {input_path}")
    splits = split_policy_graph_samples(samples)
    resolved_device = _resolve_device(device, torch)
    model = build_repair_policy_transformer(config).to(resolved_device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(config["lr"]), weight_decay=float(config["weight_decay"]))
    train_data = [tensorize_sample(sample) for sample in splits["train"]]
    history = []
    for epoch in range(1, max(1, int(config["epochs"])) + 1):
        model.train()
        total = 0.0
        for item in train_data:
            optimizer.zero_grad()
            logits = model(item["node_x"].to(resolved_device), item["memory_x"].to(resolved_device), item["action_x"].to(resolved_device))
            q = item["q"].to(resolved_device).view_as(logits)
            prior = item["prior"].to(resolved_device).view_as(logits)
            loss = F.mse_loss(logits.sigmoid(), q.clamp(0.0, 1.0)) + 0.25 * F.binary_cross_entropy_with_logits(logits, prior.clamp(0.0, 1.0))
            loss.backward()
            optimizer.step()
            total += float(loss.detach().cpu())
        history.append({"epoch": epoch, "train_loss": total / max(1, len(train_data))})
    metrics = {
        "samples": {split: len(rows) for split, rows in splits.items()},
        "history": history,
        "device": str(resolved_device),
    }
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "config": config}, model_dir / "model.pt")
    write_json(model_dir / "model_card.json", {
        "model_type": "repair_policy_transformer",
        "algorithm": POLICY_TRANSFORMER_ALGORITHM,
        "policy_semantics": POLICY_TRANSFORMER_SEMANTICS,
        "format": format_name,
        "run_id": run_id,
    })
    write_json(model_dir / "graph_schema.json", {"schema": "policy_loop.graph", "node_feature_dim": NODE_FEATURE_DIM})
    write_json(model_dir / "action_schema.json", {"actions": ["stop", "undo", "module"], "semantics": POLICY_TRANSFORMER_SEMANTICS})
    write_json(model_dir / "train_metrics.json", metrics)
    return metrics


def _resolve_device(device: str, torch_module) -> str:
    requested = str(device or "auto").lower()
    if requested == "auto":
        return "cuda" if torch_module.cuda.is_available() else "cpu"
    if requested == "cuda" and not torch_module.cuda.is_available():
        raise SystemExit("RepairPolicyTransformer requested --device cuda but CUDA is not available")
    return requested
