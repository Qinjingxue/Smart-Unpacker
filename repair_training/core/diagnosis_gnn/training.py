from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json
from repair_training.core.diagnosis_graph.schema import DIAGNOSIS_GRAPH_SCHEMA_VERSION, DiagnosisGraphSample
from repair_training.core.diagnosis_gnn import DIAGNOSIS_GNN_ALGORITHM, DIAGNOSIS_GNN_SEMANTICS
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples, split_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.metrics import (
    binary_multilabel_metrics,
    calibrate_global_threshold,
    clean_false_positive_rate,
)
from repair_training.core.diagnosis_gnn.model import build_diagnosis_gnn_model
from repair_training.core.diagnosis_gnn.tensorize import (
    THEORY_DEPENDS_EDGE_TYPE,
    metadata_for_sample,
    metadata_from_samples,
    tensorize_sample,
)


DEFAULT_CONFIG = {
    "hidden_dim": 64,
    "layers": 2,
    "dropout": 0.15,
    "batch_size": 16,
    "epochs": 50,
    "lr": 1e-3,
    "weight_decay": 1e-4,
    "early_stopping_patience": 8,
    "aux_loss_weight": 0.25,
    "edge_loss_weight": 0.35,
}


def train_diagnosis_gnn_model(
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
        from torch_geometric.loader import DataLoader
    except Exception as exc:  # pragma: no cover
        raise SystemExit(
            "DiagnosisGNN training requires torch and torch-geometric. "
            "Install repair_training/requirements-training.txt."
        ) from exc

    config = {**DEFAULT_CONFIG, **dict(config or {})}
    samples = read_diagnosis_graph_samples(input_path)
    if not samples:
        raise SystemExit(f"no diagnosis graph samples found: {input_path}")
    splits = split_diagnosis_graph_samples(samples)
    metadata = metadata_from_samples(samples)
    train_data = [tensorize_sample(sample) for sample in splits["train"]]
    valid_data = [tensorize_sample(sample) for sample in splits["valid"]]
    test_data = [tensorize_sample(sample) for sample in splits["test"]]
    resolved_device = _resolve_device(device, torch)
    model = build_diagnosis_gnn_model(metadata=metadata, config=config).to(resolved_device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(config["lr"]), weight_decay=float(config["weight_decay"]))
    batch_size = max(1, int(config["batch_size"]))
    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
    valid_loader = DataLoader(valid_data or train_data, batch_size=batch_size)
    best_state = None
    best_loss = float("inf")
    stale = 0
    history = []
    for epoch in range(1, max(1, int(config["epochs"])) + 1):
        model.train()
        train_loss = 0.0
        batches = 0
        for batch in train_loader:
            batch = batch.to(resolved_device)
            optimizer.zero_grad()
            out = model(batch.x_dict, batch.edge_index_dict)
            cause_loss = F.binary_cross_entropy_with_logits(out["cause"], batch["cause"].y.float())
            theory_loss = F.binary_cross_entropy_with_logits(out["theory"], batch["theory"].y_alignment.float())
            edge_loss = _theory_edge_loss(out, batch, F)
            loss = (
                cause_loss
                + float(config["aux_loss_weight"]) * theory_loss
                + float(config["edge_loss_weight"]) * edge_loss
            )
            loss.backward()
            optimizer.step()
            train_loss += float(loss.detach().cpu())
            batches += 1
        valid_loss = _eval_loss(
            model,
            valid_loader,
            resolved_device,
            F,
            aux_weight=float(config["aux_loss_weight"]),
            edge_weight=float(config["edge_loss_weight"]),
        )
        history.append({"epoch": epoch, "train_loss": train_loss / max(1, batches), "valid_loss": valid_loss})
        if valid_loss < best_loss - 1e-6:
            best_loss = valid_loss
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
            stale = 0
        else:
            stale += 1
            if stale >= int(config["early_stopping_patience"]):
                break
    if best_state is not None:
        model.load_state_dict(best_state)
    train_pred = _predict_score_rows(model, train_data, resolved_device)
    valid_pred = _predict_score_rows(model, valid_data, resolved_device)
    test_pred = _predict_score_rows(model, test_data, resolved_device)
    thresholds = _calibrate_thresholds(valid_pred or train_pred)
    metrics = {
        "train": _metrics_from_predictions(train_pred, thresholds=thresholds),
        "valid": _metrics_from_predictions(valid_pred, thresholds=thresholds),
        "test": _metrics_from_predictions(test_pred, thresholds=thresholds),
        "thresholds": thresholds,
        "best_valid_loss": best_loss,
        "history": history,
        "device": str(resolved_device),
        "samples": {key: len(value) for key, value in splits.items()},
    }
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    torch.save({
        "state_dict": model.state_dict(),
        "metadata": metadata,
        "config": config,
    }, model_dir / "model.pt")
    write_json(model_dir / "model_card.json", {
        "model_type": "diagnosis_gnn",
        "algorithm": DIAGNOSIS_GNN_ALGORITHM,
        "diagnosis_semantics": DIAGNOSIS_GNN_SEMANTICS,
        "graph_schema": DIAGNOSIS_GRAPH_SCHEMA_VERSION,
        "format": format_name,
        "run_id": run_id,
        "device": str(resolved_device),
    })
    write_json(model_dir / "graph_schema.json", {
        "graph_schema": DIAGNOSIS_GRAPH_SCHEMA_VERSION,
        "node_types": metadata[0],
        "edge_types": [list(item) for item in metadata[1]],
    })
    write_json(model_dir / "label_schema.json", _label_schema(samples))
    write_json(model_dir / "thresholds.json", thresholds)
    write_json(model_dir / "train_metrics.json", metrics)
    write_json(model_dir / "metrics.json", metrics)
    return metrics


def _eval_loss(model, loader, device, F, *, aux_weight: float, edge_weight: float) -> float:
    model.eval()
    total = 0.0
    batches = 0
    with _torch_no_grad():
        for batch in loader:
            batch = batch.to(device)
            out = model(batch.x_dict, batch.edge_index_dict)
            cause_loss = F.binary_cross_entropy_with_logits(out["cause"], batch["cause"].y.float())
            theory_loss = F.binary_cross_entropy_with_logits(out["theory"], batch["theory"].y_alignment.float())
            edge_loss = _theory_edge_loss(out, batch, F)
            total += float((cause_loss + aux_weight * theory_loss + edge_weight * edge_loss).detach().cpu())
            batches += 1
    return total / max(1, batches)


def _theory_edge_loss(out: dict[str, Any], batch, F):
    try:
        labels = batch[THEORY_DEPENDS_EDGE_TYPE].edge_label.float()
    except Exception:
        return out["cause"].sum() * 0.0
    logits = out.get("theory_edge")
    if logits is None or logits.numel() == 0 or labels.numel() == 0:
        return out["cause"].sum() * 0.0
    return F.binary_cross_entropy_with_logits(logits, labels)


def _predict_score_rows(model, dataset, device) -> dict[str, Any]:
    if not dataset:
        return {
            "cause_scores": [],
            "cause_labels": [],
            "theory_scores": [],
            "theory_labels": [],
            "theory_edge_scores": [],
            "theory_edge_labels": [],
        }
    try:
        import torch
    except Exception:
        return {"cause_scores": [], "cause_labels": [], "theory_scores": [], "theory_labels": []}
    scores = []
    labels = []
    theory_scores = []
    theory_labels = []
    edge_scores = []
    edge_labels = []
    model.eval()
    with torch.no_grad():
        for data in dataset:
            data = data.to(device)
            out = model(data.x_dict, data.edge_index_dict)
            scores.append(torch.sigmoid(out["cause"]).detach().cpu().tolist())
            labels.append(data["cause"].y.detach().cpu().tolist())
            theory_scores.append(torch.sigmoid(out["theory"]).detach().cpu().tolist())
            theory_labels.append(data["theory"].y_alignment.detach().cpu().tolist())
            edge_scores.append(torch.sigmoid(out["theory_edge"]).detach().cpu().tolist())
            try:
                edge_labels.append(data[THEORY_DEPENDS_EDGE_TYPE].edge_label.detach().cpu().tolist())
            except Exception:
                edge_labels.append([])
    return {
        "cause_scores": scores,
        "cause_labels": labels,
        "theory_scores": theory_scores,
        "theory_labels": theory_labels,
        "theory_edge_scores": edge_scores,
        "theory_edge_labels": edge_labels,
    }


def _calibrate_thresholds(predictions: dict[str, Any]) -> dict[str, Any]:
    cause = calibrate_global_threshold(predictions["cause_scores"], predictions["cause_labels"])
    theory = calibrate_global_threshold(predictions["theory_scores"], predictions["theory_labels"], max_clean_false_positive_rate=None)
    theory_edge = calibrate_global_threshold(
        predictions.get("theory_edge_scores", []),
        predictions.get("theory_edge_labels", []),
        max_clean_false_positive_rate=None,
    )
    return {
        "selection_split": "valid",
        "cause": cause,
        "theory_alignment": theory,
        "theory_edge_alignment": theory_edge,
        "default_threshold": float(cause.get("threshold", 0.5)),
        "field_threshold": float(cause.get("threshold", 0.5)),
        "zone_threshold": float(cause.get("threshold", 0.5)),
    }


def _metrics_from_predictions(predictions: dict[str, Any], *, thresholds: dict[str, Any]) -> dict[str, Any]:
    cause_threshold = float((thresholds.get("cause") or {}).get("threshold", thresholds.get("default_threshold", 0.5)))
    theory_threshold = float((thresholds.get("theory_alignment") or {}).get("threshold", 0.5))
    theory_edge_threshold = float((thresholds.get("theory_edge_alignment") or {}).get("threshold", theory_threshold))
    cause = binary_multilabel_metrics(predictions["cause_scores"], predictions["cause_labels"], threshold=cause_threshold)
    theory = binary_multilabel_metrics(predictions["theory_scores"], predictions["theory_labels"], threshold=theory_threshold)
    theory_edge = binary_multilabel_metrics(
        predictions.get("theory_edge_scores", []),
        predictions.get("theory_edge_labels", []),
        threshold=theory_edge_threshold,
    )
    return {
        "rows": len(predictions["cause_scores"]),
        "cause_threshold": cause_threshold,
        "cause_micro_f1": cause["micro_f1"],
        "cause_micro_precision": cause["micro_precision"],
        "cause_micro_recall": cause["micro_recall"],
        "cause_top1_hit": cause["top1_hit"],
        "cause_top3_hit": cause["top3_hit"],
        "cause_top5_hit": cause["top5_hit"],
        "theory_alignment_threshold": theory_threshold,
        "theory_alignment_f1": theory["micro_f1"],
        "theory_edge_alignment_threshold": theory_edge_threshold,
        "theory_edge_alignment_f1": theory_edge["micro_f1"],
        "clean_false_positive_rate": clean_false_positive_rate(predictions["cause_scores"], predictions["cause_labels"], threshold=cause_threshold),
    }


def _label_schema(samples: list[DiagnosisGraphSample]) -> dict[str, Any]:
    cause_labels = sorted({label for sample in samples for label in metadata_for_sample(sample).cause_labels if label})
    return {
        "labels": cause_labels,
        "metadata": {
            "kind": "diagnosis_gnn_root_cause",
            "diagnosis_semantics": DIAGNOSIS_GNN_SEMANTICS,
        },
    }


def _resolve_device(device: str, torch_module) -> str:
    requested = str(device or "auto").lower()
    if requested == "auto":
        return "cuda" if torch_module.cuda.is_available() else "cpu"
    if requested == "cuda" and not torch_module.cuda.is_available():
        raise SystemExit("DiagnosisGNN requested --device cuda but CUDA is not available")
    return requested


def _torch_no_grad():
    import torch
    return torch.no_grad()
