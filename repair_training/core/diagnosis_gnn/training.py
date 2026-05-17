from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from repair_training.core.datasets import sha256_file, write_json
from repair_training.core.diagnosis_graph.schema import DIAGNOSIS_GRAPH_SCHEMA_VERSION, DiagnosisGraphSample
from repair_training.core.diagnosis_gnn import DIAGNOSIS_GNN_ALGORITHM, DIAGNOSIS_GNN_SEMANTICS
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples, split_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.metrics import (
    binary_multilabel_metrics,
    calibrate_global_threshold,
    clean_false_positive_rate,
    multilabel_set_metrics,
)
from repair_training.core.diagnosis_gnn.model import build_diagnosis_gnn_model, normalize_diagnosis_gnn_arch
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
    "arch": DIAGNOSIS_GNN_ALGORITHM,
    "heads": 4,
    "num_bases": 8,
    "residual": True,
    "layernorm": True,
    "amp": False,
    "loss": "bce",
    "focal_gamma": 2.0,
    "pos_weight_max": 8.0,
    "sample_weighting": "multi_field_root_count",
}

TENSOR_CACHE_VERSION = "diagnosis_gnn_tensor_cache_v1"


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
    config["arch"] = normalize_diagnosis_gnn_arch(config.get("arch"))
    samples = read_diagnosis_graph_samples(input_path)
    if not samples:
        raise SystemExit(f"no diagnosis graph samples found: {input_path}")
    splits = split_diagnosis_graph_samples(samples)
    metadata = metadata_from_samples(samples)
    resolved_device = _resolve_device(device, torch)
    train_data = _tensorize_split(
        splits["train"],
        split="train",
        input_path=Path(input_path),
        config=config,
    )
    valid_data = _tensorize_split(
        splits["valid"],
        split="valid",
        input_path=Path(input_path),
        config=config,
    )
    test_data = _tensorize_split(
        splits["test"],
        split="test",
        input_path=Path(input_path),
        config=config,
    )
    _attach_graph_weights(train_data, splits["train"], config)
    _attach_graph_weights(valid_data, splits["valid"], config)
    _attach_graph_weights(test_data, splits["test"], config)
    model = build_diagnosis_gnn_model(metadata=metadata, config=config).to(resolved_device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(config["lr"]), weight_decay=float(config["weight_decay"]))
    batch_size = max(1, int(config["batch_size"]))
    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
    valid_loader = DataLoader(valid_data or train_data, batch_size=batch_size)
    amp_enabled = bool(config.get("amp")) and str(resolved_device).startswith("cuda")
    scaler = _grad_scaler(torch, resolved_device, amp_enabled)
    cause_pos_weight = _pos_weight_from_dataset(train_data, torch, max_value=float(config["pos_weight_max"])).to(resolved_device)
    if str(resolved_device).startswith("cuda"):
        torch.cuda.reset_peak_memory_stats()
    best_state = None
    best_loss = float("inf")
    stale = 0
    history = []
    for epoch in range(1, max(1, int(config["epochs"])) + 1):
        epoch_started = time.perf_counter()
        model.train()
        train_loss = 0.0
        batches = 0
        seen_samples = 0
        for batch in train_loader:
            batch = batch.to(resolved_device)
            optimizer.zero_grad()
            with _autocast_context(resolved_device, amp_enabled):
                out = model(batch.x_dict, batch.edge_index_dict)
                cause_loss = _cause_loss(out, batch, F, config=config, pos_weight=cause_pos_weight)
                theory_loss = _theory_loss(out, batch, F)
                edge_loss = _theory_edge_loss(out, batch, F)
                loss = (
                    cause_loss
                    + float(config["aux_loss_weight"]) * theory_loss
                    + float(config["edge_loss_weight"]) * edge_loss
                )
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
            train_loss += float(loss.detach().cpu())
            batches += 1
            seen_samples += int(getattr(batch, "num_graphs", 1) or 1)
        valid_loss = _eval_loss(
            model,
            valid_loader,
            resolved_device,
            F,
            aux_weight=float(config["aux_loss_weight"]),
            edge_weight=float(config["edge_loss_weight"]),
            config=config,
            cause_pos_weight=cause_pos_weight,
            amp_enabled=amp_enabled,
        )
        epoch_seconds = time.perf_counter() - epoch_started
        peak_memory = torch.cuda.max_memory_allocated() / (1024 * 1024) if str(resolved_device).startswith("cuda") else 0.0
        history.append({
            "epoch": epoch,
            "train_loss": train_loss / max(1, batches),
            "valid_loss": valid_loss,
            "epoch_seconds": round(epoch_seconds, 3),
            "samples_per_second": round(seen_samples / max(epoch_seconds, 1e-9), 3),
            "peak_cuda_memory_mb": round(float(peak_memory), 3),
        })
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
        "amp_enabled": amp_enabled,
        "peak_cuda_memory_mb": max((item.get("peak_cuda_memory_mb", 0.0) for item in history), default=0.0),
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
        "algorithm": config["arch"],
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


def _eval_loss(model, loader, device, F, *, aux_weight: float, edge_weight: float, config: dict[str, Any], cause_pos_weight, amp_enabled: bool) -> float:
    model.eval()
    total = 0.0
    batches = 0
    with _torch_no_grad():
        for batch in loader:
            batch = batch.to(device)
            with _autocast_context(device, amp_enabled):
                out = model(batch.x_dict, batch.edge_index_dict)
                cause_loss = _cause_loss(out, batch, F, config=config, pos_weight=cause_pos_weight)
                theory_loss = _theory_loss(out, batch, F)
                edge_loss = _theory_edge_loss(out, batch, F)
            total += float((cause_loss + aux_weight * theory_loss + edge_weight * edge_loss).detach().cpu())
            batches += 1
    return total / max(1, batches)


def _cause_loss(out: dict[str, Any], batch, F, *, config: dict[str, Any], pos_weight):
    logits = out["cause"]
    labels = batch["cause"].y.float()
    loss_kind = str(config.get("loss") or "bce").lower()
    weight = _node_sample_weights(batch, "cause")
    if loss_kind == "weighted_bce":
        element = F.binary_cross_entropy_with_logits(logits, labels, reduction="none", pos_weight=_expanded_pos_weight(pos_weight, labels))
    elif loss_kind == "focal":
        element = _focal_bce_with_logits(logits, labels, gamma=float(config.get("focal_gamma", 2.0)), pos_weight=_expanded_pos_weight(pos_weight, labels))
    else:
        element = F.binary_cross_entropy_with_logits(logits, labels, reduction="none")
    if weight is not None and weight.numel() == element.numel():
        element = element * weight
    return element.mean()


def _theory_loss(out: dict[str, Any], batch, F):
    element = F.binary_cross_entropy_with_logits(out["theory"], batch["theory"].y_alignment.float(), reduction="none")
    weight = _node_sample_weights(batch, "theory")
    if weight is not None and weight.numel() == element.numel():
        element = element * weight
    return element.mean()


def _theory_edge_loss(out: dict[str, Any], batch, F):
    try:
        labels = batch[THEORY_DEPENDS_EDGE_TYPE].edge_label.float()
    except Exception:
        return out["cause"].sum() * 0.0
    logits = out.get("theory_edge")
    if logits is None or logits.numel() == 0 or labels.numel() == 0:
        return out["cause"].sum() * 0.0
    element = F.binary_cross_entropy_with_logits(logits, labels, reduction="none")
    weight = _theory_edge_sample_weights(batch)
    if weight is not None and weight.numel() == element.numel():
        element = element * weight
    return element.mean()


def _focal_bce_with_logits(logits, labels, *, gamma: float, pos_weight):
    import torch
    import torch.nn.functional as F

    bce = F.binary_cross_entropy_with_logits(logits, labels, reduction="none", pos_weight=_expanded_pos_weight(pos_weight, labels))
    probability = torch.sigmoid(logits)
    p_t = probability * labels + (1.0 - probability) * (1.0 - labels)
    return bce * (1.0 - p_t).pow(float(gamma))


def _expanded_pos_weight(pos_weight, labels):
    if pos_weight is None or pos_weight.numel() == 0:
        return None
    if pos_weight.numel() == labels.numel():
        return pos_weight
    if labels.numel() % pos_weight.numel() == 0:
        return pos_weight.repeat(labels.numel() // pos_weight.numel())
    return None


def _pos_weight_from_dataset(dataset: list[Any], torch_module, *, max_value: float):
    if not dataset:
        return torch_module.empty(0)
    rows = []
    for data in dataset:
        try:
            rows.append(data["cause"].y.float())
        except Exception:
            pass
    if not rows:
        return torch_module.empty(0)
    matrix = torch_module.stack(rows)
    positives = matrix.sum(dim=0)
    negatives = matrix.shape[0] - positives
    weights = negatives / positives.clamp(min=1.0)
    weights = weights.clamp(min=1.0, max=float(max_value))
    return weights


def _node_sample_weights(batch, node_type: str):
    try:
        graph_weight = batch.graph_weight.float()
        node_batch = batch[node_type].batch
    except Exception:
        return None
    if graph_weight.numel() == 0 or node_batch.numel() == 0:
        return None
    return graph_weight[node_batch]


def _theory_edge_sample_weights(batch):
    try:
        graph_weight = batch.graph_weight.float()
        edge_index = batch[THEORY_DEPENDS_EDGE_TYPE].edge_index
        theory_batch = batch["theory"].batch
    except Exception:
        return None
    if edge_index.numel() == 0:
        return None
    return graph_weight[theory_batch[edge_index[0]]]


def _attach_graph_weights(dataset: list[Any], samples: list[DiagnosisGraphSample], config: dict[str, Any]) -> None:
    try:
        import torch
    except Exception:
        return
    for data, sample in zip(dataset, samples):
        weight = _sample_weight(sample, config)
        data.graph_weight = torch.tensor([weight], dtype=torch.float32)


def _sample_weight(sample: DiagnosisGraphSample, config: dict[str, Any]) -> float:
    if str(config.get("sample_weighting") or "").lower() in {"", "none", "false", "0"}:
        return 1.0
    root_count = len([label for label in sample.labels.field_labels if str(label).startswith("field:")])
    return min(2.0, 1.0 + 0.12 * max(0, root_count - 1))


def _autocast_context(device: str, enabled: bool):
    import torch
    active = bool(enabled) and str(device).startswith("cuda")
    if hasattr(torch, "amp"):
        return torch.amp.autocast("cuda", enabled=active)
    return torch.cuda.amp.autocast(enabled=active)


def _grad_scaler(torch_module, device: str, enabled: bool):
    active = bool(enabled) and str(device).startswith("cuda")
    if hasattr(torch_module, "amp"):
        return torch_module.amp.GradScaler("cuda", enabled=active)
    return torch_module.cuda.amp.GradScaler(enabled=active)


def _tensorize_split(samples: list[DiagnosisGraphSample], *, split: str, input_path: Path, config: dict[str, Any]) -> list[Any]:
    cache_dir = Path(str(config.get("tensor_cache_dir") or "")) if config.get("tensor_cache_dir") else None
    if cache_dir is None:
        return [tensorize_sample(sample) for sample in samples]
    try:
        import torch
    except Exception:
        return [tensorize_sample(sample) for sample in samples]
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_key = _tensor_cache_key(input_path, split)
    cache_path = cache_dir / f"{cache_key}.pt"
    if cache_path.is_file():
        loaded = torch.load(cache_path, map_location="cpu", weights_only=False)
        if isinstance(loaded, dict) and loaded.get("version") == TENSOR_CACHE_VERSION:
            return list(loaded.get("items") or [])
    items = [tensorize_sample(sample) for sample in samples]
    torch.save({"version": TENSOR_CACHE_VERSION, "items": items}, cache_path)
    return items


def _tensor_cache_key(input_path: Path, split: str) -> str:
    import hashlib

    raw = "|".join([
        TENSOR_CACHE_VERSION,
        str(input_path.resolve()),
        sha256_file(input_path) if input_path.is_file() else "",
        split,
        DIAGNOSIS_GRAPH_SCHEMA_VERSION,
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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
        from torch_geometric.loader import DataLoader
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
        loader = DataLoader(dataset, batch_size=32)
        for batch in loader:
            batch = batch.to(device)
            out = model(batch.x_dict, batch.edge_index_dict)
            cause_values = torch.sigmoid(out["cause"]).detach().cpu()
            theory_values = torch.sigmoid(out["theory"]).detach().cpu()
            cause_batch = batch["cause"].batch.detach().cpu()
            theory_batch = batch["theory"].batch.detach().cpu()
            edge_values = torch.sigmoid(out["theory_edge"]).detach().cpu()
            edge_batch = _edge_batch_for_predictions(batch)
            for index in range(int(getattr(batch, "num_graphs", 1) or 1)):
                scores.append(cause_values[cause_batch == index].tolist())
                labels.append(batch["cause"].y.detach().cpu()[cause_batch == index].tolist())
                theory_scores.append(theory_values[theory_batch == index].tolist())
                theory_labels.append(batch["theory"].y_alignment.detach().cpu()[theory_batch == index].tolist())
                if edge_batch is not None:
                    edge_scores.append(edge_values[edge_batch == index].tolist())
                    try:
                        edge_labels_all = batch[THEORY_DEPENDS_EDGE_TYPE].edge_label.detach().cpu()
                        edge_labels.append(edge_labels_all[edge_batch == index].tolist())
                    except Exception:
                        edge_labels.append([])
                else:
                    edge_scores.append([])
                    edge_labels.append([])
    return {
        "cause_scores": scores,
        "cause_labels": labels,
        "theory_scores": theory_scores,
        "theory_labels": theory_labels,
        "theory_edge_scores": edge_scores,
        "theory_edge_labels": edge_labels,
    }


def _edge_batch_for_predictions(batch):
    try:
        edge_index = batch[THEORY_DEPENDS_EDGE_TYPE].edge_index
        theory_batch = batch["theory"].batch.detach().cpu()
    except Exception:
        return None
    if edge_index.numel() == 0:
        return None
    return theory_batch[edge_index[0].detach().cpu()]


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
    cause_set = multilabel_set_metrics(predictions["cause_scores"], predictions["cause_labels"])
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
        "set_recall_top5": cause_set["recall_top5"],
        "set_recall_topN": cause_set["recall_topN"],
        "set_exact_top5": cause_set["exact_top5"],
        "set_exact_topN": cause_set["exact_topN"],
        "set_by_root_count": cause_set["by_root_count"],
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
