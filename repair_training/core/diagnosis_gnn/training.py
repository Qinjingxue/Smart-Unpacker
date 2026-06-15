from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from repair_training.core.datasets import sha256_file, write_json
from sunpack.model_runtime.diagnosis.graph_schema import DIAGNOSIS_GRAPH_SCHEMA_VERSION, DiagnosisGraphSample
from repair_training.core.diagnosis_gnn import DIAGNOSIS_GNN_ALGORITHM, DIAGNOSIS_GNN_SCORE_SEMANTICS, DIAGNOSIS_GNN_SEMANTICS
from repair_training.core.diagnosis_gnn.actionable_roots import ACTIONABLE_LABEL_SOURCE, ROOT_HYPOTHESIS_TRAINING_OBJECTIVE
from repair_training.core.diagnosis_gnn.dataset import read_diagnosis_graph_samples, split_diagnosis_graph_samples
from repair_training.core.diagnosis_gnn.metrics import (
    binary_multilabel_metrics,
    calibrate_global_threshold,
    clean_false_positive_rate,
    multilabel_set_metrics,
)
from sunpack.model_runtime.diagnosis.model import build_diagnosis_gnn_model, normalize_diagnosis_gnn_arch
from sunpack.model_runtime.diagnosis.root_cases import ROOT_CASES
from sunpack.model_runtime.diagnosis.tensorize import (
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
    "asym_gamma_pos": 1.0,
    "asym_gamma_neg": 3.0,
    "rank_loss_weight": 0.0,
    "rank_loss_top_negatives": 8,
    "root_softmax_loss_weight": 0.0,
    "root_evidence_loss_weight": 0.15,
    "root_transition_gain_loss_weight": 0.20,
    "root_probe_viability_loss_weight": 0.35,
    "probe_pairwise_loss_weight": 0.35,
    "probe_viability_pairwise_loss_weight": 0.35,
    "same_state_gain_rank_loss_weight": 0.80,
    "hard_negative_suppression_loss_weight": 0.80,
    "priority_direct_weight": 0.45,
    "priority_evidence_weight": 0.10,
    "priority_transition_gain_weight": 0.25,
    "priority_viability_weight": 0.20,
    "pos_weight_max": 8.0,
    "sample_weighting": "multi_field_root_count",
    "score_normalization": "raw",
}

TENSOR_CACHE_VERSION = "diagnosis_gnn_tensor_cache_actionable_root_v2"


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
            "Install the project training extra."
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
                out = model(batch.x_dict, batch.edge_index_dict, _batch_dict(batch))
                cause_loss = _root_case_loss(out, batch, F, config=config, pos_weight=cause_pos_weight)
                rank_loss = _set_rank_loss(out, batch, config=config)
                softmax_loss = _root_softmax_loss(out, batch)
                theory_loss = _theory_loss(out, batch, F)
                edge_loss = _theory_edge_loss(out, batch, F)
                evidence_loss = _root_evidence_loss(out, batch, F)
                transition_loss = _root_transition_gain_loss(out, batch, F)
                viability_loss = _root_probe_viability_loss(out, batch, F)
                probe_rank_loss = _probe_pairwise_rank_loss(out, batch)
                viability_rank_loss = _probe_viability_pairwise_rank_loss(out, batch)
                same_state_rank_loss = _same_state_gain_rank_loss(out, batch)
                hard_negative_loss = _hard_negative_suppression_loss(out, batch)
                loss = (
                    cause_loss
                    + float(config.get("rank_loss_weight", 0.0) or 0.0) * rank_loss
                    + float(config.get("root_softmax_loss_weight", 0.0) or 0.0) * softmax_loss
                    + float(config["aux_loss_weight"]) * theory_loss
                    + float(config["edge_loss_weight"]) * edge_loss
                    + float(config.get("root_evidence_loss_weight", 0.0) or 0.0) * evidence_loss
                    + float(config.get("root_transition_gain_loss_weight", 0.0) or 0.0) * transition_loss
                    + float(config.get("root_probe_viability_loss_weight", 0.0) or 0.0) * viability_loss
                    + float(config.get("probe_pairwise_loss_weight", 0.0) or 0.0) * probe_rank_loss
                    + float(config.get("probe_viability_pairwise_loss_weight", 0.0) or 0.0) * viability_rank_loss
                    + float(config.get("same_state_gain_rank_loss_weight", 0.0) or 0.0) * same_state_rank_loss
                    + float(config.get("hard_negative_suppression_loss_weight", 0.0) or 0.0) * hard_negative_loss
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
    thresholds = _calibrate_thresholds(valid_pred or train_pred, label_names=_cause_label_names(samples))
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
        "score_semantics": DIAGNOSIS_GNN_SCORE_SEMANTICS,
        "label_source": ACTIONABLE_LABEL_SOURCE,
        "training_objective": ROOT_HYPOTHESIS_TRAINING_OBJECTIVE,
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
                out = model(batch.x_dict, batch.edge_index_dict, _batch_dict(batch))
                cause_loss = _root_case_loss(out, batch, F, config=config, pos_weight=cause_pos_weight)
                rank_loss = _set_rank_loss(out, batch, config=config)
                softmax_loss = _root_softmax_loss(out, batch)
                theory_loss = _theory_loss(out, batch, F)
                edge_loss = _theory_edge_loss(out, batch, F)
                evidence_loss = _root_evidence_loss(out, batch, F)
                transition_loss = _root_transition_gain_loss(out, batch, F)
                viability_loss = _root_probe_viability_loss(out, batch, F)
                probe_rank_loss = _probe_pairwise_rank_loss(out, batch)
                viability_rank_loss = _probe_viability_pairwise_rank_loss(out, batch)
                same_state_rank_loss = _same_state_gain_rank_loss(out, batch)
                hard_negative_loss = _hard_negative_suppression_loss(out, batch)
            total += float((
                cause_loss
                + float(config.get("rank_loss_weight", 0.0) or 0.0) * rank_loss
                + float(config.get("root_softmax_loss_weight", 0.0) or 0.0) * softmax_loss
                + aux_weight * theory_loss
                + edge_weight * edge_loss
                + float(config.get("root_evidence_loss_weight", 0.0) or 0.0) * evidence_loss
                + float(config.get("root_transition_gain_loss_weight", 0.0) or 0.0) * transition_loss
                + float(config.get("root_probe_viability_loss_weight", 0.0) or 0.0) * viability_loss
                + float(config.get("probe_pairwise_loss_weight", 0.0) or 0.0) * probe_rank_loss
                + float(config.get("probe_viability_pairwise_loss_weight", 0.0) or 0.0) * viability_rank_loss
                + float(config.get("same_state_gain_rank_loss_weight", 0.0) or 0.0) * same_state_rank_loss
                + float(config.get("hard_negative_suppression_loss_weight", 0.0) or 0.0) * hard_negative_loss
            ).detach().cpu())
            batches += 1
    return total / max(1, batches)


def _root_case_loss(out: dict[str, Any], batch, F, *, config: dict[str, Any], pos_weight):
    logits = out["root_case"]
    labels = batch.root_case_y.float().view_as(logits)
    loss_kind = str(config.get("loss") or "bce").lower()
    weight = _graph_sample_weights(batch, logits)
    if loss_kind == "weighted_bce":
        element = F.binary_cross_entropy_with_logits(logits, labels, reduction="none", pos_weight=_expanded_pos_weight(pos_weight, labels))
    elif loss_kind == "focal":
        element = _focal_bce_with_logits(logits, labels, gamma=float(config.get("focal_gamma", 2.0)), pos_weight=_expanded_pos_weight(pos_weight, labels))
    elif loss_kind == "asymmetric_focal":
        element = _asymmetric_focal_bce_with_logits(
            logits,
            labels,
            gamma_pos=float(config.get("asym_gamma_pos", 1.0)),
            gamma_neg=float(config.get("asym_gamma_neg", 3.0)),
            pos_weight=_expanded_pos_weight(pos_weight, labels),
        )
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
        return out["root_case"].sum() * 0.0
    logits = out.get("theory_edge")
    if logits is None or logits.numel() == 0 or labels.numel() == 0:
        return out["root_case"].sum() * 0.0
    element = F.binary_cross_entropy_with_logits(logits, labels, reduction="none")
    weight = _theory_edge_sample_weights(batch)
    if weight is not None and weight.numel() == element.numel():
        element = element * weight
    return element.mean()


def _root_evidence_loss(out: dict[str, Any], batch, F):
    if "root_evidence" not in out or not hasattr(batch, "root_evidence_y"):
        return out["root_case"].sum() * 0.0
    labels = batch.root_evidence_y.float().view_as(out["root_evidence"])
    mask = batch.root_evidence_mask.float().view_as(labels) if hasattr(batch, "root_evidence_mask") else (labels >= 0.0).float()
    if float(mask.sum().detach().cpu()) <= 0.0:
        return out["root_case"].sum() * 0.0
    element = F.binary_cross_entropy_with_logits(out["root_evidence"], labels.clamp(0.0, 1.0), reduction="none")
    return (element * mask).sum() / mask.sum().clamp(min=1.0)


def _root_transition_gain_loss(out: dict[str, Any], batch, F):
    if "root_transition_gain" not in out or not hasattr(batch, "root_transition_gain_y"):
        return out["root_case"].sum() * 0.0
    labels = batch.root_transition_gain_y.float().view_as(out["root_transition_gain"])
    mask = batch.root_transition_gain_mask.float().view_as(labels) if hasattr(batch, "root_transition_gain_mask") else (labels >= 0.0).float()
    if float(mask.sum().detach().cpu()) <= 0.0:
        return out["root_case"].sum() * 0.0
    prediction = out["root_transition_gain"].sigmoid()
    element = F.smooth_l1_loss(prediction, labels.clamp(0.0, 1.0), reduction="none")
    return (element * mask).sum() / mask.sum().clamp(min=1.0)


def _root_probe_viability_loss(out: dict[str, Any], batch, F):
    if "root_probe_viability" not in out or not hasattr(batch, "root_probe_viability_y"):
        return out["root_case"].sum() * 0.0
    labels = batch.root_probe_viability_y.float().view_as(out["root_probe_viability"])
    mask = batch.root_probe_viability_mask.float().view_as(labels) if hasattr(batch, "root_probe_viability_mask") else (labels >= 0.0).float()
    if float(mask.sum().detach().cpu()) <= 0.0:
        return out["root_case"].sum() * 0.0
    element = F.binary_cross_entropy_with_logits(out["root_probe_viability"], labels.clamp(0.0, 1.0), reduction="none")
    return (element * mask).sum() / mask.sum().clamp(min=1.0)


def _probe_pairwise_rank_loss(out: dict[str, Any], batch):
    import torch
    import torch.nn.functional as F

    if not hasattr(batch, "root_transition_gain_y"):
        return out["root_case"].sum() * 0.0
    labels = batch.root_transition_gain_y.float().view_as(out["root_case"])
    mask = batch.root_transition_gain_mask.float().view_as(labels) if hasattr(batch, "root_transition_gain_mask") else (labels >= 0.0).float()
    logits = out["root_case"]
    losses = []
    for index in range(labels.shape[0]):
        valid = mask[index] > 0.0
        if int(valid.sum().item()) < 2:
            continue
        values = labels[index][valid]
        scores = logits[index][valid]
        gap = values.view(-1, 1) - values.view(1, -1)
        comparable = gap > 0.03
        if int(comparable.sum().item()) <= 0:
            continue
        score_gap = scores.view(-1, 1) - scores.view(1, -1)
        losses.append(F.softplus(0.05 - score_gap[comparable]).mean())
    if not losses:
        return logits.sum() * 0.0
    return torch.stack(losses).mean()


def _probe_viability_pairwise_rank_loss(out: dict[str, Any], batch):
    import torch
    import torch.nn.functional as F

    if "root_probe_viability" not in out or not hasattr(batch, "root_probe_viability_y"):
        return out["root_case"].sum() * 0.0
    labels = batch.root_probe_viability_y.float().view_as(out["root_probe_viability"])
    mask = batch.root_probe_viability_mask.float().view_as(labels) if hasattr(batch, "root_probe_viability_mask") else (labels >= 0.0).float()
    logits = out["root_case"] + 0.5 * out["root_probe_viability"]
    losses = []
    for index in range(labels.shape[0]):
        valid = mask[index] > 0.0
        if int(valid.sum().item()) < 2:
            continue
        values = labels[index][valid]
        scores = logits[index][valid]
        gap = values.view(-1, 1) - values.view(1, -1)
        comparable = gap > 0.30
        if int(comparable.sum().item()) <= 0:
            continue
        score_gap = scores.view(-1, 1) - scores.view(1, -1)
        losses.append(F.softplus(0.10 - score_gap[comparable]).mean())
    if not losses:
        return logits.sum() * 0.0
    return torch.stack(losses).mean()


def _same_state_gain_rank_loss(out: dict[str, Any], batch):
    import torch
    import torch.nn.functional as F

    if not hasattr(batch, "root_positive_probe_y") or not hasattr(batch, "root_hard_negative_y"):
        return out["root_case"].sum() * 0.0
    positives = batch.root_positive_probe_y.float().view_as(out["root_case"])
    positive_mask = batch.root_positive_probe_mask.float().view_as(positives) if hasattr(batch, "root_positive_probe_mask") else (positives > 0.0).float()
    hard_negatives = batch.root_hard_negative_y.float().view_as(out["root_case"])
    hard_negative_mask = batch.root_hard_negative_mask.float().view_as(hard_negatives) if hasattr(batch, "root_hard_negative_mask") else (hard_negatives > 0.0).float()
    logits = out["root_case"]
    losses = []
    for index in range(logits.shape[0]):
        pos = (positive_mask[index] > 0.0) & (positives[index] > 0.0)
        neg = (hard_negative_mask[index] > 0.0) & (hard_negatives[index] > 0.0)
        if int(pos.sum().item()) <= 0 or int(neg.sum().item()) <= 0:
            continue
        pos_scores = logits[index][pos]
        neg_scores = logits[index][neg]
        pos_values = positives[index][pos].clamp(min=0.05)
        margin = (0.08 + 0.12 * pos_values).view(-1, 1)
        losses.append(F.softplus(margin - (pos_scores.view(-1, 1) - neg_scores.view(1, -1))).mean())
    if not losses:
        return logits.sum() * 0.0
    return torch.stack(losses).mean()


def _hard_negative_suppression_loss(out: dict[str, Any], batch):
    import torch
    import torch.nn.functional as F

    if not hasattr(batch, "root_hard_negative_y"):
        return out["root_case"].sum() * 0.0
    hard_negatives = batch.root_hard_negative_y.float().view_as(out["root_case"])
    mask = batch.root_hard_negative_mask.float().view_as(hard_negatives) if hasattr(batch, "root_hard_negative_mask") else (hard_negatives > 0.0).float()
    active = (mask > 0.0) & (hard_negatives > 0.0)
    if int(active.sum().item()) <= 0:
        return out["root_case"].sum() * 0.0
    return F.softplus(out["root_case"][active] - 0.15).mean()


def _focal_bce_with_logits(logits, labels, *, gamma: float, pos_weight):
    import torch
    import torch.nn.functional as F

    bce = F.binary_cross_entropy_with_logits(logits, labels, reduction="none", pos_weight=_expanded_pos_weight(pos_weight, labels))
    probability = torch.sigmoid(logits)
    p_t = probability * labels + (1.0 - probability) * (1.0 - labels)
    return bce * (1.0 - p_t).pow(float(gamma))


def _asymmetric_focal_bce_with_logits(logits, labels, *, gamma_pos: float, gamma_neg: float, pos_weight):
    import torch
    import torch.nn.functional as F

    bce = F.binary_cross_entropy_with_logits(logits, labels, reduction="none", pos_weight=_expanded_pos_weight(pos_weight, labels))
    probability = torch.sigmoid(logits)
    factors = labels * (1.0 - probability).pow(float(gamma_pos)) + (1.0 - labels) * probability.pow(float(gamma_neg))
    return bce * factors


def _set_rank_loss(out: dict[str, Any], batch, *, config: dict[str, Any]):
    import torch
    import torch.nn.functional as F

    if float(config.get("rank_loss_weight", 0.0) or 0.0) <= 0.0:
        return out["root_case"].sum() * 0.0
    logits = out["root_case"]
    labels = batch.root_case_y.float().view_as(logits)
    top_negatives = max(1, int(config.get("rank_loss_top_negatives", 8) or 8))
    losses = []
    for graph_index in range(int(getattr(batch, "num_graphs", logits.shape[0]) or logits.shape[0])):
        graph_logits = logits[graph_index]
        graph_labels = labels[graph_index]
        positives = graph_logits[graph_labels >= 0.5]
        negatives = graph_logits[graph_labels < 0.5]
        if positives.numel() == 0 or negatives.numel() == 0:
            continue
        hard_negatives = torch.topk(negatives, k=min(top_negatives, negatives.numel())).values
        losses.append(F.softplus(hard_negatives.view(1, -1) - positives.view(-1, 1)).mean())
    if not losses:
        return logits.sum() * 0.0
    return torch.stack(losses).mean()


def _root_softmax_loss(out: dict[str, Any], batch):
    import torch
    import torch.nn.functional as F

    logits = out["root_case"]
    labels = batch.root_case_y.float().view_as(logits)
    positive_counts = labels.sum(dim=-1, keepdim=True)
    valid = positive_counts.squeeze(-1) > 0.0
    if int(valid.sum().item()) <= 0:
        return logits.sum() * 0.0
    targets = labels[valid] / positive_counts[valid].clamp(min=1.0)
    log_probs = F.log_softmax(logits[valid], dim=-1)
    losses = -(targets * log_probs).sum(dim=-1)
    try:
        graph_weight = batch.graph_weight.float().to(logits.device)[valid]
        if graph_weight.numel() == losses.numel():
            losses = losses * graph_weight
    except Exception:
        pass
    return losses.mean()


def _expanded_pos_weight(pos_weight, labels):
    if pos_weight is None or pos_weight.numel() == 0:
        return None
    if labels.dim() >= 2 and pos_weight.numel() == labels.shape[-1]:
        return pos_weight
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
            rows.append(data.root_case_y.float())
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


def _graph_sample_weights(batch, logits):
    try:
        graph_weight = batch.graph_weight.float().to(logits.device)
    except Exception:
        return None
    if graph_weight.numel() == logits.shape[0]:
        return graph_weight.view(-1, 1)
    return None


def _batch_dict(batch) -> dict[str, Any]:
    output = {}
    for node_type in batch.x_dict:
        try:
            output[node_type] = batch[node_type].batch
        except Exception:
            pass
    return output


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
    root_count = len(sample.labels.root_case_labels)
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
            "root_scores": [],
            "root_labels": [],
            "theory_scores": [],
            "theory_labels": [],
            "theory_edge_scores": [],
            "theory_edge_labels": [],
        "root_evidence_scores": [],
        "root_evidence_labels": [],
        "transition_gain_scores": [],
        "transition_gain_labels": [],
        "probe_viability_scores": [],
        "probe_viability_labels": [],
        "positive_probe_labels": [],
        "hard_negative_labels": [],
        }
    try:
        import torch
        from torch_geometric.loader import DataLoader
    except Exception:
        return {"root_scores": [], "root_labels": [], "theory_scores": [], "theory_labels": []}
    scores = []
    labels = []
    theory_scores = []
    theory_labels = []
    edge_scores = []
    edge_labels = []
    root_evidence_scores = []
    root_evidence_labels = []
    transition_gain_scores = []
    transition_gain_labels = []
    probe_viability_scores = []
    probe_viability_labels = []
    positive_probe_labels = []
    hard_negative_labels = []
    model.eval()
    with torch.no_grad():
        loader = DataLoader(dataset, batch_size=32)
        for batch in loader:
            batch = batch.to(device)
            out = model(batch.x_dict, batch.edge_index_dict, _batch_dict(batch))
            root_values = torch.sigmoid(out["root_case"]).detach().cpu()
            theory_values = torch.sigmoid(out["theory"]).detach().cpu()
            theory_batch = batch["theory"].batch.detach().cpu()
            edge_values = torch.sigmoid(out["theory_edge"]).detach().cpu()
            root_evidence_values = torch.sigmoid(out.get("root_evidence", out["root_case"])).detach().cpu()
            transition_gain_values = torch.sigmoid(out.get("root_transition_gain", out["root_case"])).detach().cpu()
            probe_viability_values = torch.sigmoid(out.get("root_probe_viability", out["root_case"])).detach().cpu()
            edge_batch = _edge_batch_for_predictions(batch)
            for index in range(int(getattr(batch, "num_graphs", 1) or 1)):
                scores.append(root_values[index].tolist())
                labels.append(batch.root_case_y.detach().cpu().view(root_values.shape)[index].tolist())
                root_evidence_scores.append(root_evidence_values[index].tolist())
                root_evidence_labels.append(_masked_label_row(batch, "root_evidence_y", "root_evidence_mask", index, root_evidence_values.shape))
                transition_gain_scores.append(transition_gain_values[index].tolist())
                transition_gain_labels.append(_masked_label_row(batch, "root_transition_gain_y", "root_transition_gain_mask", index, transition_gain_values.shape))
                probe_viability_scores.append(probe_viability_values[index].tolist())
                probe_viability_labels.append(_masked_label_row(batch, "root_probe_viability_y", "root_probe_viability_mask", index, probe_viability_values.shape))
                positive_probe_labels.append(_masked_label_row(batch, "root_positive_probe_y", "root_positive_probe_mask", index, root_values.shape))
                hard_negative_labels.append(_masked_label_row(batch, "root_hard_negative_y", "root_hard_negative_mask", index, root_values.shape))
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
        "root_scores": scores,
        "root_labels": labels,
        "theory_scores": theory_scores,
        "theory_labels": theory_labels,
        "theory_edge_scores": edge_scores,
        "theory_edge_labels": edge_labels,
        "root_evidence_scores": root_evidence_scores,
        "root_evidence_labels": root_evidence_labels,
        "transition_gain_scores": transition_gain_scores,
        "transition_gain_labels": transition_gain_labels,
        "probe_viability_scores": probe_viability_scores,
        "probe_viability_labels": probe_viability_labels,
        "positive_probe_labels": positive_probe_labels,
        "hard_negative_labels": hard_negative_labels,
    }


def _masked_label_row(batch, label_name: str, mask_name: str, index: int, shape) -> list[float]:
    if not hasattr(batch, label_name):
        return [-1.0] * int(shape[-1])
    labels = getattr(batch, label_name).detach().cpu().view(shape)
    if not hasattr(batch, mask_name):
        return labels[index].tolist()
    mask = getattr(batch, mask_name).detach().cpu().view(shape)
    return [
        float(value) if float(mask_value) > 0.0 else -1.0
        for value, mask_value in zip(labels[index].tolist(), mask[index].tolist())
    ]


def _edge_batch_for_predictions(batch):
    try:
        edge_index = batch[THEORY_DEPENDS_EDGE_TYPE].edge_index
        theory_batch = batch["theory"].batch.detach().cpu()
    except Exception:
        return None
    if edge_index.numel() == 0:
        return None
    return theory_batch[edge_index[0].detach().cpu()]


def _calibrate_thresholds(predictions: dict[str, Any], *, label_names: list[str]) -> dict[str, Any]:
    root = calibrate_global_threshold(predictions["root_scores"], predictions["root_labels"])
    theory = calibrate_global_threshold(predictions["theory_scores"], predictions["theory_labels"], max_clean_false_positive_rate=None)
    theory_edge = calibrate_global_threshold(
        predictions.get("theory_edge_scores", []),
        predictions.get("theory_edge_labels", []),
        max_clean_false_positive_rate=None,
    )
    label_thresholds = _calibrate_label_thresholds(predictions["root_scores"], predictions["root_labels"], label_names)
    return {
        "selection_split": "valid",
        "root_case": root,
        "theory_alignment": theory,
        "theory_edge_alignment": theory_edge,
        "default_threshold": float(root.get("threshold", 0.5)),
        "root_case_threshold": float(root.get("threshold", 0.5)),
        "root_case_label_thresholds": label_thresholds,
    }


def _calibrate_label_thresholds(scores: list[list[float]], labels: list[list[float]], label_names: list[str]) -> dict[str, float]:
    output: dict[str, float] = {}
    for index, label_name in enumerate(label_names):
        if not label_name:
            continue
        column_scores = [[float(row[index])] for row in scores if index < len(row)]
        column_labels = [[float(row[index])] for row in labels if index < len(row)]
        if not column_scores:
            continue
        output[label_name] = float(calibrate_global_threshold(
            column_scores,
            column_labels,
            max_clean_false_positive_rate=None,
        ).get("threshold", 0.5))
    return output


def _metrics_from_predictions(predictions: dict[str, Any], *, thresholds: dict[str, Any]) -> dict[str, Any]:
    root_threshold = float((thresholds.get("root_case") or {}).get("threshold", thresholds.get("default_threshold", 0.5)))
    theory_threshold = float((thresholds.get("theory_alignment") or {}).get("threshold", 0.5))
    theory_edge_threshold = float((thresholds.get("theory_edge_alignment") or {}).get("threshold", theory_threshold))
    root = binary_multilabel_metrics(predictions["root_scores"], predictions["root_labels"], threshold=root_threshold)
    root_set = multilabel_set_metrics(predictions["root_scores"], predictions["root_labels"])
    theory = binary_multilabel_metrics(predictions["theory_scores"], predictions["theory_labels"], threshold=theory_threshold)
    theory_edge = binary_multilabel_metrics(
        predictions.get("theory_edge_scores", []),
        predictions.get("theory_edge_labels", []),
        threshold=theory_edge_threshold,
    )
    return {
        "rows": len(predictions["root_scores"]),
        "root_case_threshold": root_threshold,
        "root_case_micro_f1": root["micro_f1"],
        "root_case_micro_precision": root["micro_precision"],
        "root_case_micro_recall": root["micro_recall"],
        "root_case_top1_hit": root["top1_hit"],
        "root_case_top3_hit": root["top3_hit"],
        "root_case_top5_hit": root["top5_hit"],
        "set_recall_top5": root_set["recall_top5"],
        "set_recall_topN": root_set["recall_topN"],
        "set_exact_top5": root_set["exact_top5"],
        "set_exact_topN": root_set["exact_topN"],
        "set_by_root_count": root_set["by_root_count"],
        "theory_alignment_threshold": theory_threshold,
        "theory_alignment_f1": theory["micro_f1"],
        "theory_edge_alignment_threshold": theory_edge_threshold,
        "theory_edge_alignment_f1": theory_edge["micro_f1"],
        "root_transition_gain_mae": _masked_mae(
            predictions.get("transition_gain_scores", []),
            predictions.get("transition_gain_labels", []),
        ),
        "root_probe_viability_mae": _masked_mae(
            predictions.get("probe_viability_scores", []),
            predictions.get("probe_viability_labels", []),
        ),
        "probe_viability_f1": _masked_binary_f1(
            predictions.get("probe_viability_scores", []),
            predictions.get("probe_viability_labels", []),
        ),
        "evidence_explanation_f1": _masked_binary_f1(
            predictions.get("root_evidence_scores", []),
            predictions.get("root_evidence_labels", []),
        ),
        "probe_pairwise_accuracy": _probe_pairwise_accuracy(
            predictions.get("root_scores", []),
            predictions.get("transition_gain_labels", []),
        ),
        "probe_viability_pairwise_accuracy": _probe_pairwise_accuracy(
            predictions.get("root_scores", []),
            predictions.get("probe_viability_labels", []),
        ),
        "same_state_gain_pairwise_accuracy": _positive_vs_hard_negative_accuracy(
            predictions.get("root_scores", []),
            predictions.get("positive_probe_labels", []),
            predictions.get("hard_negative_labels", []),
        ),
        "clean_false_positive_rate": clean_false_positive_rate(predictions["root_scores"], predictions["root_labels"], threshold=root_threshold),
    }


def _masked_mae(scores: list[list[float]], labels: list[list[float]]) -> float:
    errors = []
    for score_row, label_row in zip(scores, labels):
        for score, label in zip(score_row, label_row):
            if float(label) >= 0.0:
                errors.append(abs(float(score) - float(label)))
    return sum(errors) / max(1, len(errors))


def _masked_binary_f1(scores: list[list[float]], labels: list[list[float]], *, threshold: float = 0.5) -> float:
    tp = fp = fn = 0
    for score_row, label_row in zip(scores, labels):
        for score, label in zip(score_row, label_row):
            if float(label) < 0.0:
                continue
            pred = float(score) >= threshold
            truth = float(label) >= threshold
            tp += int(pred and truth)
            fp += int(pred and not truth)
            fn += int((not pred) and truth)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    return 0.0 if precision + recall <= 0.0 else 2 * precision * recall / (precision + recall)


def _probe_pairwise_accuracy(scores: list[list[float]], gain_labels: list[list[float]]) -> float:
    correct = total = 0
    for score_row, label_row in zip(scores, gain_labels):
        for left in range(len(label_row)):
            if float(label_row[left]) < 0.0:
                continue
            for right in range(len(label_row)):
                if left == right or float(label_row[right]) < 0.0:
                    continue
                if float(label_row[left]) <= float(label_row[right]) + 0.03:
                    continue
                total += 1
                correct += int(float(score_row[left]) > float(score_row[right]))
    return correct / max(1, total)


def _positive_vs_hard_negative_accuracy(
    scores: list[list[float]],
    positive_labels: list[list[float]],
    hard_negative_labels: list[list[float]],
) -> float:
    correct = total = 0
    for score_row, positive_row, hard_row in zip(scores, positive_labels, hard_negative_labels):
        positives = [
            index for index, value in enumerate(positive_row)
            if float(value) > 0.0 and index < len(score_row)
        ]
        negatives = [
            index for index, value in enumerate(hard_row)
            if float(value) > 0.0 and index < len(score_row)
        ]
        for pos in positives:
            for neg in negatives:
                total += 1
                correct += int(float(score_row[pos]) > float(score_row[neg]))
    return correct / max(1, total)


def _label_schema(samples: list[DiagnosisGraphSample]) -> dict[str, Any]:
    return {
        "labels": list(ROOT_CASES),
        "metadata": {
            "kind": "diagnosis_gnn_root_case",
            "diagnosis_semantics": DIAGNOSIS_GNN_SEMANTICS,
            "score_semantics": DIAGNOSIS_GNN_SCORE_SEMANTICS,
            "label_source": ACTIONABLE_LABEL_SOURCE,
            "training_objective": ROOT_HYPOTHESIS_TRAINING_OBJECTIVE,
        },
    }


def _cause_label_names(samples: list[DiagnosisGraphSample]) -> list[str]:
    if not samples:
        return []
    return list(ROOT_CASES)


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
