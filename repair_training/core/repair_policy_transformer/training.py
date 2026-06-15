from __future__ import annotations

from pathlib import Path
from typing import Any

from repair_training.core.datasets import write_json
from repair_training.core.repair_policy_transformer import POLICY_TRANSFORMER_ALGORITHM, POLICY_TRANSFORMER_SEMANTICS
from repair_training.core.repair_policy_transformer.dataset import read_policy_graph_samples, read_policy_world_samples, split_policy_graph_samples, split_policy_world_samples
from sunpack.repair.model.policy.model import build_repair_policy_transformer
from sunpack.repair.model.policy.tensorize import EDGE_FEATURE_DIM, NODE_FEATURE_DIM, tensorize_sample, tensorize_world_sample


DEFAULT_CONFIG = {
    "hidden_dim": 128,
    "heads": 4,
    "layers": 2,
    "dropout": 0.15,
    "epochs": 1,
    "batch_size": 8,
    "lr": 1e-3,
    "weight_decay": 1e-4,
    "rank_loss_weight": 0.35,
    "softmax_loss_weight": 1.0,
    "q_regression_weight": 0.10,
    "premature_stop_loss_weight": 1.0,
    "undo_loss_weight": 0.5,
    "promising_loss_weight": 0.35,
    "continuation_loss_weight": 0.8,
    "action_continuation_loss_weight": 1.0,
    "continuation_rank_loss_weight": 0.0,
    "continuation_rank_margin": 0.08,
    "post_undo_switch_loss_weight": 0.0,
    "post_module_deepen_loss_weight": 0.0,
    "branch_context_margin": 0.12,
    "continuation_score_fusion_weight": 0.0,
    "stop_margin": 0.02,
    "q_margin": 0.01,
    "q_temperature": 0.05,
    "best_tie_margin": 0.02,
    "rank_q_gap_min": 0.04,
    "undo_margin": 0.04,
    "transition_loss_weight": 0.5,
    "uncertainty_loss_weight": 0.20,
    "uncertainty_tiebreak_loss_weight": 0.15,
    "masked_graph_loss_weight": 0.25,
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
    input_path = Path(input_path)
    if "world" in input_path.name:
        return _train_world_policy_transformer(
            input_path=input_path,
            model_dir=model_dir,
            run_id=run_id,
            format_name=format_name,
            config=config,
            device=device,
            torch=torch,
            F=F,
        )
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
        used = 0
        train_batches = list(_batches(train_data, int(config.get("batch_size", 8) or 8)))
        for batch in train_batches:
            optimizer.zero_grad()
            batch_loss = None
            batch_used = 0
            for item in batch:
                logits = model(
                    item["node_x"].to(resolved_device),
                    item["memory_x"].to(resolved_device),
                    item["action_x"].to(resolved_device),
                    item["edge_x"].to(resolved_device),
                )
                q = item["q"].to(resolved_device).view_as(logits)
                prior = item["prior"].to(resolved_device).view_as(logits)
                promising_logit = model.promising_logit(item["node_x"].to(resolved_device), item["memory_x"].to(resolved_device), item["edge_x"].to(resolved_device))
                continuation_logit = model.continuation_logit(item["node_x"].to(resolved_device), item["memory_x"].to(resolved_device), item["edge_x"].to(resolved_device))
                promising = item["has_promising_future"].to(resolved_device).view_as(promising_logit)
                loss_parts = _policy_loss_parts(
                    logits=logits,
                    q=q,
                    prior=prior,
                    actions=item["actions"],
                    promising_logit=promising_logit,
                    promising=promising,
                    continuation_logit=continuation_logit,
                    continue_branch=item["continue_branch"].to(resolved_device).view_as(continuation_logit),
                    action_continue_logits=None,
                    action_continue_target=item["action_continue_target"].to(resolved_device).view_as(logits),
                    action_continue_mask=item["action_continue_mask"].to(resolved_device).view_as(logits),
                    action_uncertainty=item["action_uncertainty"].to(resolved_device).view_as(logits),
                    config=config,
                    F=F,
                )
                batch_loss = loss_parts["total"] if batch_loss is None else batch_loss + loss_parts["total"]
                batch_used += 1
            if batch_loss is None:
                continue
            loss = batch_loss / max(1, batch_used)
            loss.backward()
            optimizer.step()
            total += float(loss.detach().cpu())
            used += batch_used
        history.append({"epoch": epoch, "train_loss": total / max(1, len(train_batches)), "train_items": used, "batch_size": int(config.get("batch_size", 8) or 8)})
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
    write_json(model_dir / "graph_schema.json", {"schema": "policy_loop.graph", "node_feature_dim": NODE_FEATURE_DIM, "edge_feature_dim": EDGE_FEATURE_DIM})
    write_json(model_dir / "action_schema.json", {"actions": ["stop", "undo", "module"], "semantics": POLICY_TRANSFORMER_SEMANTICS})
    write_json(model_dir / "train_metrics.json", metrics)
    return metrics


def _train_world_policy_transformer(
    *,
    input_path: Path,
    model_dir: str | Path,
    run_id: str,
    format_name: str,
    config: dict[str, Any],
    device: str,
    torch,
    F,
) -> dict[str, Any]:
    samples = read_policy_world_samples(input_path)
    if not samples:
        raise SystemExit(f"no policy world samples found: {input_path}")
    config = {**DEFAULT_CONFIG, **dict(config or {})}
    splits = split_policy_world_samples(samples)
    resolved_device = _resolve_device(device, torch)
    model = build_repair_policy_transformer(config).to(resolved_device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=float(config["lr"]), weight_decay=float(config["weight_decay"]))
    train_data = [tensorize_world_sample(sample) for sample in splits["train"]]
    history = []
    for epoch in range(1, max(1, int(config["epochs"])) + 1):
        model.train()
        total = 0.0
        used = 0
        train_batches = list(_batches(train_data, int(config.get("batch_size", 8) or 8)))
        for batch in train_batches:
            optimizer.zero_grad()
            batch_loss = None
            batch_used = 0
            for item in batch:
                outputs = model.forward_all(
                    item["node_x"].to(resolved_device),
                    item["memory_x"].to(resolved_device),
                    item["action_x"].to(resolved_device),
                    item["edge_x"].to(resolved_device),
                )
                item_loss = _world_loss(item, outputs, config=config, F=F, device=resolved_device)
                batch_loss = item_loss if batch_loss is None else batch_loss + item_loss
                batch_used += 1
            if batch_loss is None:
                continue
            loss = batch_loss / max(1, batch_used)
            loss.backward()
            optimizer.step()
            total += float(loss.detach().cpu())
            used += batch_used
        history.append({"epoch": epoch, "train_loss": total / max(1, len(train_batches)), "train_items": used, "batch_size": int(config.get("batch_size", 8) or 8)})
    metrics = {
        "samples": {split: len(rows) for split, rows in splits.items()},
        "task_counts": _task_counts(samples),
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
    write_json(model_dir / "graph_schema.json", {"schema": "repair_policy_world_row_v1", "node_feature_dim": NODE_FEATURE_DIM, "edge_feature_dim": EDGE_FEATURE_DIM})
    write_json(model_dir / "action_schema.json", {"actions": ["stop", "undo", "module"], "semantics": POLICY_TRANSFORMER_SEMANTICS})
    write_json(model_dir / "train_metrics.json", metrics)
    return metrics


def _world_loss(item: dict[str, Any], outputs: dict[str, Any], *, config: dict[str, Any], F, device: str):
    task = str(item.get("task") or "")
    loss = outputs["action_logits"].sum() * 0.0
    if task in {"ranking", "transition"}:
        q = item["q"].to(device).view_as(outputs["action_logits"])
        prior = item["prior"].to(device).view_as(outputs["action_logits"])
        promising = item["has_promising_future"].to(device).view_as(outputs["promising"])
        parts = _policy_loss_parts(
            logits=outputs["action_logits"],
            q=q,
            prior=prior,
            actions=item["actions"],
            promising_logit=outputs["promising"],
            promising=promising,
            continuation_logit=outputs["continue_branch"],
            continue_branch=item["continue_branch"].to(device).view_as(outputs["continue_branch"]),
            action_continue_logits=outputs["action_continue"],
            action_continue_target=item["action_continue_target"].to(device).view_as(outputs["action_logits"]),
            action_continue_mask=item["action_continue_mask"].to(device).view_as(outputs["action_logits"]),
            action_uncertainty=item["action_uncertainty"].to(device).view_as(outputs["action_logits"]),
            config=config,
            F=F,
        )
        loss = loss + parts["total"]
    if task == "transition":
        prediction = _chosen_transition_prediction(outputs["transition"], item.get("chosen_action_index", -1))
        target = item["transition_target"].to(device).view_as(prediction)
        loss = loss + float(config.get("transition_loss_weight", 0.5) or 0.0) * F.mse_loss(prediction.sigmoid(), target.clamp(0.0, 1.0))
        uncertainty_prediction = _chosen_transition_prediction(outputs["uncertainty"], item.get("chosen_action_index", -1))
        uncertainty_target = item["uncertainty_target"].to(device).view_as(uncertainty_prediction)
        loss = loss + float(config.get("uncertainty_loss_weight", 0.20) or 0.0) * F.mse_loss(uncertainty_prediction.sigmoid(), uncertainty_target.clamp(0.0, 1.0))
    if task == "masked_graph":
        target = item["mask_target"].to(device).view_as(outputs["masked"])
        loss = loss + float(config.get("masked_graph_loss_weight", 0.25) or 0.0) * F.mse_loss(outputs["masked"].sigmoid(), target.clamp(0.0, 1.0))
    return loss


def _chosen_transition_prediction(prediction, chosen_index: int):
    if len(prediction.shape) == 1:
        return prediction
    index = int(chosen_index or 0)
    if index < 0 or index >= int(prediction.shape[0]):
        index = 0
    return prediction[index]


def _task_counts(samples) -> dict[str, int]:
    counts: dict[str, int] = {}
    for sample in samples:
        counts[sample.task] = counts.get(sample.task, 0) + 1
    return dict(sorted(counts.items()))


def _batches(items: list[Any], batch_size: int):
    size = max(1, int(batch_size or 1))
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _policy_loss_parts(*, logits, q, prior, actions: list[dict[str, Any]], promising_logit, promising, continuation_logit=None, continue_branch=None, action_continue_logits=None, action_continue_target=None, action_continue_mask=None, action_uncertainty=None, config: dict[str, Any], F) -> dict[str, Any]:
    q = q.clamp(0.0, 1.0)
    q_loss = F.mse_loss(logits.sigmoid(), q)
    softmax_loss = _softmax_teacher_loss(
        logits,
        q,
        temperature=float(config.get("q_temperature", 0.05) or 0.05),
        best_tie_margin=float(config.get("best_tie_margin", 0.02) or 0.02),
        F=F,
    )
    prior_loss = 0.25 * F.binary_cross_entropy_with_logits(logits, prior.clamp(0.0, 1.0))
    rank_loss = _pairwise_rank_loss(
        logits,
        q,
        gap_min=float(config.get("rank_q_gap_min", 0.04) or 0.04),
        F=F,
    )
    premature_stop_loss = _premature_stop_loss(
        logits,
        q,
        actions,
        promising=bool(float(promising.detach().cpu().item()) >= 0.5),
        stop_margin=float(config.get("stop_margin", 0.02) or 0.02),
        F=F,
    )
    undo_loss = _undo_path_loss(logits, q, actions, margin=float(config.get("undo_margin", config.get("q_margin", 0.04)) or 0.04), F=F)
    repeat_loss = _repeat_action_loss(
        logits,
        q,
        actions,
        margin=float(config.get("repeat_action_margin", 0.12) or 0.12),
        F=F,
    )
    uncertainty_tiebreak_loss = _uncertainty_tiebreak_loss(
        logits,
        q,
        action_uncertainty,
        tie_margin=float(config.get("best_tie_margin", 0.02) or 0.02),
        F=F,
    )
    promising_loss = F.binary_cross_entropy_with_logits(promising_logit, promising)
    continuation_loss = logits.sum() * 0.0
    if continuation_logit is not None and continue_branch is not None:
        continuation_loss = F.binary_cross_entropy_with_logits(continuation_logit, continue_branch)
    action_continuation_loss = logits.sum() * 0.0
    if action_continue_logits is None:
        action_continue_logits = logits
    if action_continue_target is not None and action_continue_mask is not None and float(action_continue_mask.detach().sum().cpu()) > 0.0:
        per_action = F.binary_cross_entropy_with_logits(action_continue_logits, action_continue_target.clamp(0.0, 1.0), reduction="none")
        action_continuation_loss = (per_action * action_continue_mask).sum() / action_continue_mask.sum().clamp_min(1.0)
    continuation_rank_loss = _continuation_rank_loss(
        logits,
        actions,
        continue_branch=continue_branch,
        margin=float(config.get("continuation_rank_margin", 0.08) or 0.08),
        F=F,
    )
    post_undo_switch_loss = _flagged_module_over_undo_loss(
        logits,
        actions,
        module_flag="post_undo_continue_module_bonus",
        undo_flag="post_undo_repeat_undo_penalty",
        margin=float(config.get("branch_context_margin", 0.12) or 0.12),
        F=F,
    )
    post_module_deepen_loss = _flagged_module_over_undo_loss(
        logits,
        actions,
        module_flag="post_module_deepen_bonus",
        undo_flag="post_module_immediate_undo_penalty",
        margin=float(config.get("branch_context_margin", 0.12) or 0.12),
        F=F,
    )
    total = (
        float(config.get("softmax_loss_weight", 1.0) or 0.0) * softmax_loss
        + float(config.get("q_regression_weight", 0.10) or 0.0) * q_loss
        + prior_loss
        + float(config.get("rank_loss_weight", 0.35) or 0.0) * rank_loss
        + float(config.get("premature_stop_loss_weight", 1.0) or 0.0) * premature_stop_loss
        + float(config.get("undo_loss_weight", 0.5) or 0.0) * undo_loss
        + float(config.get("repeat_action_loss_weight", 1.2) or 0.0) * repeat_loss
        + float(config.get("uncertainty_tiebreak_loss_weight", 0.15) or 0.0) * uncertainty_tiebreak_loss
        + float(config.get("promising_loss_weight", 0.35) or 0.0) * promising_loss
        + float(config.get("continuation_loss_weight", 0.8) or 0.0) * continuation_loss
        + float(config.get("action_continuation_loss_weight", 1.0) or 0.0) * action_continuation_loss
        + float(config.get("continuation_rank_loss_weight", 0.0) or 0.0) * continuation_rank_loss
        + float(config.get("post_undo_switch_loss_weight", 0.0) or 0.0) * post_undo_switch_loss
        + float(config.get("post_module_deepen_loss_weight", 0.0) or 0.0) * post_module_deepen_loss
    )
    return {
        "total": total,
        "softmax_loss": softmax_loss,
        "q_loss": q_loss,
        "rank_loss": rank_loss,
        "premature_stop_loss": premature_stop_loss,
        "undo_loss": undo_loss,
        "repeat_action_loss": repeat_loss,
        "uncertainty_tiebreak_loss": uncertainty_tiebreak_loss,
        "promising_loss": promising_loss,
        "continuation_loss": continuation_loss,
        "action_continuation_loss": action_continuation_loss,
        "continuation_rank_loss": continuation_rank_loss,
        "post_undo_switch_loss": post_undo_switch_loss,
        "post_module_deepen_loss": post_module_deepen_loss,
    }


def _softmax_teacher_loss(logits, q, *, temperature: float, best_tie_margin: float, F):
    import torch

    if int(q.numel()) < 2:
        return logits.sum() * 0.0
    max_q = q.max()
    teacher = torch.softmax(q / max(1e-4, float(temperature)), dim=0)
    best_mask = (max_q - q) <= max(0.0, float(best_tie_margin))
    if bool(best_mask.any()):
        teacher = torch.where(best_mask, torch.ones_like(teacher), teacher * 0.25)
        teacher = teacher / teacher.sum().clamp_min(1e-8)
    return F.kl_div(F.log_softmax(logits, dim=0), teacher.detach(), reduction="batchmean")


def _pairwise_rank_loss(logits, q, *, gap_min: float, F):
    losses = []
    for left in range(int(q.numel())):
        for right in range(int(q.numel())):
            q_gap = float(q[left].detach().cpu()) - float(q[right].detach().cpu())
            if q_gap < float(gap_min):
                continue
            margin = min(0.25, max(0.03, q_gap * 2.0))
            losses.append(F.relu((logits[right] - logits[left]) + margin))
    if not losses:
        return logits.sum() * 0.0
    return sum(losses) / len(losses)


def _premature_stop_loss(logits, q, actions: list[dict[str, Any]], *, promising: bool, stop_margin: float, F):
    if not promising:
        return logits.sum() * 0.0
    stop_indices = [index for index, action in enumerate(actions) if action.get("action_type") == "stop"]
    explore_indices = [index for index, action in enumerate(actions) if action.get("action_type") != "stop"]
    if not stop_indices or not explore_indices:
        return logits.sum() * 0.0
    stop_index = stop_indices[0]
    best_explore = max(explore_indices, key=lambda index: float(q[index].detach().cpu()))
    if float(q[best_explore].detach().cpu()) <= float(q[stop_index].detach().cpu()) + stop_margin:
        return logits.sum() * 0.0
    return F.relu((logits[stop_index] - logits[best_explore]) + stop_margin)


def _undo_path_loss(logits, q, actions: list[dict[str, Any]], *, margin: float, F):
    undo_indices = [index for index, action in enumerate(actions) if action.get("action_type") == "undo"]
    module_indices = [index for index, action in enumerate(actions) if action.get("action_type") == "module"]
    if not undo_indices or not module_indices:
        return logits.sum() * 0.0
    undo_index = undo_indices[0]
    best_module = max(module_indices, key=lambda index: float(q[index].detach().cpu()))
    if float(q[undo_index].detach().cpu()) <= float(q[best_module].detach().cpu()) + margin:
        return logits.sum() * 0.0
    return F.relu((logits[best_module] - logits[undo_index]) + margin)


def _repeat_action_loss(logits, q, actions: list[dict[str, Any]], *, margin: float, F):
    repeat_indices = []
    non_repeat_indices = []
    for index, action in enumerate(actions):
        if action.get("action_type") != "module":
            non_repeat_indices.append(index)
            continue
        features = action.get("features") if isinstance(action.get("features"), dict) else {}
        repeated = bool(features.get("same_as_parent_incoming_action") or features.get("same_family_as_parent_incoming_action"))
        if repeated:
            repeat_indices.append(index)
        else:
            non_repeat_indices.append(index)
    if not repeat_indices or not non_repeat_indices:
        return logits.sum() * 0.0
    losses = []
    for repeat_index in repeat_indices:
        best_other = max(non_repeat_indices, key=lambda index: float(q[index].detach().cpu()))
        repeat_q = float(q[repeat_index].detach().cpu())
        other_q = float(q[best_other].detach().cpu())
        if repeat_q > other_q + 0.05:
            continue
        losses.append(F.relu((logits[repeat_index] - logits[best_other]) + margin))
    if not losses:
        return logits.sum() * 0.0
    return sum(losses) / len(losses)


def _continuation_rank_loss(logits, actions: list[dict[str, Any]], *, continue_branch, margin: float, F):
    if continue_branch is None:
        return logits.sum() * 0.0
    try:
        should_continue = float(continue_branch.detach().cpu().view(-1)[0]) >= 0.5
    except Exception:
        should_continue = False
    if not should_continue:
        return logits.sum() * 0.0
    undo_indices = [index for index, action in enumerate(actions) if action.get("action_type") == "undo"]
    module_indices = [index for index, action in enumerate(actions) if action.get("action_type") == "module"]
    if not undo_indices or not module_indices:
        return logits.sum() * 0.0
    undo_index = undo_indices[0]
    best_module = max(module_indices, key=lambda index: float(logits[index].detach().cpu()))
    return F.relu((logits[undo_index] - logits[best_module]) + margin)


def _flagged_module_over_undo_loss(logits, actions: list[dict[str, Any]], *, module_flag: str, undo_flag: str, margin: float, F):
    module_indices = []
    undo_indices = []
    for index, action in enumerate(actions):
        features = action.get("features") if isinstance(action.get("features"), dict) else {}
        if action.get("action_type") == "module" and float(features.get(module_flag) or 0.0) > 0.0:
            module_indices.append(index)
        if action.get("action_type") == "undo" and float(features.get(undo_flag) or 0.0) > 0.0:
            undo_indices.append(index)
    if not module_indices or not undo_indices:
        return logits.sum() * 0.0
    best_module = max(module_indices, key=lambda index: float(logits[index].detach().cpu()))
    undo_index = undo_indices[0]
    return F.relu((logits[undo_index] - logits[best_module]) + margin)


def _uncertainty_tiebreak_loss(logits, q, action_uncertainty, *, tie_margin: float, F):
    if action_uncertainty is None or int(q.numel()) < 2:
        return logits.sum() * 0.0
    losses = []
    uncertainty_gap_min = 0.05
    for left in range(int(q.numel())):
        for right in range(int(q.numel())):
            q_gap = abs(float(q[left].detach().cpu()) - float(q[right].detach().cpu()))
            if q_gap > float(tie_margin):
                continue
            left_uncertainty = float(action_uncertainty[left].detach().cpu())
            right_uncertainty = float(action_uncertainty[right].detach().cpu())
            if left_uncertainty + uncertainty_gap_min >= right_uncertainty:
                continue
            margin = min(0.12, max(0.02, (right_uncertainty - left_uncertainty) * 0.5))
            losses.append(F.relu((logits[right] - logits[left]) + margin))
    if not losses:
        return logits.sum() * 0.0
    return sum(losses) / len(losses)


def _resolve_device(device: str, torch_module) -> str:
    requested = str(device or "auto").lower()
    if requested == "auto":
        return "cuda" if torch_module.cuda.is_available() else "cpu"
    if requested == "cuda" and not torch_module.cuda.is_available():
        raise SystemExit("RepairPolicyTransformer requested --device cuda but CUDA is not available")
    return requested
