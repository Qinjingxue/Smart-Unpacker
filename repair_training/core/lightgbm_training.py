from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from repair_training.core.model_artifacts import write_model_artifacts
from repair_training.core.plugin import TrainingFormatPlugin


def train_lightgbm_model(
    *,
    plugin: TrainingFormatPlugin,
    model_type: str,
    features_dir: str | Path,
    model_dir: str | Path,
    run_id: str = "",
) -> dict[str, Any]:
    try:
        import lightgbm as lgb
    except Exception as exc:  # pragma: no cover - depends on optional training environment
        raise SystemExit("LightGBM is required for training. Install repair_training/requirements-training.txt") from exc

    features_dir = Path(features_dir)
    model_dir = Path(model_dir)
    feature_schema = _read_json(features_dir / "feature_schema.json")
    label_schema = _read_json(features_dir / ("label_schema.json" if model_type == "damage_analysis" else "action_schema.json"))
    training_config = {
        "run_id": run_id,
        "format": plugin.format_name,
        "model_type": model_type,
        "lightgbm_params": _params(plugin, model_type),
        "taxonomy_version": 1,
    }
    if model_type == "damage_analysis":
        metrics = _train_damage_models(lgb, plugin, features_dir, model_dir, label_schema)
    elif model_type == "repair_action":
        metrics = _train_action_ranker(lgb, plugin, features_dir, model_dir)
    else:
        raise SystemExit(f"unsupported model type: {model_type}")
    write_model_artifacts(
        model_dir,
        format_name=plugin.format_name,
        model_type=model_type,
        training_config=training_config,
        metrics=metrics,
        feature_schema=feature_schema,
        label_schema=label_schema,
        input_files={
            "train": features_dir / "train.npz",
            "valid": features_dir / "valid.npz",
            "test": features_dir / "test.npz",
        },
    )
    return metrics


def _train_damage_models(lgb, plugin: TrainingFormatPlugin, features_dir: Path, model_dir: Path, label_schema: dict[str, Any]) -> dict[str, Any]:
    train = _load_npz(features_dir / "train.npz")
    valid = _load_npz(features_dir / "valid.npz")
    test = _load_npz(features_dir / "test.npz")
    labels = list(label_schema.get("labels") or [])
    models_dir = model_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    model_index: dict[str, str] = {}
    per_label: dict[str, dict[str, float]] = {}
    params = _params(plugin, "damage_analysis")
    for index, label in enumerate(labels):
        y = train["y"][:, index] if train["y"].ndim > 1 else train["y"]
        if len(set(float(v) for v in y)) < 2:
            constant = float(y[0]) if len(y) else 0.0
            model_path = models_dir / f"{_safe_name(label)}.constant.json"
            model_path.write_text(json.dumps({"constant_probability": constant}, sort_keys=True), encoding="utf-8")
            model_index[label] = str(model_path.relative_to(model_dir))
            per_label[label] = _binary_metrics(np.full_like(_label_column(test["y"], index), constant), _label_column(test["y"], index))
            continue
        model = lgb.LGBMClassifier(**params)
        eval_set = [(valid["X"], _label_column(valid["y"], index))] if len(valid["X"]) else None
        fit_kwargs = {"eval_set": eval_set} if eval_set else {}
        model.fit(train["X"], y, **fit_kwargs)
        model_path = models_dir / f"{_safe_name(label)}.txt"
        model.booster_.save_model(str(model_path))
        model_index[label] = str(model_path.relative_to(model_dir))
        predicted = model.predict_proba(test["X"])[:, 1] if len(test["X"]) else np.array([], dtype=np.float32)
        per_label[label] = _binary_metrics(predicted, _label_column(test["y"], index))
    (model_dir / "models.json").write_text(json.dumps(model_index, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return _damage_metrics(per_label)


def _train_action_ranker(lgb, plugin: TrainingFormatPlugin, features_dir: Path, model_dir: Path) -> dict[str, Any]:
    model_dir.mkdir(parents=True, exist_ok=True)
    train = _load_npz(features_dir / "train.npz")
    valid = _load_npz(features_dir / "valid.npz")
    test = _load_npz(features_dir / "test.npz")
    train_group = _read_group(features_dir / "group_train.txt")
    valid_group = _read_group(features_dir / "group_valid.txt")
    params = _params(plugin, "repair_action")
    model = lgb.LGBMRanker(**params)
    fit_kwargs: dict[str, Any] = {"group": train_group}
    if len(valid["X"]) and valid_group:
        fit_kwargs["eval_set"] = [(valid["X"], valid["y"])]
        fit_kwargs["eval_group"] = [valid_group]
    model.fit(train["X"], train["y"], **fit_kwargs)
    model.booster_.save_model(str(model_dir / "model.txt"))
    joblib.dump(model, model_dir / "model.joblib")
    scores = model.predict(test["X"]) if len(test["X"]) else np.array([], dtype=np.float32)
    return _rank_metrics(scores, test["y"], _read_group(features_dir / "group_test.txt"))


def _params(plugin: TrainingFormatPlugin, model_type: str) -> dict[str, Any]:
    if plugin.lightgbm_params is not None:
        params = dict(plugin.lightgbm_params(model_type) or {})
    else:
        params = {}
    if model_type == "damage_analysis":
        return {"n_estimators": 40, "learning_rate": 0.05, "num_leaves": 15, "random_state": 17, **params}
    return {"objective": "lambdarank", "n_estimators": 40, "learning_rate": 0.05, "num_leaves": 15, "random_state": 17, **params}


def _load_npz(path: Path) -> dict[str, np.ndarray]:
    if not path.is_file():
        return {"X": np.zeros((0, 0), dtype=np.float32), "y": np.zeros((0,), dtype=np.float32)}
    loaded = np.load(path)
    return {"X": loaded["X"], "y": loaded["y"]}


def _label_column(y: np.ndarray, index: int) -> np.ndarray:
    if y.ndim == 1:
        return y
    if y.shape[1] <= index:
        return np.zeros((y.shape[0],), dtype=np.float32)
    return y[:, index]


def _binary_metrics(scores: np.ndarray, y: np.ndarray) -> dict[str, float]:
    if len(y) == 0:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    pred = scores >= 0.5
    truth = y >= 0.5
    tp = float(np.sum(pred & truth))
    fp = float(np.sum(pred & ~truth))
    fn = float(np.sum(~pred & truth))
    precision = tp / max(1.0, tp + fp)
    recall = tp / max(1.0, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def _damage_metrics(per_label: dict[str, dict[str, float]]) -> dict[str, Any]:
    if not per_label:
        return {"label_count": 0, "macro_f1": 0.0, "per_label": {}}
    macro = sum(item.get("f1", 0.0) for item in per_label.values()) / max(1, len(per_label))
    return {"label_count": len(per_label), "macro_f1": macro, "per_label": per_label}


def _rank_metrics(scores: np.ndarray, labels: np.ndarray, groups: list[int]) -> dict[str, Any]:
    if len(scores) == 0:
        return {"groups": 0, "best_action_accuracy": 0.0, "ndcg_at_1": 0.0, "mean_regret": 0.0}
    offset = 0
    correct = 0
    regrets = []
    for size in groups or [len(scores)]:
        end = offset + size
        group_scores = scores[offset:end]
        group_labels = labels[offset:end]
        if len(group_scores):
            selected = int(np.argmax(group_scores))
            best = int(np.argmax(group_labels))
            correct += 1 if selected == best else 0
            regrets.append(float(group_labels[best] - group_labels[selected]))
        offset = end
    count = max(1, len(groups) or 1)
    return {"groups": len(groups) or 1, "best_action_accuracy": correct / count, "ndcg_at_1": correct / count, "mean_regret": float(np.mean(regrets)) if regrets else 0.0}


def _read_group(path: Path) -> list[int]:
    if not path.is_file():
        return []
    return [int(line.strip()) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or ""))[:120] or "label"
