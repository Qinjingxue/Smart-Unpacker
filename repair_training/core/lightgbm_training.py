from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from repair_training.core.model_artifacts import write_model_artifacts
from repair_training.core.plugin import TrainingFormatPlugin
from repair_training.core.thresholds import calibrate_binary_thresholds
from repair_training.core.features import normalize_model_type


def train_lightgbm_model(
    *,
    plugin: TrainingFormatPlugin,
    model_type: str,
    features_dir: str | Path,
    model_dir: str | Path,
    run_id: str = "",
) -> dict[str, Any]:
    model_type = normalize_model_type(model_type)
    try:
        import lightgbm as lgb
    except Exception as exc:  # pragma: no cover - depends on optional training environment
        raise SystemExit("LightGBM is required for training. Install repair_training/requirements-training.txt") from exc

    features_dir = Path(features_dir)
    model_dir = Path(model_dir)
    feature_schema = _read_json(features_dir / "feature_schema.json")
    label_schema = _read_json(features_dir / ("action_schema.json" if model_type == "repair_action" else "label_schema.json"))
    training_config = {
        "run_id": run_id,
        "format": plugin.format_name,
        "model_type": model_type,
        "lightgbm_params": _params(plugin, model_type),
        "taxonomy_version": 1,
    }
    if model_type == "damage_location":
        metrics = _train_damage_models(lgb, plugin, features_dir, model_dir, label_schema)
    elif model_type == "normal_structure":
        metrics = _train_normal_structure_model(lgb, plugin, features_dir, model_dir)
    elif model_type == "state_value":
        metrics = _train_state_value_model(lgb, plugin, features_dir, model_dir)
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
        extra=_model_card_extra(model_type),
    )
    return metrics


def _model_card_extra(model_type: str) -> dict[str, Any]:
    if model_type == "repair_action":
        return {
            "model_role": "action_prior",
            "does_not_use_state_value": True,
            "final_decision_by": "PolicyDecisionArbiter",
        }
    if model_type == "state_value":
        return {
            "model_role": "reachable_recovery_value",
            "final_decision_by": "PolicyDecisionArbiter",
        }
    return {}


def _train_damage_models(lgb, plugin: TrainingFormatPlugin, features_dir: Path, model_dir: Path, label_schema: dict[str, Any]) -> dict[str, Any]:
    train = _load_npz(features_dir / "train.npz")
    valid = _load_npz(features_dir / "valid.npz")
    test = _load_npz(features_dir / "test.npz")
    labels = list(label_schema.get("labels") or [])
    uncertain_labels = list(label_schema.get("uncertain_labels") or [])
    observed = _train_damage_head(
        lgb,
        plugin,
        train,
        valid,
        test,
        labels,
        model_dir=model_dir,
        models_subdir="models/observed",
        index_name="models_observed.json",
        thresholds_name="thresholds_observed.json",
        y_offset=0,
    )
    uncertain = _train_damage_head(
        lgb,
        plugin,
        train,
        valid,
        test,
        uncertain_labels,
        model_dir=model_dir,
        models_subdir="models/uncertain",
        index_name="models_uncertain.json",
        thresholds_name="thresholds_uncertain.json",
        y_offset=len(labels),
    )
    (model_dir / "models.json").write_text((model_dir / "models_observed.json").read_text(encoding="utf-8"), encoding="utf-8")
    (model_dir / "thresholds.json").write_text((model_dir / "thresholds_observed.json").read_text(encoding="utf-8"), encoding="utf-8")
    metrics = {
        "observed": observed["metrics"],
        "uncertain": uncertain["metrics"],
        "observed_macro_f1": observed["metrics"].get("macro_f1", 0.0),
        "observed_micro_f1": observed["metrics"].get("micro_f1", 0.0),
        "uncertain_macro_f1": uncertain["metrics"].get("macro_f1", 0.0),
        "uncertain_micro_f1": uncertain["metrics"].get("micro_f1", 0.0),
        "oracle_reconstructed_f1": _reconstructed_f1(
            observed["test_scores"],
            observed["test_y"],
            uncertain["test_scores"],
            uncertain["test_y"],
            observed["thresholds"],
            uncertain["thresholds"],
        ),
        "label_count": len(labels),
        "uncertain_label_count": len(uncertain_labels),
    }
    metrics["thresholds"] = {
        "default_threshold": observed["thresholds"].get("default_threshold", 0.5),
        "per_label_count": len(observed["thresholds"].get("thresholds") or {}),
        "selection_metric": observed["thresholds"].get("selection_metric"),
    }
    return metrics


def _train_damage_head(
    lgb,
    plugin: TrainingFormatPlugin,
    train: dict[str, Any],
    valid: dict[str, Any],
    test: dict[str, Any],
    labels: list[str],
    *,
    model_dir: Path,
    models_subdir: str,
    index_name: str,
    thresholds_name: str,
    y_offset: int,
) -> dict[str, Any]:
    models_dir = model_dir / models_subdir
    models_dir.mkdir(parents=True, exist_ok=True)
    model_index: dict[str, str] = {}
    per_label: dict[str, dict[str, float]] = {}
    valid_scores = np.zeros((len(valid["X"]), len(labels)), dtype=np.float32)
    test_scores = np.zeros((len(test["X"]), len(labels)), dtype=np.float32)
    params = _params(plugin, "damage_location")
    for index, label in enumerate(labels):
        col = y_offset + index
        y = _label_column(train["y"], col)
        if len(set(float(v) for v in y)) < 2:
            constant = float(y[0]) if len(y) else 0.0
            model_path = models_dir / f"{_safe_name(label)}.constant.json"
            model_path.write_text(json.dumps({"constant_probability": constant}, sort_keys=True), encoding="utf-8")
            model_index[label] = str(model_path.relative_to(model_dir))
            valid_scores[:, index] = constant
            test_scores[:, index] = constant
            per_label[label] = _binary_metrics(_label_column(test_scores, index), _label_column(test["y"], col))
            continue
        model = lgb.LGBMClassifier(**params)
        eval_set = [(valid["X"], _label_column(valid["y"], col))] if len(valid["X"]) else None
        fit_kwargs = {"eval_set": eval_set} if eval_set else {}
        model.fit(train["X"], y, **fit_kwargs)
        model_path = models_dir / f"{_safe_name(label)}.txt"
        model.booster_.save_model(str(model_path))
        model_index[label] = str(model_path.relative_to(model_dir))
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="X does not have valid feature names.*")
            if len(valid["X"]):
                valid_scores[:, index] = model.predict_proba(valid["X"])[:, 1]
            if len(test["X"]):
                test_scores[:, index] = model.predict_proba(test["X"])[:, 1]
        per_label[label] = _binary_metrics(_label_column(test_scores, index), _label_column(test["y"], col))
    (model_dir / index_name).write_text(json.dumps(model_index, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    calibration_score_parts = [item for item in (valid_scores, test_scores) if len(item)]
    calibration_y_parts = [_slice_y(item, y_offset, len(labels)) for item in (valid["y"], test["y"]) if len(item)]
    if calibration_score_parts and calibration_y_parts and labels:
        calibration_scores = np.vstack(calibration_score_parts)
        calibration_y = np.vstack(calibration_y_parts)
        thresholds = calibrate_binary_thresholds(calibration_scores, calibration_y, labels)
    else:
        thresholds = {"default_threshold": 0.5, "thresholds": {}, "selection_metric": "default_no_calibration_rows"}
    (model_dir / thresholds_name).write_text(json.dumps(thresholds, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    metrics = _damage_metrics(per_label)
    metrics["micro_f1"] = _micro_f1(test_scores, _slice_y(test["y"], y_offset, len(labels)))
    return {
        "metrics": metrics,
        "thresholds": thresholds,
        "test_scores": test_scores,
        "test_y": _slice_y(test["y"], y_offset, len(labels)),
    }


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


def _train_normal_structure_model(lgb, plugin: TrainingFormatPlugin, features_dir: Path, model_dir: Path) -> dict[str, Any]:
    model_dir.mkdir(parents=True, exist_ok=True)
    train = _load_npz(features_dir / "train.npz")
    valid = _load_npz(features_dir / "valid.npz")
    test = _load_npz(features_dir / "test.npz")
    params = _params(plugin, "normal_structure")
    y = train["y"]
    if y.ndim > 1:
        y = y[:, 0]
    if len(set(float(v) for v in y)) < 2:
        constant = float(y[0]) if len(y) else 0.0
        (model_dir / "model.constant.json").write_text(json.dumps({"constant_probability": constant}, sort_keys=True), encoding="utf-8")
        scores = np.full((len(test["X"]),), constant, dtype=np.float32)
        metrics = _normal_structure_metrics(scores, test["y"], meta=_read_jsonl(features_dir / "meta_test.jsonl"))
        metrics["constant_probability"] = constant
        return metrics
    model = lgb.LGBMClassifier(**params)
    fit_kwargs: dict[str, Any] = {}
    if len(valid["X"]):
        valid_y = valid["y"][:, 0] if valid["y"].ndim > 1 else valid["y"]
        fit_kwargs["eval_set"] = [(valid["X"], valid_y)]
    model.fit(train["X"], y, **fit_kwargs)
    model.booster_.save_model(str(model_dir / "model.txt"))
    joblib.dump(model, model_dir / "model.joblib")
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="X does not have valid feature names.*")
        scores = model.predict_proba(test["X"])[:, 1] if len(test["X"]) else np.array([], dtype=np.float32)
    return _normal_structure_metrics(scores, test["y"], meta=_read_jsonl(features_dir / "meta_test.jsonl"))


def _train_state_value_model(lgb, plugin: TrainingFormatPlugin, features_dir: Path, model_dir: Path) -> dict[str, Any]:
    model_dir.mkdir(parents=True, exist_ok=True)
    train = _load_npz(features_dir / "train.npz")
    valid = _load_npz(features_dir / "valid.npz")
    test = _load_npz(features_dir / "test.npz")
    params = _params(plugin, "state_value")
    model = lgb.LGBMRegressor(**params)
    fit_kwargs: dict[str, Any] = {}
    if len(valid["X"]):
        fit_kwargs["eval_set"] = [(valid["X"], valid["y"])]
    model.fit(train["X"], train["y"], **fit_kwargs)
    model.booster_.save_model(str(model_dir / "model.txt"))
    joblib.dump(model, model_dir / "model.joblib")
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="X does not have valid feature names.*")
        scores = model.predict(test["X"]) if len(test["X"]) else np.array([], dtype=np.float32)
    return _state_value_metrics(np.asarray(scores, dtype=np.float32), test["y"])


def _params(plugin: TrainingFormatPlugin, model_type: str) -> dict[str, Any]:
    model_type = normalize_model_type(model_type)
    if plugin.lightgbm_params is not None:
        params = dict(plugin.lightgbm_params(model_type) or {})
    else:
        params = {}
    if model_type == "damage_location":
        return {"n_estimators": 40, "learning_rate": 0.05, "num_leaves": 15, "random_state": 17, "verbosity": -1, **params}
    if model_type == "normal_structure":
        return {"objective": "binary", "n_estimators": 80, "learning_rate": 0.04, "num_leaves": 31, "random_state": 17, "verbosity": -1, **params}
    if model_type == "state_value":
        return {"objective": "regression", "n_estimators": 80, "learning_rate": 0.04, "num_leaves": 31, "random_state": 17, "verbosity": -1, **params}
    return {"objective": "lambdarank", "n_estimators": 40, "learning_rate": 0.05, "num_leaves": 15, "random_state": 17, "verbosity": -1, **params}


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


def _slice_y(y: np.ndarray, offset: int, width: int) -> np.ndarray:
    if width <= 0:
        return np.zeros((y.shape[0], 0), dtype=np.float32)
    if y.ndim == 1:
        return y.reshape(-1, 1) if offset == 0 and width == 1 else np.zeros((y.shape[0], width), dtype=np.float32)
    output = np.zeros((y.shape[0], width), dtype=np.float32)
    available = max(0, min(width, y.shape[1] - offset))
    if available:
        output[:, :available] = y[:, offset:offset + available]
    return output


def _reconstructed_f1(
    observed_scores: np.ndarray,
    observed_y: np.ndarray,
    uncertain_scores: np.ndarray,
    uncertain_y: np.ndarray,
    observed_thresholds: dict[str, Any],
    uncertain_thresholds: dict[str, Any],
) -> float:
    if len(observed_y) == 0 and len(uncertain_y) == 0:
        return 0.0
    observed_default = float(observed_thresholds.get("default_threshold", 0.5) or 0.5)
    uncertain_default = float(uncertain_thresholds.get("default_threshold", 0.5) or 0.5)
    observed_pred = observed_scores >= observed_default if observed_scores.size else np.zeros_like(observed_y, dtype=bool)
    uncertain_pred = uncertain_scores >= uncertain_default if uncertain_scores.size else np.zeros_like(uncertain_y, dtype=bool)
    observed_truth = observed_y >= 0.5
    uncertain_truth = uncertain_y >= 0.5
    tp = float(np.sum(observed_pred & observed_truth) + np.sum(uncertain_pred & uncertain_truth))
    fp = float(np.sum(observed_pred & ~observed_truth) + np.sum(uncertain_pred & ~uncertain_truth))
    fn = float(np.sum(~observed_pred & observed_truth) + np.sum(~uncertain_pred & uncertain_truth))
    return _prf(tp, fp, fn)["f1"]


def _micro_f1(scores: np.ndarray, y: np.ndarray) -> float:
    if scores.size == 0 or y.size == 0:
        return 0.0
    pred = scores >= 0.5
    truth = y >= 0.5
    tp = float(np.sum(pred & truth))
    fp = float(np.sum(pred & ~truth))
    fn = float(np.sum(~pred & truth))
    return _prf(tp, fp, fn)["f1"]


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


def _prf(tp: float, fp: float, fn: float) -> dict[str, float]:
    precision = tp / max(1.0, tp + fp)
    recall = tp / max(1.0, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return {"precision": precision, "recall": recall, "f1": f1}


def _damage_metrics(per_label: dict[str, dict[str, float]]) -> dict[str, Any]:
    if not per_label:
        return {"label_count": 0, "macro_f1": 0.0, "per_label": {}}
    macro = sum(item.get("f1", 0.0) for item in per_label.values()) / max(1, len(per_label))
    return {"label_count": len(per_label), "macro_f1": macro, "per_label": per_label}


def _normal_structure_metrics(scores: np.ndarray, y: np.ndarray, *, meta: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    y1 = y[:, 0] if getattr(y, "ndim", 1) > 1 else y
    binary = _binary_metrics(scores, y1)
    output: dict[str, Any] = {"rows": int(len(y1)), **binary}
    try:
        from sklearn.metrics import roc_auc_score  # type: ignore
        if len(set(float(v) for v in y1)) >= 2:
            output["auc"] = float(roc_auc_score(y1, scores))
    except Exception:
        output["auc"] = 0.0
    if len(y1):
        truth = y1 >= 0.5
        pred = scores >= 0.5
        clean = truth
        output["clean_false_positive_rate"] = float(np.sum((~pred) & clean) / max(1.0, np.sum(clean)))
        output["anomaly_recall"] = float(np.sum((~truth) & (~pred)) / max(1.0, np.sum(~truth)))
    meta = meta or []
    output["per_query_type"] = _normal_group_metrics(scores, y1, meta, "query_type")
    output["per_target_field"] = _normal_group_metrics(scores, y1, meta, "target_field")
    output["clean_observed_false_positive_rate"] = _clean_observed_false_positive_rate(scores, y1, meta)
    output["hard_negative_recall"] = _hard_negative_recall(scores, y1, meta)
    return output


def _state_value_metrics(scores: np.ndarray, y: np.ndarray) -> dict[str, Any]:
    y1 = y[:, 0] if getattr(y, "ndim", 1) > 1 else y
    if len(y1) == 0:
        return {"rows": 0, "mae": 0.0, "rmse": 0.0, "r2": 0.0, "bucket_accuracy": 0.0, "high_value_recall": 0.0, "bias": 0.0}
    clipped = np.clip(scores, 0.0, 1.0)
    err = clipped - y1
    mae = float(np.mean(np.abs(err)))
    rmse = float(np.sqrt(np.mean(err * err)))
    variance = float(np.sum((y1 - np.mean(y1)) ** 2))
    r2 = 1.0 - float(np.sum(err * err)) / variance if variance > 1e-9 else 0.0
    truth_bucket = np.floor(np.clip(y1, 0.0, 0.999999) * 5.0).astype(int)
    pred_bucket = np.floor(np.clip(clipped, 0.0, 0.999999) * 5.0).astype(int)
    high_truth = y1 >= 0.8
    high_pred = clipped >= 0.8
    return {
        "rows": int(len(y1)),
        "mae": mae,
        "rmse": rmse,
        "r2": float(r2),
        "bucket_accuracy": float(np.mean(truth_bucket == pred_bucket)),
        "high_value_recall": float(np.sum(high_truth & high_pred) / max(1.0, np.sum(high_truth))),
        "high_value_precision": float(np.sum(high_truth & high_pred) / max(1.0, np.sum(high_pred))),
        "bias": float(np.mean(err)),
        "overestimation_mean": float(np.mean(np.maximum(err, 0.0))),
        "underestimation_mean": float(np.mean(np.maximum(-err, 0.0))),
    }


def _normal_group_metrics(scores: np.ndarray, y: np.ndarray, meta: list[dict[str, Any]], key: str) -> dict[str, Any]:
    grouped: dict[str, dict[str, list[float]]] = {}
    for index, row in enumerate(meta[: len(y)]):
        group = str(row.get(key) or "")
        if not group:
            continue
        grouped.setdefault(group, {"scores": [], "labels": []})
        grouped[group]["scores"].append(float(scores[index]) if index < len(scores) else 1.0)
        grouped[group]["labels"].append(float(y[index]) if index < len(y) else 0.0)
    return {
        group: {
            **_binary_metrics(np.array(values["scores"], dtype=np.float32), np.array(values["labels"], dtype=np.float32)),
            "rows": len(values["labels"]),
        }
        for group, values in sorted(grouped.items())
    }


def _clean_observed_false_positive_rate(scores: np.ndarray, y: np.ndarray, meta: list[dict[str, Any]]) -> float:
    indexes = [
        index
        for index, row in enumerate(meta[: len(y)])
        if str(row.get("candidate_kind") or "") == "observed" and float(y[index]) >= 0.5
    ]
    if not indexes:
        return 0.0
    return float(sum(1 for index in indexes if float(scores[index]) < 0.5) / max(1, len(indexes)))


def _hard_negative_recall(scores: np.ndarray, y: np.ndarray, meta: list[dict[str, Any]]) -> float:
    indexes = [
        index
        for index, row in enumerate(meta[: len(y)])
        if str(row.get("candidate_kind") or "") == "counterfactual" and float(y[index]) < 0.5
    ]
    if not indexes:
        return 0.0
    return float(sum(1 for index in indexes if float(scores[index]) < 0.5) / max(1, len(indexes)))


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


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                rows.append(payload)
    return rows


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or ""))[:120] or "label"
