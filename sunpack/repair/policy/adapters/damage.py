from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from sunpack.repair.policy.types import DamageAnalysisRequest, DamageAnalysisResult
from sunpack.repair.policy.training_runtime import request_to_dict


DEFAULT_THRESHOLD = 0.5


class DamageAnalysisAdapter(Protocol):
    format: str

    def prepare_input(self, request: DamageAnalysisRequest) -> dict[str, Any]:
        ...

    def postprocess_scores(
        self,
        scores: dict[str, float],
        thresholds: dict[str, Any] | None = None,
        *,
        metadata: dict[str, Any] | None = None,
        threshold_override: float | None = None,
        uncertainty_scores: dict[str, float] | None = None,
        uncertainty_thresholds: dict[str, Any] | None = None,
    ) -> DamageAnalysisResult:
        ...


def get_damage_analysis_adapter(fmt: str) -> DamageAnalysisAdapter | None:
    normalized = _normalize_format(fmt)
    if normalized == "zip":
        return ZipDamageAnalysisAdapter()
    return None


def select_labels_with_thresholds(
    scores: dict[str, float],
    thresholds: dict[str, Any] | None = None,
    *,
    default_threshold: float = DEFAULT_THRESHOLD,
) -> list[str]:
    payload = thresholds if isinstance(thresholds, dict) else {}
    per_label = payload.get("thresholds") if isinstance(payload.get("thresholds"), dict) else {}
    default = float(payload.get("default_threshold", default_threshold) or default_threshold)
    selected: list[str] = []
    for label, score in scores.items():
        threshold = float(per_label.get(label, default) or default)
        if float(score or 0.0) >= threshold:
            selected.append(label)
    return apply_location_hierarchy(selected)


def apply_location_hierarchy(labels: list[str]) -> list[str]:
    output = {str(label) for label in labels if str(label)}
    for label in list(output):
        if not label.startswith("field:"):
            continue
        zone = zone_label_for_field(label.split(":", 1)[1])
        if zone:
            output.add(f"zone:{zone}")
    return sorted(output)


def zone_label_for_field(field: str) -> str:
    text = str(field or "")
    if "." not in text:
        return text
    head = text.split(".", 1)[0]
    if head in {"sfx_prefix", "split_volume", "zip64"}:
        return head
    return head


@dataclass(frozen=True)
class ZipDamageAnalysisAdapter:
    format: str = "zip"

    def prepare_input(self, request: DamageAnalysisRequest) -> dict[str, Any]:
        return request_to_dict(request)

    def postprocess_scores(
        self,
        scores: dict[str, float],
        thresholds: dict[str, Any] | None = None,
        *,
        metadata: dict[str, Any] | None = None,
        threshold_override: float | None = None,
        uncertainty_scores: dict[str, float] | None = None,
        uncertainty_thresholds: dict[str, Any] | None = None,
    ) -> DamageAnalysisResult:
        clean_scores = {str(label): _float(score) for label, score in scores.items() if str(label).startswith(("zone:", "field:"))}
        selected_scores = _selected_scores(clean_scores, thresholds, threshold_override=threshold_override)
        if not selected_scores and clean_scores:
            label, score = max(clean_scores.items(), key=lambda item: item[1])
            selected_scores[label] = score
        labels = apply_location_hierarchy(sorted(selected_scores))
        uncertain_clean_scores = {
            str(label): _float(score)
            for label, score in (uncertainty_scores or {}).items()
            if str(label).startswith(("zone:", "field:"))
        }
        uncertain_selected_scores = _selected_scores(
            uncertain_clean_scores,
            uncertainty_thresholds,
            threshold_override=threshold_override,
        )
        uncertain_labels = apply_location_hierarchy(sorted(uncertain_selected_scores))
        zone_labels = sorted({label.split(":", 1)[1] for label in labels if label.startswith("zone:")})
        meta = dict(metadata or {})
        meta.update({
            "threshold_mode": "override" if threshold_override is not None else "model",
            "taxonomy": "zip",
            "analysis_target": "observed_location_with_uncertainty",
            "selected_scores": selected_scores,
            "uncertain_labels": uncertain_labels,
            "uncertain_scores": uncertain_selected_scores,
            "observability_summary": _observability_summary(uncertain_labels),
        })
        return DamageAnalysisResult(
            format="zip",
            damage_labels=labels,
            damage_zones=[{"kind": zone, "path": zone} for zone in zone_labels],
            confidence=max(selected_scores.values(), default=0.0),
            route_hints=[],
            blocking_reasons=[],
            metadata=meta,
        )


def _selected_scores(
    scores: dict[str, float],
    thresholds: dict[str, Any] | None,
    *,
    threshold_override: float | None,
) -> dict[str, float]:
    if threshold_override is not None:
        threshold = float(threshold_override)
        return {label: score for label, score in scores.items() if score >= threshold}
    payload = thresholds if isinstance(thresholds, dict) else {}
    per_label = payload.get("thresholds") if isinstance(payload.get("thresholds"), dict) else {}
    default = float(payload.get("default_threshold", DEFAULT_THRESHOLD) or DEFAULT_THRESHOLD)
    return {
        label: score
        for label, score in scores.items()
        if score >= float(per_label.get(label, default) or default)
    }


def _observability_summary(labels: list[str]) -> dict[str, Any]:
    zones = sorted({zone_label_for_field(label.split(":", 1)[1]) for label in labels if label.startswith("field:")})
    zones.extend(label.split(":", 1)[1] for label in labels if label.startswith("zone:"))
    return {
        "uncertain_label_count": len(labels),
        "uncertain_zones": sorted({zone for zone in zones if zone}),
    }


def _normalize_format(fmt: str) -> str:
    value = str(fmt or "").lower().strip().replace("-", "_")
    return "zip" if value in {"zip", ".zip"} else value


def _float(value: Any, *, default: float = 0.0) -> float:
    try:
        return float(value if value is not None else default)
    except (TypeError, ValueError):
        return float(default)
