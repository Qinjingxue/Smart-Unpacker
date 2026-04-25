import os
from typing import Any


def context_from_marker_candidates(candidates: list[dict[str, Any]], rules: list[dict[str, Any]]) -> dict[str, Any]:
    fallback = candidates[0] if candidates else {"target_dir": "", "markers": []}
    fallback_ctx = context_from_markers(str(fallback.get("target_dir") or ""), set(fallback.get("markers") or []), rules)
    for candidate in candidates:
        ctx = context_from_markers(
            str(candidate.get("target_dir") or ""),
            set(candidate.get("markers") or []),
            rules,
        )
        if ctx["scene_type"] != "generic":
            return ctx
    return fallback_ctx


def context_from_markers(target_dir: str, markers: set[str], rules: list[dict[str, Any]]) -> dict[str, Any]:
    matched_rule = None
    match_strength = "none"

    for rule in rules:
        for variant in rule.get("match_variants", ()):
            if _variant_matches(markers, variant):
                matched_rule = rule
                match_strength = "strong"
                break
        if matched_rule:
            break

    if not matched_rule:
        for rule in rules:
            for variant in rule.get("weak_match_variants", ()):
                if _variant_matches(markers, variant):
                    matched_rule = rule
                    match_strength = "weak"
                    break
            if matched_rule:
                break

    return {
        "target_dir": os.path.normpath(target_dir),
        "scene_type": matched_rule["scene_type"] if matched_rule else "generic",
        "match_strength": match_strength,
        "markers": sorted(markers),
    }


def _variant_matches(markers: set[str], variant: dict) -> bool:
    all_of = set(variant.get("all_of", set()))
    any_of = set(variant.get("any_of", set()))
    if all_of and not all_of.issubset(markers):
        return False
    if any_of and not (markers & any_of):
        return False
    return True
