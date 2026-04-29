from __future__ import annotations

from packrelic.analysis.fuzzy_pipeline.module import FuzzyAnalysisModuleSpec
from packrelic.analysis.fuzzy_pipeline.registry import register_fuzzy_analysis_module


class BinaryProfileFuzzyModule:
    spec = FuzzyAnalysisModuleSpec(
        name="binary_profile",
        provides=(
            "entropy_profile",
            "byte_class_profile",
            "window_anomalies",
            "ngram_sketch",
            "run_profile",
            "offset_hints",
        ),
        io_profile="sampled_native",
    )

    def analyze(self, view, prepass: dict, config: dict) -> dict:
        native_profile = getattr(view, "fuzzy_binary_profile", None)
        if not callable(native_profile):
            raise RuntimeError("native fuzzy binary profile is required")
        profile = native_profile(
            window_bytes=max(1024, int(config.get("window_bytes", 64 * 1024) or 64 * 1024)),
            max_windows=max(1, int(config.get("max_windows", 8) or 8)),
            max_sample_bytes=max(1024, int(config.get("max_sample_bytes", 1024 * 1024) or 1024 * 1024)),
            entropy_high_threshold=float(config.get("entropy_high_threshold", 6.8) or 6.8),
            entropy_low_threshold=float(config.get("entropy_low_threshold", 3.5) or 3.5),
            entropy_jump_threshold=float(config.get("entropy_jump_threshold", 1.25) or 1.25),
            ngram_top_k=max(1, int(config.get("ngram_top_k", 8) or 8)),
            max_ngram_sample_bytes=max(0, int(config.get("max_ngram_sample_bytes", 256 * 1024) or 256 * 1024)),
        )
        return _complete_profile(dict(profile), prepass)


def _complete_profile(profile: dict, prepass: dict) -> dict:
    entropy_profile = dict(profile.get("entropy_profile") or {})
    byte_class_profile = dict(profile.get("byte_class_profile") or {})
    window_anomalies = list(profile.get("window_anomalies") or [])
    run_profile = dict(profile.get("run_profile") or {})
    ngram_sketch = dict(profile.get("ngram_sketch") or {})
    offset_hints = _offset_hints(prepass, entropy_profile, byte_class_profile, window_anomalies, run_profile)
    profile["offset_hints"] = offset_hints
    profile["hints"] = _hints(
        list(profile.get("hints") or []),
        entropy_profile,
        byte_class_profile,
        window_anomalies,
        offset_hints,
        run_profile,
        ngram_sketch,
    )
    return profile


def _offset_hints(
    prepass: dict,
    entropy_profile: dict,
    byte_class_profile: dict,
    window_anomalies: list[dict],
    run_profile: dict,
) -> list[dict]:
    hints = []
    head = byte_class_profile.get("head", {})
    for hit in prepass.get("hits", []) or []:
        name = str(hit.get("name") or "")
        offset = int(hit.get("offset") or 0)
        if offset <= 0 or name not in _ARCHIVE_SIGNATURE_HIT_NAMES:
            continue
        archive_start = max(0, offset - 257) if name == "tar_ustar" else offset
        confidence = 0.78
        reason = "archive_signature_after_prefix"
        if float(head.get("printable_ratio") or 0.0) >= 0.45 or entropy_profile.get("head_low_entropy"):
            confidence = 0.88
            reason = "archive_signature_after_low_entropy_prefix"
        hints.append({
            "kind": "carrier_prefix_end",
            "offset": archive_start,
            "format_hint": _format_from_signature_name(name),
            "signature": name,
            "signature_offset": offset,
            "confidence": confidence,
            "reason": reason,
        })

    for anomaly in window_anomalies:
        anomaly_type = str(anomaly.get("type") or "")
        offset = int(anomaly.get("offset") or 0)
        if anomaly_type in {"entropy_jump", "printable_to_high_entropy"}:
            hints.append({
                "kind": "entropy_boundary",
                "offset": offset,
                "confidence": float(anomaly.get("confidence") or 0.0),
                "reason": anomaly_type,
                "approximate": True,
            })
        elif anomaly_type in {"high_entropy_to_printable", "high_entropy_to_padding", "tail_printable_region"}:
            hints.append({
                "kind": "trailing_junk_start",
                "offset": offset,
                "confidence": float(anomaly.get("confidence") or 0.0),
                "reason": anomaly_type,
                "approximate": True,
            })
        elif anomaly_type == "tail_padding":
            hints.append({
                "kind": "tail_padding_start",
                "offset": _tail_padding_offset(run_profile, anomaly, offset),
                "confidence": float(anomaly.get("confidence") or 0.0),
                "reason": "tail_padding",
                "approximate": True,
            })
    return _dedupe_hints(hints)


def _hints(
    base_hints: list[str],
    entropy_profile: dict,
    byte_class_profile: dict,
    window_anomalies: list[dict],
    offset_hints: list[dict],
    run_profile: dict,
    ngram_sketch: dict,
) -> list[str]:
    hints = {str(item) for item in base_hints}
    if any(hint.get("kind") == "carrier_prefix_end" for hint in offset_hints):
        hints.add("carrier_prefix_likely")
    if any(hint.get("kind") == "trailing_junk_start" for hint in offset_hints):
        hints.add("trailing_text_junk_likely")
    if any(hint.get("kind") == "tail_padding_start" for hint in offset_hints) or run_profile.get("tail_padding_likely"):
        hints.add("trailing_padding_likely")
    if entropy_profile.get("overall_high_entropy"):
        hints.add("high_entropy_body")
    if entropy_profile.get("entropy_range", 0.0) >= 1.5 or any(item.get("type") == "entropy_jump" for item in window_anomalies):
        hints.add("entropy_boundary_shift")
    if entropy_profile.get("head_low_entropy"):
        hints.add("head_low_entropy")
    if entropy_profile.get("tail_low_entropy"):
        hints.add("tail_low_entropy")
    if float(byte_class_profile.get("tail", {}).get("printable_ratio") or 0.0) >= 0.55:
        hints.add("tail_printable_region")
    if ngram_sketch.get("magic_like_hits"):
        hints.add("magic_like_signature_sampled")
    return sorted(hints)


def _tail_padding_offset(run_profile: dict, anomaly: dict, default_offset: int) -> int:
    key = "longest_ff_run" if anomaly.get("dominant_byte") == "ff" else "longest_zero_run"
    run = run_profile.get(key) or {}
    offset = run.get("offset")
    return int(offset) if offset is not None else default_offset


def _dedupe_hints(hints: list[dict]) -> list[dict]:
    result = []
    seen = set()
    for hint in hints:
        key = (hint.get("kind"), hint.get("offset"), hint.get("format_hint"), hint.get("reason"))
        if key in seen:
            continue
        seen.add(key)
        result.append(hint)
    return sorted(result, key=lambda item: (int(item.get("offset") or 0), str(item.get("kind") or "")))


def _format_from_signature_name(name: str) -> str:
    if name.startswith("zip_"):
        return "zip"
    if name.startswith("rar"):
        return "rar"
    if name == "tar_ustar":
        return "tar"
    return name


_ARCHIVE_SIGNATURE_HIT_NAMES = {
    "zip_local",
    "rar4",
    "rar5",
    "7z",
    "gzip",
    "bzip2",
    "xz",
    "zstd",
    "tar_ustar",
}


register_fuzzy_analysis_module(BinaryProfileFuzzyModule())
