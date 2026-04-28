FUZZY_ARCHIVE_SIGNATURES = {"zip_local", "rar4", "rar5", "7z", "gzip", "bzip2", "xz", "zstd", "tar_ustar"}


def apply_fuzzy_routes(
    details: dict,
    evidence: list[str],
    damage_flags: list[str],
    prepass: dict,
    *,
    start_offset: int,
    end_offset: int | None,
    file_size: int,
    format_hint: str,
) -> dict:
    route = fuzzy_structure_route(
        prepass,
        start_offset=start_offset,
        end_offset=end_offset,
        file_size=file_size,
        format_hint=format_hint,
    )
    if not route:
        return {}
    details["fuzzy"] = route
    if route.get("carrier_prefix_likely"):
        _append_unique(evidence, "fuzzy:carrier_prefix")
        _append_unique(damage_flags, "carrier_prefix")
        details["prefix_context"] = "carrier"
    if route.get("trailing_junk_likely"):
        _append_unique(evidence, "fuzzy:trailing_junk")
        _append_unique(damage_flags, "trailing_junk")
        details["post_archive_context"] = "junk_or_padding_candidate"
    elif route.get("tail_padding_likely"):
        _append_unique(evidence, "fuzzy:tail_padding")
        _append_unique(damage_flags, "trailing_padding")
        details["post_archive_context"] = "padding_candidate"
    if route.get("entropy_boundary_near_start"):
        _append_unique(evidence, "fuzzy:entropy_boundary")
    return route


def fuzzy_structure_route(
    prepass: dict,
    *,
    start_offset: int,
    end_offset: int | None,
    file_size: int,
    format_hint: str,
) -> dict:
    profile = binary_profile(prepass)
    if not profile:
        return {}

    window_bytes = int(profile.get("window_bytes") or 0)
    tolerance = max(1024, window_bytes)
    hints = [str(item) for item in profile.get("hints") or []]
    offset_hints = [hint for hint in profile.get("offset_hints") or [] if isinstance(hint, dict)]
    relevant_offset_hints = _relevant_offset_hints(
        offset_hints,
        start_offset=start_offset,
        end_offset=end_offset,
        file_size=file_size,
        format_hint=format_hint,
        tolerance=tolerance,
    )
    route_names = []
    carrier_prefix = _carrier_prefix_likely(hints, relevant_offset_hints, start_offset=start_offset, format_hint=format_hint)
    entropy_boundary = any(
        hint.get("kind") == "entropy_boundary" and _near(int(hint.get("offset") or 0), start_offset, tolerance)
        for hint in relevant_offset_hints
    )
    trailing_junk = _trailing_junk_likely(
        prepass,
        hints,
        relevant_offset_hints,
        start_offset=start_offset,
        end_offset=end_offset,
        file_size=file_size,
    )
    tail_padding = _tail_padding_likely(hints, relevant_offset_hints, end_offset=end_offset, file_size=file_size)
    if carrier_prefix:
        route_names.append("carrier_prefixed_archive")
    if entropy_boundary:
        route_names.append("entropy_boundary_aligned")
    if trailing_junk:
        route_names.append("post_archive_junk_candidate")
    elif tail_padding:
        route_names.append("post_archive_padding_candidate")
    if "high_entropy_body" in hints:
        route_names.append("high_entropy_body")

    compact = _compact_profile(profile)
    return {
        "routes": route_names,
        "hints": hints,
        "carrier_prefix_likely": carrier_prefix,
        "entropy_boundary_near_start": entropy_boundary,
        "trailing_junk_likely": trailing_junk,
        "tail_padding_likely": tail_padding,
        "relevant_offset_hints": relevant_offset_hints[:8],
        "profile": compact,
    }


def binary_profile(prepass: dict) -> dict:
    fuzzy = prepass.get("fuzzy") if isinstance(prepass.get("fuzzy"), dict) else {}
    profile = fuzzy.get("binary_profile") if isinstance(fuzzy.get("binary_profile"), dict) else {}
    return profile


def _carrier_prefix_likely(hints: list[str], offset_hints: list[dict], *, start_offset: int, format_hint: str) -> bool:
    if start_offset <= 0:
        return False
    if "carrier_prefix_likely" in hints:
        return True
    for hint in offset_hints:
        if hint.get("kind") != "carrier_prefix_end":
            continue
        if hint.get("format_hint") not in {None, "", format_hint}:
            continue
        if int(hint.get("offset") or 0) == int(start_offset):
            return True
    return False


def _trailing_junk_likely(
    prepass: dict,
    hints: list[str],
    offset_hints: list[dict],
    *,
    start_offset: int,
    end_offset: int | None,
    file_size: int,
) -> bool:
    if end_offset is None or end_offset >= file_size:
        return False
    next_archive = _next_archive_offset(prepass, start_offset)
    if next_archive is not None and next_archive < file_size:
        return False
    if any(hint.get("kind") == "trailing_junk_start" and int(hint.get("offset") or 0) >= end_offset for hint in offset_hints):
        return True
    return "trailing_text_junk_likely" in hints or "tail_printable_region" in hints


def _tail_padding_likely(hints: list[str], offset_hints: list[dict], *, end_offset: int | None, file_size: int) -> bool:
    if end_offset is None or end_offset >= file_size:
        return False
    if any(hint.get("kind") == "tail_padding_start" and int(hint.get("offset") or 0) >= end_offset for hint in offset_hints):
        return True
    return "trailing_padding_likely" in hints


def _relevant_offset_hints(
    offset_hints: list[dict],
    *,
    start_offset: int,
    end_offset: int | None,
    file_size: int,
    format_hint: str,
    tolerance: int,
) -> list[dict]:
    relevant = []
    for hint in offset_hints:
        offset = int(hint.get("offset") or 0)
        kind = str(hint.get("kind") or "")
        if kind == "carrier_prefix_end":
            if hint.get("format_hint") not in {None, "", format_hint}:
                continue
            if offset == start_offset or _near(offset, start_offset, tolerance):
                relevant.append(dict(hint))
        elif kind == "entropy_boundary" and _near(offset, start_offset, tolerance):
            relevant.append(dict(hint))
        elif kind in {"trailing_junk_start", "tail_padding_start"}:
            if end_offset is not None and offset >= end_offset:
                relevant.append(dict(hint))
            elif offset >= max(0, file_size - tolerance):
                relevant.append(dict(hint))
    return relevant


def _compact_profile(profile: dict) -> dict:
    entropy = profile.get("entropy_profile") if isinstance(profile.get("entropy_profile"), dict) else {}
    byte_class = profile.get("byte_class_profile") if isinstance(profile.get("byte_class_profile"), dict) else {}
    ngram = profile.get("ngram_sketch") if isinstance(profile.get("ngram_sketch"), dict) else {}
    run_profile = profile.get("run_profile") if isinstance(profile.get("run_profile"), dict) else {}
    return {
        "entropy": {
            key: entropy.get(key)
            for key in (
                "head_entropy",
                "middle_entropy",
                "tail_entropy",
                "avg_entropy",
                "overall_class",
                "head_low_entropy",
                "tail_low_entropy",
                "local_high_entropy",
            )
            if key in entropy
        },
        "byte_class": {
            "head": byte_class.get("head", {}),
            "tail": byte_class.get("tail", {}),
            "average": byte_class.get("average", {}),
        },
        "run": {
            "longest_zero_run": run_profile.get("longest_zero_run", {}),
            "longest_ff_run": run_profile.get("longest_ff_run", {}),
            "tail_run": run_profile.get("tail_run", {}),
            "tail_padding_likely": run_profile.get("tail_padding_likely", False),
        },
        "ngram": {
            "byte_histogram_top": (ngram.get("byte_histogram_top") or [])[:4],
            "bigram_top": (ngram.get("bigram_top") or [])[:4],
            "magic_like_hits": (ngram.get("magic_like_hits") or [])[:4],
            "magic_like_density_per_mb": ngram.get("magic_like_density_per_mb", 0.0),
        },
    }


def _next_archive_offset(prepass: dict, start_offset: int) -> int | None:
    offsets = []
    for hit in prepass.get("hits", []) or []:
        if hit.get("name") not in FUZZY_ARCHIVE_SIGNATURES:
            continue
        offset = int(hit.get("offset") or 0)
        if offset > start_offset:
            offsets.append(offset)
    return min(offsets) if offsets else None


def _near(left: int, right: int, tolerance: int) -> bool:
    return abs(int(left) - int(right)) <= max(1, int(tolerance))


def _append_unique(target: list[str], value: str) -> None:
    if value not in target:
        target.append(value)
