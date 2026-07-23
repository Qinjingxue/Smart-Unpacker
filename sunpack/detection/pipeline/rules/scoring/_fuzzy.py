from __future__ import annotations

from pathlib import PurePath
from typing import Iterable

from sunpack.contracts.detection import FactBag


def naming_prior(
    facts: FactBag,
    *,
    formats: Iterable[str],
    extensions: Iterable[str],
) -> tuple[int, str]:
    """Return a bounded naming prior derived from the logical archive identity.

    Split-volume format hints are produced by the relationship layer and take
    precedence over physical suffixes.  Naming is intentionally capped at two
    points, so a filename can route and reinforce binary evidence but can never
    identify an archive by itself.
    """

    wanted_formats = {_normalize_format(value) for value in formats if value}
    wanted_extensions = {_normalize_extension(value) for value in extensions if value}
    hinted = {
        _normalize_format(value)
        for value in (
            _archive_input_format(facts),
            facts.get("relation.format_hint"),
        )
        if value
    }
    if wanted_formats & hinted:
        confidence = str(facts.get("relation.format_hint_confidence") or "none").lower()
        return (2 if confidence == "strong" else 1), f"logical format hint ({confidence})"

    for value in (
        facts.get("candidate.logical_name"),
        facts.get("file.logical_name"),
        facts.get("candidate.entry_path"),
        facts.get("file.path"),
    ):
        suffixes = _suffixes(str(value or ""))
        if wanted_extensions & suffixes:
            return 2, "matching logical filename"
    return 0, ""


def add_component(
    components: list[str],
    label: str,
    points: int,
    condition: bool,
) -> int:
    if not condition or not points:
        return 0
    components.append(f"{label}:{points:+d}")
    return points


def split_layout_prior(facts: FactBag, *, formats: Iterable[str]) -> tuple[int, str]:
    """Score a relationship-layer split layout independently of its suffix hint."""
    if not bool(facts.get("relation.is_split_related") or facts.get("file.is_split_candidate")):
        return 0, ""
    wanted = {_normalize_format(value) for value in formats if value}
    observed = {
        _normalize_format(value)
        for value in (
            _archive_input_format(facts),
            facts.get("relation.format_hint"),
            facts.get("relation.split_family"),
        )
        if value
    }
    if wanted & observed or any(
        any(fmt in value for fmt in wanted)
        for value in observed
    ):
        return 2, "logical split-volume layout"
    return 0, ""


def fuzzy_effect_reason(format_name: str, components: list[str]) -> str:
    return f"Fuzzy {format_name} evidence ({', '.join(components)})"


def available(value) -> bool:
    return value not in (None, "", "unavailable")


def text_contains(value, fragment: str) -> bool:
    return fragment in str(value or "").lower()


def _archive_input_format(facts: FactBag) -> str:
    archive_input = facts.get("archive.input") or {}
    return str(archive_input.get("format_hint") or "") if isinstance(archive_input, dict) else ""


def _normalize_format(value: str) -> str:
    return str(value).strip().lower().lstrip(".")


def _normalize_extension(value: str) -> str:
    normalized = str(value).strip().lower()
    return normalized if normalized.startswith(".") else f".{normalized}"


def _suffixes(value: str) -> set[str]:
    name = PurePath(value.replace("\\", "/")).name.lower()
    parts = name.split(".")
    return {
        "." + ".".join(parts[-count:])
        for count in (1, 2)
        if len(parts) > count
    }
