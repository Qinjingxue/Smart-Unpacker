from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from sunpack.support.archive_formats import canonical_format


ACTION_CONTRACT_VERSION = "repair_action_v2"


@dataclass(frozen=True)
class RepairActionDescriptor:
    """Format-preserving action metadata consumed by the shared meta-policy.

    The descriptor intentionally does not claim that two format-specific
    operations are semantically equivalent.  It only exposes properties that
    are safe to compare across formats: granularity, risk, cost and expected
    verification effects.
    """

    format: str
    format_family: str
    expert: str
    operation: str
    route_family: str
    granularity: str
    mutation_scope: str
    mutation_kind: str
    stage: str
    safe: bool
    reversible: bool
    partial: bool
    lossy: bool
    atomic: bool
    estimated_cost: float
    verification_contract: str

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": ACTION_CONTRACT_VERSION, **asdict(self)}


def describe_repair_module(module: Any, *, format_name: str = "") -> RepairActionDescriptor:
    spec = module.spec
    fmt = canonical_format(format_name or _first_format(spec.formats))
    name = str(spec.name or "")
    atomic = bool(getattr(spec, "atomic", False))
    partial = bool(getattr(spec, "partial", False))
    lossy = bool(getattr(spec, "lossy", False))
    safe = bool(getattr(spec, "safe", True))
    stage = str(getattr(spec, "stage", "targeted") or "targeted")
    return RepairActionDescriptor(
        format=fmt,
        format_family=format_family(fmt),
        expert=fmt or "archive",
        operation=name,
        route_family=str(getattr(spec, "route_family", "") or name),
        granularity="atomic" if atomic else "macro",
        mutation_scope=_mutation_scope(name),
        mutation_kind=_mutation_kind(name),
        stage=stage,
        safe=safe,
        reversible=atomic and safe and not lossy,
        partial=partial,
        lossy=lossy,
        atomic=atomic,
        estimated_cost=_estimated_cost(stage=stage, atomic=atomic, partial=partial),
        verification_contract="partial_recovery" if partial else "archive_integrity",
    )


def format_family(format_name: str) -> str:
    fmt = canonical_format(format_name)
    if fmt in {"gzip", "bzip2", "xz", "zstd"}:
        return "compression_stream"
    if fmt == "tar":
        return "sequential_archive"
    if fmt in {"zip", "rar"}:
        return "indexed_container"
    if fmt in {"7z", "seven_zip"}:
        return "coder_graph_container"
    return "archive"


def _first_format(formats: tuple[str, ...]) -> str:
    return next((item for item in formats if item != "archive"), "archive")


def _mutation_scope(name: str) -> str:
    tokens = name.lower()
    for marker, scope in (
        ("folder", "folder"),
        ("entry", "entry"),
        ("file", "entry"),
        ("stream", "stream"),
        ("header", "header"),
        ("eocd", "index"),
        ("directory", "index"),
        ("_cd_", "index"),
        ("footer", "footer"),
        ("trailing", "boundary"),
        ("prefix", "boundary"),
        ("carrier", "boundary"),
        ("block", "block"),
    ):
        if marker in tokens:
            return scope
    return "archive"


def _mutation_kind(name: str) -> str:
    tokens = name.lower()
    for marker, kind in (
        ("rebuild", "rebuild"),
        ("reconcile", "reconcile"),
        ("quarantine", "quarantine"),
        ("salvage", "salvage"),
        ("trim", "trim"),
        ("crop", "crop"),
        ("drop", "delete"),
        ("remove", "delete"),
        ("decode", "decode"),
        ("repoint", "repoint"),
        ("resync", "resync"),
        ("fix", "field_patch"),
        ("repair", "repair"),
    ):
        if marker in tokens:
            return kind
    return "transform"


def _estimated_cost(*, stage: str, atomic: bool, partial: bool) -> float:
    cost = {"targeted": 0.25, "deep": 0.75}.get(stage, 0.5)
    if atomic:
        cost -= 0.1
    if partial:
        cost += 0.1
    return max(0.0, min(1.0, cost))
