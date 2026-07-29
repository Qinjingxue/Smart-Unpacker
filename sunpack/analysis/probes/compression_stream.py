from __future__ import annotations

from dataclasses import dataclass

from sunpack_native import inspect_compression_stream_structure as _native_inspect_compression_stream

from sunpack.analysis.observation import FormatObservation
from sunpack.analysis.view import SharedBinaryView
from sunpack.support.global_cache_manager import cached_value, file_identity


SUPPORTED_COMPRESSION_FORMATS = frozenset({"gzip", "bzip2", "xz", "zstd"})


@dataclass(frozen=True, slots=True)
class CompressionStreamProbeOptions:
    format: str = ""

    def __post_init__(self) -> None:
        if self.format and self.format not in SUPPORTED_COMPRESSION_FORMATS:
            raise ValueError(f"unsupported compression format: {self.format}")


def _observation(raw: dict, requested_format: str = "") -> FormatObservation:
    actual_format = str(raw.get("format") or "")
    if requested_format and actual_format != requested_format:
        raw = {
            "format": requested_format,
            "actual_format": actual_format,
            "magic_matched": False,
            "plausible": False,
            "validation_complete": False,
            "error": f"{requested_format}_magic_not_found",
            "damage_flags": [],
            "evidence": [],
        }
        actual_format = requested_format
    validation_complete = bool(raw.get("validation_complete"))
    trailing = int(raw.get("archive.trailing_data") or 0)
    damage_flags = sorted(set(str(item) for item in (raw.get("damage_flags") or []) if item))
    error = str(raw.get("error") or "")
    if validation_complete and not damage_flags and trailing == 0:
        boundary_confidence = "high"
        integrity_confidence = "high"
    elif damage_flags or error:
        boundary_confidence = "low"
        integrity_confidence = "low"
    elif raw.get("plausible"):
        boundary_confidence = "medium"
        integrity_confidence = "unknown"
    else:
        boundary_confidence = "none"
        integrity_confidence = "unknown"
    file_size = int(raw.get("file_size") or 0)
    raw.setdefault("segment_end", file_size - trailing if validation_complete and file_size >= trailing else None)
    raw["boundary_confidence"] = boundary_confidence
    raw["integrity_confidence"] = integrity_confidence
    raw.setdefault("validation_complete", False)
    raw.setdefault("damage_flags", damage_flags)
    capabilities = {"compression_header"}
    if validation_complete:
        capabilities.add("compression_full_validation")
    return FormatObservation(
        format=actual_format or requested_format,
        start_offset=0,
        raw=raw,
        capabilities=frozenset(capabilities),
        damage_flags=tuple(damage_flags),
        boundary_confidence=boundary_confidence,
        integrity_confidence=integrity_confidence,
    )


def probe_compression_stream_path(
    path: str,
    options: CompressionStreamProbeOptions | None = None,
) -> FormatObservation:
    options = options or CompressionStreamProbeOptions()
    identity = file_identity(path)
    raw = cached_value(
        "analysis_compression_stream",
        (identity,),
        lambda: dict(_native_inspect_compression_stream(path)),
    )
    return _observation(dict(raw), options.format)


def probe_compression_stream_view(
    view,
    options: CompressionStreamProbeOptions,
) -> FormatObservation:
    if isinstance(view, SharedBinaryView):
        return probe_compression_stream_path(view.path, options)
    raw = dict(view.probe_compression_stream(format=options.format) or {})
    raw.setdefault("validation_scope", "header_only")
    raw.setdefault("validation_complete", False)
    raw.setdefault("file_size", int(view.size))
    return _observation(raw, options.format)
