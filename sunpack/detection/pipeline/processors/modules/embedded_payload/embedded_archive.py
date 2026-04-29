import os
from typing import Any, Dict, Optional

from sunpack_native import scan_after_markers as _NATIVE_SCAN_AFTER_MARKERS
from sunpack_native import scan_carrier_archive as _NATIVE_SCAN_CARRIER_ARCHIVE
from sunpack_native import scan_magics_anywhere as _NATIVE_SCAN_MAGICS_ANYWHERE

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.modules.format_structure.zip_local_header import inspect_zip_local_header
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.config_values import bool_value, non_negative_int, optional_positive_int, positive_int
from sunpack.support.global_cache_manager import cached_value, file_identity, stable_fingerprint
from sunpack.support.extensions import normalize_exts


DEFAULT_LOOSE_SCAN_MIN_PREFIX = 32
DEFAULT_LOOSE_SCAN_MAX_HITS = 3
DEFAULT_LOOSE_SCAN_TAIL_WINDOW_BYTES = 8 * 1024 * 1024
DEFAULT_LOOSE_SCAN_FULL_SCAN_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_LOOSE_SCAN_DEEP_SCAN = False
DEFAULT_CARRIER_SCAN_TAIL_WINDOW_BYTES = 8 * 1024 * 1024
DEFAULT_CARRIER_SCAN_PREFIX_WINDOW_BYTES = 8 * 1024 * 1024
DEFAULT_CARRIER_SCAN_FULL_SCAN_MAX_BYTES = 0
DEFAULT_CARRIER_SCAN_DEEP_SCAN = False

TAIL_MAGICS = {
    b"7z\xbc\xaf\x27\x1c": ".7z",
    b"Rar!\x1a\x07\x00": ".rar",
    b"Rar!\x1a\x07\x01\x00": ".rar",
    b"PK\x03\x04": ".zip",
}


def _empty_result() -> dict[str, Any]:
    return {
        "found": False,
        "detected_ext": "",
        "offset": 0,
        "mode": "",
        "carrier_ext": "",
        "zip_local_header": {},
    }


def _find_tail_after_markers_layered(
    path: str,
    markers: tuple[bytes, ...],
    file_size: int,
    config: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    tail_window = positive_int(
        config,
        "carrier_scan_tail_window_bytes",
        DEFAULT_CARRIER_SCAN_TAIL_WINDOW_BYTES,
    )
    prefix_window = non_negative_int(
        config,
        "carrier_scan_prefix_window_bytes",
        DEFAULT_CARRIER_SCAN_PREFIX_WINDOW_BYTES,
    )
    full_scan_max = non_negative_int(
        config,
        "carrier_scan_full_scan_max_bytes",
        DEFAULT_CARRIER_SCAN_FULL_SCAN_MAX_BYTES,
    )
    deep_scan = bool_value(config, "carrier_scan_deep_scan", DEFAULT_CARRIER_SCAN_DEEP_SCAN)

    tail_start = max(0, file_size - tail_window)
    should_full_scan = deep_scan or (full_scan_max > 0 and file_size <= full_scan_max)

    native_hit = _native_find_tail_after_markers_layered(
        path,
        markers,
        tail_start,
        file_size,
        should_full_scan,
    )
    if native_hit or should_full_scan:
        return native_hit

    if prefix_window <= 0 or tail_start <= 0:
        return None

    return _native_find_after_markers_in_prefix(path, markers, min(file_size, prefix_window))


def _native_find_tail_after_markers_layered(
    path: str,
    markers: tuple[bytes, ...],
    tail_start: int,
    file_size: int,
    should_full_scan: bool,
) -> Optional[Dict[str, Any]]:
    result = _NATIVE_SCAN_AFTER_MARKERS(
        path,
        list(markers),
        [(magic, detected_ext) for magic, detected_ext in TAIL_MAGICS.items()],
        int(tail_start),
        int(file_size),
        bool(should_full_scan),
    )
    if result is None:
        return None
    if not isinstance(result, dict):
        raise TypeError("Native scan_after_markers returned a non-dict result")
    detected_ext = result.get("detected_ext")
    offset = result.get("offset")
    if not isinstance(detected_ext, str) or not detected_ext:
        raise TypeError("Native scan_after_markers returned an invalid detected_ext")
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        raise TypeError("Native scan_after_markers returned an invalid offset")
    return {
        "detected_ext": detected_ext,
        "offset": offset,
        "scan_scope": str(result.get("scan_scope") or ""),
    }


def _native_find_after_markers_in_prefix(
    path: str,
    markers: tuple[bytes, ...],
    prefix_end: int,
) -> Optional[Dict[str, Any]]:
    result = _NATIVE_SCAN_AFTER_MARKERS(
        path,
        list(markers),
        [(magic, detected_ext) for magic, detected_ext in TAIL_MAGICS.items()],
        0,
        int(max(0, prefix_end)),
        False,
    )
    if result is None:
        return None
    if not isinstance(result, dict):
        raise TypeError("Native scan_after_markers returned a non-dict result")
    detected_ext = result.get("detected_ext")
    offset = result.get("offset")
    if not isinstance(detected_ext, str) or not detected_ext:
        raise TypeError("Native scan_after_markers returned an invalid detected_ext")
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        raise TypeError("Native scan_after_markers returned an invalid offset")
    return {
        "detected_ext": detected_ext,
        "offset": offset,
        "scan_scope": "prefix",
    }


def _stream_find_tail_magics_anywhere(
    path: str,
    min_offset: int,
    max_hits: int,
    end_offset: int | None = None,
):
    return _native_stream_find_tail_magics_anywhere(path, min_offset, max_hits, end_offset=end_offset)


def _native_stream_find_tail_magics_anywhere(
    path: str,
    min_offset: int,
    max_hits: int,
    end_offset: int | None = None,
) -> list[dict[str, Any]]:
    result = _NATIVE_SCAN_MAGICS_ANYWHERE(
        path,
        [(magic, detected_ext) for magic, detected_ext in TAIL_MAGICS.items()],
        int(max(0, min_offset)),
        int(max(0, max_hits)),
        None if end_offset is None else int(max(0, end_offset)),
    )
    if not isinstance(result, list):
        raise TypeError("Native scan_magics_anywhere returned a non-list result")

    hits: list[dict[str, Any]] = []
    for item in result:
        if not isinstance(item, dict):
            raise TypeError("Native scan_magics_anywhere returned a non-dict item")
        detected_ext = item.get("detected_ext")
        offset = item.get("offset")
        if not isinstance(detected_ext, str) or not detected_ext:
            raise TypeError("Native scan_magics_anywhere returned an invalid detected_ext")
        try:
            offset = int(offset)
        except (TypeError, ValueError):
            raise TypeError("Native scan_magics_anywhere returned an invalid offset")
        hits.append({"detected_ext": detected_ext, "offset": offset})
    return hits


def _find_after_carrier(path: str, ext: str, file_size: int, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return _native_find_after_carrier(path, ext, file_size, config)


def _native_find_after_carrier(path: str, ext: str, file_size: int, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if ext not in {".jpg", ".jpeg", ".png", ".pdf", ".gif", ".webp"}:
        return None

    tail_window = positive_int(
        config,
        "carrier_scan_tail_window_bytes",
        DEFAULT_CARRIER_SCAN_TAIL_WINDOW_BYTES,
    )
    prefix_window = non_negative_int(
        config,
        "carrier_scan_prefix_window_bytes",
        DEFAULT_CARRIER_SCAN_PREFIX_WINDOW_BYTES,
    )
    full_scan_max = non_negative_int(
        config,
        "carrier_scan_full_scan_max_bytes",
        DEFAULT_CARRIER_SCAN_FULL_SCAN_MAX_BYTES,
    )
    deep_scan = bool_value(config, "carrier_scan_deep_scan", DEFAULT_CARRIER_SCAN_DEEP_SCAN)
    result = _NATIVE_SCAN_CARRIER_ARCHIVE(
        path,
        ext,
        [(magic, detected_ext) for magic, detected_ext in TAIL_MAGICS.items()],
        int(max(0, file_size)),
        int(tail_window),
        int(prefix_window),
        int(full_scan_max),
        bool(deep_scan),
    )

    if result is None:
        return None
    if not isinstance(result, dict):
        raise TypeError("Native scan_carrier_archive returned a non-dict result")
    detected_ext = result.get("detected_ext")
    offset = result.get("offset")
    if not isinstance(detected_ext, str) or not detected_ext:
        raise TypeError("Native scan_carrier_archive returned an invalid detected_ext")
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        raise TypeError("Native scan_carrier_archive returned an invalid offset")
    return {
        "detected_ext": detected_ext,
        "offset": offset,
        "scan_scope": str(result.get("scan_scope") or ""),
    }


def _find_by_loose_scan(path: str, file_size: int, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    min_prefix = non_negative_int(config, "loose_scan_min_prefix", DEFAULT_LOOSE_SCAN_MIN_PREFIX)
    min_tail_bytes = optional_positive_int(config, "loose_scan_min_tail_bytes")
    if min_tail_bytes is None:
        return None
    max_hits = positive_int(config, "loose_scan_max_hits", DEFAULT_LOOSE_SCAN_MAX_HITS)
    tail_window = positive_int(
        config,
        "loose_scan_tail_window_bytes",
        DEFAULT_LOOSE_SCAN_TAIL_WINDOW_BYTES,
    )
    full_scan_max = positive_int(
        config,
        "loose_scan_full_scan_max_bytes",
        DEFAULT_LOOSE_SCAN_FULL_SCAN_MAX_BYTES,
    )
    deep_scan = bool_value(config, "loose_scan_deep_scan", DEFAULT_LOOSE_SCAN_DEEP_SCAN)
    if file_size <= min_prefix + min_tail_bytes:
        return None

    tail_start = max(min_prefix, file_size - tail_window)
    for hit in _stream_find_tail_magics_anywhere(
        path,
        min_offset=tail_start,
        max_hits=max_hits,
        end_offset=file_size,
    ):
        tail_bytes = file_size - hit["offset"]
        if tail_bytes >= min_tail_bytes:
            hit["mode"] = "loose_scan"
            hit["scan_scope"] = "tail"
            return hit

    should_full_scan = deep_scan or file_size <= full_scan_max
    if not should_full_scan:
        return None

    full_scan_end = tail_start if tail_start > min_prefix else file_size
    for hit in _stream_find_tail_magics_anywhere(
        path,
        min_offset=min_prefix,
        max_hits=max_hits,
        end_offset=full_scan_end,
    ):
        tail_bytes = file_size - hit["offset"]
        if tail_bytes >= min_tail_bytes:
            hit["mode"] = "loose_scan"
            hit["scan_scope"] = "full"
            return hit
    return None


def _file_size(context: FactProcessorContext) -> int:
    size = context.fact_bag.get("file.size")
    if isinstance(size, int):
        return size
    return -1


def analyze_embedded_archive(
    path: str,
    file_size: int,
    config: Dict[str, Any],
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    cache_key = (identity or file_identity(path), stable_fingerprint(config or {}))
    return cached_value(
        "embedded_archive_analysis",
        cache_key,
        lambda: _analyze_embedded_archive_uncached(path, file_size, config, identity=identity),
    )


def _analyze_embedded_archive_uncached(
    path: str,
    file_size: int,
    config: Dict[str, Any],
    *,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    ext = os.path.splitext(path)[1].lower()
    carrier_exts = normalize_exts(config.get("carrier_exts"))
    ambiguous_exts = normalize_exts(config.get("ambiguous_resource_exts"))
    if ext not in carrier_exts and ext not in ambiguous_exts:
        return _empty_result()

    embedded = _find_after_carrier(path, ext, file_size, config) if ext in carrier_exts else None
    if embedded:
        embedded["mode"] = "carrier_tail"
    if not embedded and ext in ambiguous_exts:
        embedded = _find_by_loose_scan(path, file_size, config)
    if not embedded:
        return _empty_result()

    detected_ext = embedded.get("detected_ext") or ""
    offset = int(embedded.get("offset") or 0)
    result = {
        "found": True,
        "detected_ext": detected_ext,
        "offset": offset,
        "mode": embedded.get("mode") or "",
        "scan_scope": embedded.get("scan_scope") or "",
        "carrier_ext": ext,
        "zip_local_header": {},
    }
    if detected_ext == ".zip":
        result["zip_local_header"] = inspect_zip_local_header(path, offset, identity=identity)
    return result


@register_processor(
    "embedded_archive",
    input_facts={"file.path", "file.size"},
    output_facts={"embedded_archive.analysis"},
    schemas={
        "embedded_archive.analysis": {
            "type": "dict",
            "description": "Embedded archive scan result including found, detected_ext, offset, mode, and ZIP plausibility.",
        },
    },
)
def process_embedded_archive_analysis(context: FactProcessorContext) -> dict[str, Any]:
    file_size = _file_size(context)
    path = context.fact_bag.get("file.path") or ""
    if not path or file_size < 0:
        return _empty_result()
    try:
        return analyze_embedded_archive(path, file_size, context.fact_config, file_identity_for_context(context, path))
    except OSError:
        return _empty_result()
