import os
from typing import Any, Dict, Optional

from smart_unpacker.detection.pipeline.processors.context import FactProcessorContext
from smart_unpacker.detection.pipeline.processors.modules.format_structure.zip_local_header import inspect_zip_local_header
from smart_unpacker.detection.pipeline.processors.registry import register_processor
from smart_unpacker.support.external_command_cache import cached_value, file_identity, stable_fingerprint


STREAM_CHUNK_SIZE = 1024 * 1024
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


try:
    from smart_unpacker_native import scan_carrier_archive as _NATIVE_SCAN_CARRIER_ARCHIVE
    from smart_unpacker_native import scan_after_markers as _NATIVE_SCAN_AFTER_MARKERS
    from smart_unpacker_native import scan_magics_anywhere as _NATIVE_SCAN_MAGICS_ANYWHERE
except ImportError:
    _NATIVE_SCAN_CARRIER_ARCHIVE = None
    _NATIVE_SCAN_AFTER_MARKERS = None
    _NATIVE_SCAN_MAGICS_ANYWHERE = None


def _empty_result() -> dict[str, Any]:
    return {
        "found": False,
        "detected_ext": "",
        "offset": 0,
        "mode": "",
        "carrier_ext": "",
        "zip_local_header": {},
    }


def _normalize_exts(values) -> set[str]:
    normalized = set()
    for value in values or []:
        if not isinstance(value, str) or not value.strip():
            continue
        ext = value.strip().lower()
        normalized.add(ext if ext.startswith(".") else f".{ext}")
    return normalized


def _match_tail_magic(sample: bytes, offset: int = 0):
    for magic, detected_ext in TAIL_MAGICS.items():
        index = sample.find(magic, offset)
        if index != -1:
            return detected_ext, index
    return None, -1


def _stream_find_tail_magic_from_offset(path: str, absolute_offset: int) -> Optional[Dict[str, Any]]:
    absolute_offset = max(0, absolute_offset)
    max_tail_len = max((len(magic) for magic in TAIL_MAGICS), default=0)
    overlap = max(max_tail_len - 1, 0)
    with open(path, "rb") as handle:
        handle.seek(absolute_offset)
        carry = b""
        current_offset = absolute_offset
        while True:
            chunk = handle.read(STREAM_CHUNK_SIZE)
            if not chunk:
                return None
            sample = carry + chunk
            base_offset = current_offset - len(carry)
            detected_ext, relative_index = _match_tail_magic(sample, 0)
            if detected_ext:
                return {"detected_ext": detected_ext, "offset": base_offset + relative_index}
            carry = sample[-overlap:] if len(sample) > overlap else sample
            current_offset += len(chunk)


def _stream_find_tail_after_markers(path: str, markers: tuple[bytes, ...]) -> Optional[Dict[str, Any]]:
    markers = tuple(marker for marker in markers if marker)
    if not markers:
        return None
    max_marker_len = max(len(marker) for marker in markers)
    max_tail_len = max((len(magic) for magic in TAIL_MAGICS), default=0)
    overlap = max(max_marker_len, max_tail_len) - 1
    with open(path, "rb") as handle:
        carry = b""
        current_offset = 0
        while True:
            chunk = handle.read(STREAM_CHUNK_SIZE)
            if not chunk:
                return None
            sample = carry + chunk
            base_offset = current_offset - len(carry)
            first_match = None
            for marker in markers:
                index = sample.find(marker)
                if index != -1 and (first_match is None or index < first_match[1]):
                    first_match = (marker, index)
            if first_match is not None:
                marker, marker_index = first_match
                search_start = marker_index + len(marker)
                detected_ext, relative_index = _match_tail_magic(sample, search_start)
                if detected_ext:
                    return {"detected_ext": detected_ext, "offset": base_offset + relative_index}
                return _stream_find_tail_magic_from_offset(path, base_offset + search_start)
            carry = sample[-overlap:] if len(sample) > overlap else sample
            current_offset += len(chunk)


def _find_tail_after_markers_in_range(
    path: str,
    markers: tuple[bytes, ...],
    start_offset: int,
    end_offset: int,
) -> tuple[Optional[Dict[str, Any]], bool]:
    markers = tuple(marker for marker in markers if marker)
    if not markers or end_offset <= start_offset:
        return None, False
    with open(path, "rb") as handle:
        handle.seek(start_offset)
        sample = handle.read(end_offset - start_offset)

    marker_found = False
    search_end = len(sample)
    while search_end > 0:
        last_match = None
        for marker in markers:
            index = sample.rfind(marker, 0, search_end)
            if index != -1 and (last_match is None or index > last_match[1]):
                last_match = (marker, index)
        if last_match is None:
            break
        marker_found = True
        marker, marker_index = last_match
        search_start = marker_index + len(marker)
        detected_ext, relative_index = _match_tail_magic(sample, search_start)
        if detected_ext:
            return {"detected_ext": detected_ext, "offset": start_offset + relative_index}, True
        search_end = marker_index

    if not marker_found:
        return None, False

    return None, True


def _find_tail_after_markers_layered(
    path: str,
    markers: tuple[bytes, ...],
    file_size: int,
    config: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    tail_window = _positive_int_config(
        config,
        "carrier_scan_tail_window_bytes",
        DEFAULT_CARRIER_SCAN_TAIL_WINDOW_BYTES,
    )
    prefix_window = _non_negative_int_config(
        config,
        "carrier_scan_prefix_window_bytes",
        DEFAULT_CARRIER_SCAN_PREFIX_WINDOW_BYTES,
    )
    full_scan_max = _non_negative_int_config(
        config,
        "carrier_scan_full_scan_max_bytes",
        DEFAULT_CARRIER_SCAN_FULL_SCAN_MAX_BYTES,
    )
    deep_scan = _bool_config(config, "carrier_scan_deep_scan", DEFAULT_CARRIER_SCAN_DEEP_SCAN)

    tail_start = max(0, file_size - tail_window)
    should_full_scan = deep_scan or (full_scan_max > 0 and file_size <= full_scan_max)

    native_used, native_hit = _native_find_tail_after_markers_layered(
        path,
        markers,
        tail_start,
        file_size,
        should_full_scan,
    )
    if native_hit:
        return native_hit

    tail_marker_found = False
    if not native_used:
        embedded, tail_marker_found = _find_tail_after_markers_in_range(path, markers, tail_start, file_size)
        if embedded:
            embedded.setdefault("scan_scope", "tail")
            return embedded
    elif should_full_scan:
        return None

    if prefix_window > 0 and tail_start > 0:
        prefix_end = min(file_size, prefix_window)
        native_prefix_used, native_prefix_hit = _native_find_after_markers_in_prefix(path, markers, prefix_end)
        if native_prefix_used:
            if native_prefix_hit:
                return native_prefix_hit
        else:
            embedded, _prefix_marker_found = _find_tail_after_markers_in_range(path, markers, 0, prefix_end)
            if embedded:
                embedded.setdefault("scan_scope", "prefix")
                return embedded

    if tail_marker_found or not should_full_scan:
        return None

    embedded = _stream_find_tail_after_markers(path, markers)
    if embedded:
        embedded.setdefault("scan_scope", "full")
    return embedded


def _native_find_tail_after_markers_layered(
    path: str,
    markers: tuple[bytes, ...],
    tail_start: int,
    file_size: int,
    should_full_scan: bool,
) -> tuple[bool, Optional[Dict[str, Any]]]:
    if _native_scan_disabled() or _NATIVE_SCAN_AFTER_MARKERS is None:
        return False, None
    try:
        result = _NATIVE_SCAN_AFTER_MARKERS(
            path,
            list(markers),
            [(magic, detected_ext) for magic, detected_ext in TAIL_MAGICS.items()],
            int(tail_start),
            int(file_size),
            bool(should_full_scan),
        )
    except Exception:
        return False, None
    if result is None:
        return True, None
    if not isinstance(result, dict):
        return False, None
    detected_ext = result.get("detected_ext")
    offset = result.get("offset")
    if not isinstance(detected_ext, str) or not detected_ext:
        return False, None
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return False, None
    return True, {
        "detected_ext": detected_ext,
        "offset": offset,
        "scan_scope": str(result.get("scan_scope") or ""),
    }


def _native_find_after_markers_in_prefix(
    path: str,
    markers: tuple[bytes, ...],
    prefix_end: int,
) -> tuple[bool, Optional[Dict[str, Any]]]:
    if _native_scan_disabled() or _NATIVE_SCAN_AFTER_MARKERS is None:
        return False, None
    try:
        result = _NATIVE_SCAN_AFTER_MARKERS(
            path,
            list(markers),
            [(magic, detected_ext) for magic, detected_ext in TAIL_MAGICS.items()],
            0,
            int(max(0, prefix_end)),
            False,
        )
    except Exception:
        return False, None
    if result is None:
        return True, None
    if not isinstance(result, dict):
        return False, None
    detected_ext = result.get("detected_ext")
    offset = result.get("offset")
    if not isinstance(detected_ext, str) or not detected_ext:
        return False, None
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return False, None
    return True, {
        "detected_ext": detected_ext,
        "offset": offset,
        "scan_scope": "prefix",
    }


def _native_scan_disabled() -> bool:
    value = os.environ.get("SMART_UNPACKER_DISABLE_NATIVE", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _stream_find_tail_magics_anywhere(
    path: str,
    min_offset: int,
    max_hits: int,
    end_offset: int | None = None,
):
    native_used, native_hits = _native_stream_find_tail_magics_anywhere(
        path,
        min_offset,
        max_hits,
        end_offset=end_offset,
    )
    if native_used:
        return native_hits

    max_tail_len = max((len(magic) for magic in TAIL_MAGICS), default=0)
    overlap = max(max_tail_len - 1, 0)
    hits = []
    with open(path, "rb") as handle:
        handle.seek(max(0, min_offset))
        carry = b""
        current_offset = max(0, min_offset)
        while len(hits) < max_hits:
            if end_offset is not None and current_offset >= end_offset:
                break
            read_size = STREAM_CHUNK_SIZE
            if end_offset is not None:
                read_size = min(read_size, max(0, end_offset - current_offset))
            chunk = handle.read(read_size)
            if not chunk:
                break
            sample = carry + chunk
            base_offset = current_offset - len(carry)
            search_start = 0
            while len(hits) < max_hits:
                detected_ext, relative_index = _match_tail_magic(sample, search_start)
                if detected_ext is None:
                    break
                absolute = base_offset + relative_index
                if absolute >= min_offset and (end_offset is None or absolute < end_offset):
                    hits.append({"detected_ext": detected_ext, "offset": absolute})
                search_start = relative_index + 1
            carry = sample[-overlap:] if len(sample) > overlap else sample
            current_offset += len(chunk)
    return hits


def _native_stream_find_tail_magics_anywhere(
    path: str,
    min_offset: int,
    max_hits: int,
    end_offset: int | None = None,
) -> tuple[bool, list[dict[str, Any]]]:
    if _native_scan_disabled() or _NATIVE_SCAN_MAGICS_ANYWHERE is None:
        return False, []
    try:
        result = _NATIVE_SCAN_MAGICS_ANYWHERE(
            path,
            [(magic, detected_ext) for magic, detected_ext in TAIL_MAGICS.items()],
            int(max(0, min_offset)),
            int(max(0, max_hits)),
            None if end_offset is None else int(max(0, end_offset)),
        )
    except Exception:
        return False, []
    if not isinstance(result, list):
        return False, []

    hits: list[dict[str, Any]] = []
    for item in result:
        if not isinstance(item, dict):
            return False, []
        detected_ext = item.get("detected_ext")
        offset = item.get("offset")
        if not isinstance(detected_ext, str) or not detected_ext:
            return False, []
        try:
            offset = int(offset)
        except (TypeError, ValueError):
            return False, []
        hits.append({"detected_ext": detected_ext, "offset": offset})
    return True, hits


def _positive_int_config(config: Dict[str, Any], key: str, default: int) -> int:
    try:
        value = int(config.get(key, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _required_positive_int_config(config: Dict[str, Any], key: str) -> int | None:
    try:
        value = int(config.get(key))
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _non_negative_int_config(config: Dict[str, Any], key: str, default: int) -> int:
    try:
        value = int(config.get(key, default))
    except (TypeError, ValueError):
        return default
    return value if value >= 0 else default


def _bool_config(config: Dict[str, Any], key: str, default: bool) -> bool:
    value = config.get(key, default)
    return value if isinstance(value, bool) else default


def _find_after_carrier(path: str, ext: str, file_size: int, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    native_used, native_hit = _native_find_after_carrier(path, ext, file_size, config)
    if native_used:
        return native_hit

    if ext in {".jpg", ".jpeg"}:
        return _find_tail_after_markers_layered(path, (b"\xff\xd9",), file_size, config)
    if ext == ".png":
        return _find_tail_after_markers_layered(path, (b"IEND\xaeB`\x82",), file_size, config)
    if ext == ".pdf":
        return _find_tail_after_markers_layered(path, (b"%%EOF\r\n", b"%%EOF\n", b"%%EOF"), file_size, config)
    if ext == ".gif":
        trailer_offset = _gif_trailer_offset(path)
        if trailer_offset is None:
            return None
        embedded = _stream_find_tail_magic_from_offset(path, trailer_offset + 1)
        if embedded:
            embedded.setdefault("scan_scope", "after_gif_trailer")
        return embedded
    if ext == ".webp":
        with open(path, "rb") as handle:
            header = handle.read(12)
        if len(header) < 12 or not header.startswith(b"RIFF") or header[8:12] != b"WEBP":
            return None
        riff_size = int.from_bytes(header[4:8], "little")
        return _stream_find_tail_magic_from_offset(path, 8 + riff_size)
    return None


def _native_find_after_carrier(path: str, ext: str, file_size: int, config: Dict[str, Any]) -> tuple[bool, Optional[Dict[str, Any]]]:
    if _native_scan_disabled() or _NATIVE_SCAN_CARRIER_ARCHIVE is None:
        return False, None
    if ext not in {".jpg", ".jpeg", ".png", ".pdf", ".gif", ".webp"}:
        return False, None

    tail_window = _positive_int_config(
        config,
        "carrier_scan_tail_window_bytes",
        DEFAULT_CARRIER_SCAN_TAIL_WINDOW_BYTES,
    )
    prefix_window = _non_negative_int_config(
        config,
        "carrier_scan_prefix_window_bytes",
        DEFAULT_CARRIER_SCAN_PREFIX_WINDOW_BYTES,
    )
    full_scan_max = _non_negative_int_config(
        config,
        "carrier_scan_full_scan_max_bytes",
        DEFAULT_CARRIER_SCAN_FULL_SCAN_MAX_BYTES,
    )
    deep_scan = _bool_config(config, "carrier_scan_deep_scan", DEFAULT_CARRIER_SCAN_DEEP_SCAN)
    try:
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
    except Exception:
        return False, None

    if result is None:
        return True, None
    if not isinstance(result, dict):
        return False, None
    detected_ext = result.get("detected_ext")
    offset = result.get("offset")
    if not isinstance(detected_ext, str) or not detected_ext:
        return False, None
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        return False, None
    return True, {
        "detected_ext": detected_ext,
        "offset": offset,
        "scan_scope": str(result.get("scan_scope") or ""),
    }


def _gif_trailer_offset(path: str) -> int | None:
    """Return the real GIF trailer offset, not an arbitrary ';' byte in image data."""
    try:
        with open(path, "rb") as handle:
            header = handle.read(13)
            if len(header) < 13 or header[:6] not in {b"GIF87a", b"GIF89a"}:
                return None

            packed = header[10]
            if packed & 0x80:
                color_table_size = 3 * (2 ** ((packed & 0x07) + 1))
                handle.seek(color_table_size, os.SEEK_CUR)

            while True:
                introducer = handle.read(1)
                if not introducer:
                    return None
                code = introducer[0]
                if code == 0x3B:
                    return handle.tell() - 1
                if code == 0x2C:
                    image_descriptor = handle.read(9)
                    if len(image_descriptor) < 9:
                        return None
                    packed = image_descriptor[8]
                    if packed & 0x80:
                        color_table_size = 3 * (2 ** ((packed & 0x07) + 1))
                        handle.seek(color_table_size, os.SEEK_CUR)
                    if not _skip_gif_sub_blocks(handle, skip_lzw_minimum=True):
                        return None
                    continue
                if code == 0x21:
                    label = handle.read(1)
                    if len(label) < 1:
                        return None
                    if not _skip_gif_sub_blocks(handle):
                        return None
                    continue
                return None
    except OSError:
        return None


def _skip_gif_sub_blocks(handle, skip_lzw_minimum: bool = False) -> bool:
    if skip_lzw_minimum and len(handle.read(1)) < 1:
        return False
    while True:
        size = handle.read(1)
        if len(size) < 1:
            return False
        block_size = size[0]
        if block_size == 0:
            return True
        handle.seek(block_size, os.SEEK_CUR)


def _find_by_loose_scan(path: str, file_size: int, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    min_prefix = _non_negative_int_config(config, "loose_scan_min_prefix", DEFAULT_LOOSE_SCAN_MIN_PREFIX)
    min_tail_bytes = _required_positive_int_config(config, "loose_scan_min_tail_bytes")
    if min_tail_bytes is None:
        return None
    max_hits = _positive_int_config(config, "loose_scan_max_hits", DEFAULT_LOOSE_SCAN_MAX_HITS)
    tail_window = _positive_int_config(
        config,
        "loose_scan_tail_window_bytes",
        DEFAULT_LOOSE_SCAN_TAIL_WINDOW_BYTES,
    )
    full_scan_max = _positive_int_config(
        config,
        "loose_scan_full_scan_max_bytes",
        DEFAULT_LOOSE_SCAN_FULL_SCAN_MAX_BYTES,
    )
    deep_scan = _bool_config(config, "loose_scan_deep_scan", DEFAULT_LOOSE_SCAN_DEEP_SCAN)
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


def analyze_embedded_archive(path: str, file_size: int, config: Dict[str, Any]) -> dict[str, Any]:
    cache_key = (file_identity(path), stable_fingerprint(config or {}))
    return cached_value(
        "embedded_archive_analysis",
        cache_key,
        lambda: _analyze_embedded_archive_uncached(path, file_size, config),
    )


def _analyze_embedded_archive_uncached(path: str, file_size: int, config: Dict[str, Any]) -> dict[str, Any]:
    ext = os.path.splitext(path)[1].lower()
    carrier_exts = _normalize_exts(config.get("carrier_exts"))
    ambiguous_exts = _normalize_exts(config.get("ambiguous_resource_exts"))
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
        result["zip_local_header"] = inspect_zip_local_header(path, offset)
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
        return analyze_embedded_archive(path, file_size, context.fact_config)
    except OSError:
        return _empty_result()
