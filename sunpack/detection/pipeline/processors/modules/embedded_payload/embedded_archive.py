from typing import Any

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.support.global_cache_manager import cached_value, file_identity
from sunpack.support.archive_sessions import get_archive_session


def _empty_result(*, complete: bool = False) -> dict[str, Any]:
    return {
        "found": False,
        "complete": complete,
        "candidates": [],
        "hits": [],
        "read_bytes": 0,
        "file_size": 0,
    }


def analyze_embedded_archive(
    path: str,
    file_size: int,
    config: dict[str, Any] | None = None,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    """Run the native, extension-independent, complete embedded scan once."""
    del config
    cache_key = identity or file_identity(path)
    return cached_value(
        "embedded_archive_analysis",
        cache_key,
        lambda: _normalize_native_result(
            get_archive_session(path).scan_embedded_archives(), file_size
        ),
    )


def _normalize_native_result(value: Any, expected_size: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("Native scan_embedded_archives returned a non-dict result")
    rows = value.get("candidates")
    if not isinstance(rows, list):
        raise TypeError("Native scan_embedded_archives returned invalid candidates")

    candidates: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("Native scan_embedded_archives returned a non-dict candidate")
        archive_format = str(row.get("format") or "")
        detected_ext = str(row.get("detected_ext") or "")
        offset = int(row.get("offset") or 0)
        if not archive_format or not detected_ext or offset <= 0:
            raise TypeError("Native scan_embedded_archives returned an invalid candidate")
        end_offset = row.get("end_offset")
        candidates.append({
            "format": archive_format,
            "detected_ext": detected_ext,
            "offset": offset,
            "end_offset": None if end_offset is None else int(end_offset),
            "confidence": float(row.get("confidence") or 0.0),
            "validation": str(row.get("validation") or ""),
        })

    candidates.sort(key=lambda item: (item["offset"], item["format"]))
    raw_hits = value.get("hits")
    if not isinstance(raw_hits, list):
        raise TypeError("Native scan_embedded_archives returned invalid hits")
    hits = []
    for row in raw_hits:
        if not isinstance(row, dict):
            raise TypeError("Native scan_embedded_archives returned a non-dict hit")
        name = str(row.get("name") or "")
        offset = int(row.get("offset") or 0)
        if name and offset > 0:
            hits.append({"name": name, "offset": offset, "source": "detection_embedded_scan"})
    hits.sort(key=lambda item: (item["offset"], item["name"]))
    file_size = int(value.get("file_size") or expected_size or 0)
    return {
        "found": bool(candidates),
        "complete": bool(value.get("complete")),
        "candidates": candidates,
        "hits": hits,
        "read_bytes": int(value.get("read_bytes") or 0),
        "file_size": file_size,
    }


@register_processor(
    "embedded_archive",
    input_facts={"file.path", "file.size", "executable.carrier"},
    output_facts={"embedded_archive.analysis"},
    schemas={
        "embedded_archive.analysis": {
            "type": "dict",
            "description": "Complete extension-independent embedded archive scan with every validated candidate.",
        },
    },
)
def process_embedded_archive_analysis(context: FactProcessorContext) -> dict[str, Any]:
    if not bool(context.fact_bag.get("candidate.embedded_payload_precheck_enabled")):
        return _empty_result()
    carrier = context.fact_bag.get("executable.carrier") or {}
    if carrier.get("kind") == "runtime_bundle":
        return _empty_result()
    path = str(context.fact_bag.get("file.path") or "")
    file_size = context.fact_bag.get("file.size")
    if not path or not isinstance(file_size, int) or file_size <= 0:
        return _empty_result()
    try:
        return analyze_embedded_archive(
            path,
            file_size,
            identity=file_identity_for_context(context, path),
        )
    except OSError:
        return _empty_result()
