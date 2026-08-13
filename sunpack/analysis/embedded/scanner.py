from __future__ import annotations

import threading
from typing import Any

from sunpack.analysis.embedded.result import EmbeddedCandidate, EmbeddedScanResult, SignatureHit
from sunpack.support.archive_sessions import get_archive_session
from sunpack.support.global_cache_manager import GLOBAL_CACHE, file_identity


_CACHE_NAMESPACE = "embedded_archive_scan_v3"
_SCAN_LOCKS = tuple(threading.Lock() for _ in range(32))


def scan_embedded_archives(
    path: str,
    *,
    expected_size: int = 0,
    identity: tuple[str, int, int] | None = None,
) -> EmbeddedScanResult:
    """Run the canonical native full-stream embedded scan at most once per file identity."""
    cache_key = identity or file_identity(path)
    payload = GLOBAL_CACHE.get(_CACHE_NAMESPACE, cache_key)
    if payload is None:
        lock = _SCAN_LOCKS[hash(cache_key) % len(_SCAN_LOCKS)]
        with lock:
            payload = GLOBAL_CACHE.get(_CACHE_NAMESPACE, cache_key)
            if payload is None:
                payload = _normalize_native_result(
                    get_archive_session(path).scan_embedded_archives(), expected_size
                ).to_dict()
                GLOBAL_CACHE.set(_CACHE_NAMESPACE, cache_key, payload)
    return embedded_result_from_dict(payload)


def _normalize_native_result(value: Any, expected_size: int) -> EmbeddedScanResult:
    if not isinstance(value, dict):
        raise TypeError("Native scan_embedded_archives returned a non-dict result")
    rows = value.get("candidates")
    if not isinstance(rows, list):
        raise TypeError("Native scan_embedded_archives returned invalid candidates")

    candidates = []
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("Native scan_embedded_archives returned a non-dict candidate")
        archive_format = str(row.get("format") or "")
        detected_ext = str(row.get("detected_ext") or "")
        offset = int(row.get("offset") or 0)
        if not archive_format or not detected_ext or offset < 0:
            raise TypeError("Native scan_embedded_archives returned an invalid candidate")
        end_offset = row.get("end_offset")
        range_end_offset = row.get("range_end_offset")
        validation = str(row.get("validation") or "")
        legacy_anchor = end_offset is None and (
            "local_header" in validation or validation == "ustar_checksum"
        )
        candidates.append(EmbeddedCandidate(
            format=archive_format,
            detected_ext=detected_ext,
            offset=offset,
            end_offset=None if end_offset is None else int(end_offset),
            confidence=float(row.get("confidence") or 0.0),
            validation=validation,
            candidate_kind=str(row.get("candidate_kind") or ("anchor" if legacy_anchor else "logical_archive")),
            boundary_kind=str(row.get("boundary_kind") or ("exact" if end_offset is not None else "unresolved")),
            range_end_offset=None if range_end_offset is None else int(range_end_offset),
            extractable=bool(row.get("extractable", end_offset is not None)),
            contained_anchor_count=int(row.get("contained_anchor_count") or 0),
        ))

    raw_hits = value.get("hits")
    if not isinstance(raw_hits, list):
        raise TypeError("Native scan_embedded_archives returned invalid hits")
    validated_formats = {item.format for item in candidates}
    hit_formats = {
        "zip_local": "zip", "zip_eocd": "zip", "rar4": "rar", "rar5": "rar",
        "7z": "7z", "gzip": "gzip", "bzip2": "bzip2", "xz": "xz",
        "zstd": "zstd", "tar_ustar": "tar",
    }
    hits = []
    for row in raw_hits:
        if not isinstance(row, dict):
            raise TypeError("Native scan_embedded_archives returned a non-dict hit")
        name = str(row.get("name") or "")
        offset = int(row.get("offset") or 0)
        if name and offset >= 0 and hit_formats.get(name) in validated_formats:
            hits.append(SignatureHit(name=name, offset=offset))

    return EmbeddedScanResult(
        complete=bool(value.get("complete")),
        candidates=tuple(sorted(candidates, key=lambda item: (item.offset, item.format))),
        hits=tuple(sorted(hits, key=lambda item: (item.offset, item.name))),
        read_bytes=int(value.get("read_bytes") or 0),
        file_size=int(value.get("file_size") or expected_size or 0),
        logical_resolution_complete=bool(
            value.get("logical_resolution_complete", value.get("complete"))
        ),
        raw_hit_count=int(value.get("raw_hit_count") or len(raw_hits)),
        budget_exhausted=bool(value.get("budget_exhausted")),
    )


def embedded_result_from_dict(value: dict[str, Any]) -> EmbeddedScanResult:
    return EmbeddedScanResult(
        complete=bool(value.get("complete")),
        candidates=tuple(
            EmbeddedCandidate(
                format=str(item["format"]),
                detected_ext=str(item["detected_ext"]),
                offset=int(item["offset"]),
                end_offset=None if item.get("end_offset") is None else int(item["end_offset"]),
                confidence=float(item.get("confidence") or 0.0),
                validation=str(item.get("validation") or ""),
                candidate_kind=str(item.get("candidate_kind") or (
                    "anchor"
                    if item.get("end_offset") is None and (
                        "local_header" in str(item.get("validation") or "")
                        or str(item.get("validation") or "") == "ustar_checksum"
                    )
                    else "logical_archive"
                )),
                boundary_kind=str(item.get("boundary_kind") or ("exact" if item.get("end_offset") is not None else "unresolved")),
                range_end_offset=None if item.get("range_end_offset") is None else int(item["range_end_offset"]),
                extractable=bool(item.get("extractable", item.get("end_offset") is not None)),
                contained_anchor_count=int(item.get("contained_anchor_count") or 0),
            )
            for item in value.get("candidates", [])
        ),
        hits=tuple(
            SignatureHit(name=str(item["name"]), offset=int(item["offset"]))
            for item in value.get("hits", [])
        ),
        read_bytes=int(value.get("read_bytes") or 0),
        file_size=int(value.get("file_size") or 0),
        logical_resolution_complete=bool(
            value.get("logical_resolution_complete", value.get("complete"))
        ),
        raw_hit_count=int(value.get("raw_hit_count") or len(value.get("hits", []))),
        budget_exhausted=bool(value.get("budget_exhausted")),
    )
