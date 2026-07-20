from __future__ import annotations

from typing import Any

from sunpack.analysis.config import analysis_config
from sunpack.analysis.view import MultiVolumeBinaryView
from sunpack.detection.pipeline.processors.context import FactProcessorContext


def detection_binary_view(context: FactProcessorContext) -> MultiVolumeBinaryView:
    """Build the sole binary source used by split-aware detection processors."""
    facts = context.fact_bag
    volumes = facts.get("relation.split_volumes") or []
    if volumes:
        inputs: list[Any] = list(volumes)
    else:
        paths = list(facts.get("candidate.member_paths") or [])
        head = str(facts.get("file.path") or "")
        if head and head not in paths:
            paths.insert(0, head)
        inputs = [
            {"path": str(path), "number": index + 1}
            for index, path in enumerate(dict.fromkeys(paths or [head]))
            if str(path)
        ]
    if not inputs:
        raise ValueError("detection candidate has no binary input")
    config = analysis_config(context.config)
    max_read_mb = config.get("max_read_mb_per_archive", 256)
    return MultiVolumeBinaryView(
        inputs,
        cache_bytes=int(config.get("shared_cache_mb", 64) or 0) * 1024 * 1024,
        max_read_bytes=None if max_read_mb is None else int(max_read_mb) * 1024 * 1024,
        max_concurrent_reads=int(config.get("max_concurrent_reads", 1) or 1),
    )


def find_zip_eocd(view: MultiVolumeBinaryView) -> tuple[int | None, dict[str, Any]]:
    read_size = min(int(view.size), 22 + 65535)
    tail = view.read_tail(read_size)
    base = int(view.size) - len(tail)
    signature = b"PK\x05\x06"
    cursor = len(tail)
    fallback = None
    while True:
        index = tail.rfind(signature, 0, cursor)
        if index < 0:
            break
        if index + 22 <= len(tail):
            record = tail[index:index + 22]
            comment_length = int.from_bytes(record[20:22], "little")
            available = len(tail) - index - 22
            candidate = {
                "eocd_candidate_found": True,
                "eocd_candidate_offset": base + index,
                "eocd_candidate_comment_length": comment_length,
                "eocd_candidate_comment_available_delta": available - comment_length,
                "eocd_candidate_declared_entry_count_present": int.from_bytes(record[10:12], "little") > 0,
                "eocd_candidate_declared_cd_offset_present": int.from_bytes(record[16:20], "little") > 0,
                "eocd_candidate_total_entries": int.from_bytes(record[10:12], "little"),
                "eocd_candidate_cd_offset": int.from_bytes(record[16:20], "little"),
                "eocd_candidate_cd_size": int.from_bytes(record[12:16], "little"),
            }
            fallback = fallback or candidate
            if available == comment_length:
                return base + index, candidate
        cursor = index
    return (fallback["eocd_candidate_offset"], fallback) if fallback else (None, {"eocd_candidate_found": False})


def inspect_zip_local_header_view(view: MultiVolumeBinaryView, offset: int = 0) -> dict[str, Any]:
    header = view.read_at(offset, 30)
    result = {
        "plausible": False,
        "magic_matched": header[:4] == b"PK\x03\x04",
        "error": "zip_local_header_not_found",
        "version_needed": 0,
        "compression_method": 0,
        "filename_len": 0,
        "extra_len": 0,
    }
    if len(header) < 30 or not result["magic_matched"]:
        return result
    version_needed = int.from_bytes(header[4:6], "little")
    method = int.from_bytes(header[8:10], "little")
    filename_len = int.from_bytes(header[26:28], "little")
    extra_len = int.from_bytes(header[28:30], "little")
    result.update({
        "version_needed": version_needed,
        "compression_method": method,
        "filename_len": filename_len,
        "extra_len": extra_len,
    })
    if version_needed > 99:
        result["error"] = "zip_version_needed_out_of_range"
    elif method > 99:
        result["error"] = "zip_compression_method_out_of_range"
    elif filename_len == 0 or offset + 30 + filename_len + extra_len > view.size:
        result["error"] = "zip_local_header_variable_fields_out_of_range"
    else:
        result.update({"plausible": True, "error": ""})
    return result


def inspect_seven_zip_view(view: MultiVolumeBinaryView, max_next_header_check_bytes: int) -> dict[str, Any]:
    result = dict(view.probe_seven_zip(
        start_offset=0,
        max_next_header_check_bytes=max_next_header_check_bytes,
    ) or {})
    header = view.read_at(0, 32)
    result.update({
        "format": "7z" if result.get("magic_matched") else "",
        "detected_ext": ".7z" if result.get("magic_matched") else "",
        "version_major": header[6] if len(header) > 7 else 0,
        "version_minor": header[7] if len(header) > 7 else 0,
        "next_header_semantic_ok": bool(result.get("next_header_crc_ok") and result.get("next_header_nid_valid")),
        "confidence": "strong" if result.get("plausible") else "none",
    })
    if result.get("magic_matched") and result["version_major"] != 0:
        result.update({"plausible": False, "strong_accept": False, "error": "unsupported_version"})
    return result


def inspect_rar_view(view: MultiVolumeBinaryView, max_first_header_check_bytes: int) -> dict[str, Any]:
    # Detection needs the CRC-protected main header and one following block,
    # not a Python-side full archive walk. Bulk/random reads remain in the
    # native multi-volume view and this control loop is strictly bounded.
    result = dict(view.probe_rar(start_offset=0, max_blocks_to_walk=2) or {})
    checked = int(result.get("blocks_checked") or 0)
    first_header_ok = bool(result.get("magic_matched") and checked >= 1)
    block_walk_ok = checked >= 2
    result.update({
        "format": "rar" if result.get("magic_matched") else "",
        "detected_ext": ".rar" if result.get("magic_matched") else "",
        "plausible": bool(result.get("plausible") or first_header_ok),
        "header_crc_checked": first_header_ok,
        "header_crc_ok": first_header_ok,
        "second_block_checked": block_walk_ok,
        "second_block_ok": block_walk_ok,
        "block_walk_ok": block_walk_ok,
        "strong_accept": bool(result.get("strong_accept") or block_walk_ok),
        "confidence": "strong" if first_header_ok else "none",
    })
    if block_walk_ok:
        result["error"] = ""
    return result
