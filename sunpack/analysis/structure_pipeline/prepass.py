from sunpack.analysis.view import SharedBinaryView


DEFAULT_HEAD_BYTES = 1024 * 1024
DEFAULT_TAIL_BYTES = 1024 * 1024
KNOWN_SIGNATURES = {
    "zip_local": b"PK\x03\x04",
    "zip_eocd": b"PK\x05\x06",
    "rar4": b"Rar!\x1a\x07\x00",
    "rar5": b"Rar!\x1a\x07\x01\x00",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "gzip": b"\x1f\x8b\x08",
    "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00",
    "zstd": b"\x28\xb5\x2f\xfd",
    "tar_ustar": b"ustar",
}


def run_signature_prepass(view: SharedBinaryView, config: dict | None = None) -> dict:
    config = config or {}
    head_size = int(config.get("head_bytes", DEFAULT_HEAD_BYTES) or DEFAULT_HEAD_BYTES)
    tail_size = int(config.get("tail_bytes", DEFAULT_TAIL_BYTES) or DEFAULT_TAIL_BYTES)
    return view.signature_prepass(head_bytes=head_size, tail_bytes=tail_size)


def extend_signature_prepass_full(view, prepass: dict, config: dict | None = None) -> dict:
    """Discover candidates across the logical byte stream, preserving one prepass."""
    config = config or {}
    deep_scan = bool(config.get("deep_scan", False))
    full_scan_max = max(0, int(config.get("full_scan_max_bytes", 0) or 0))
    if not deep_scan and (full_scan_max <= 0 or int(view.size) > full_scan_max):
        return prepass

    chunk_size = max(64 * 1024, int(config.get("full_scan_chunk_bytes", 4 * 1024 * 1024) or 0))
    max_hits = max(1, int(config.get("full_scan_max_hits", 256) or 1))
    signatures = {name: value for name, value in KNOWN_SIGNATURES.items() if name != "tar_ustar"}
    overlap = max(len(value) for value in signatures.values()) - 1
    existing = {
        (str(hit.get("name") or ""), int(hit.get("offset") or 0))
        for hit in prepass.get("hits", [])
    }
    hits = list(prepass.get("hits", []))
    carry = b""
    offset = 0
    while offset < int(view.size) and len(hits) < max_hits:
        data = view.read_at(offset, min(chunk_size, int(view.size) - offset))
        window = carry + data
        window_start = offset - len(carry)
        for name, signature in signatures.items():
            cursor = 0
            while len(hits) < max_hits:
                found = window.find(signature, cursor)
                if found < 0:
                    break
                absolute = window_start + found
                key = (name, absolute)
                if key not in existing:
                    existing.add(key)
                    hits.append({"name": name, "offset": absolute, "source": "full"})
                cursor = found + 1
        carry = window[-overlap:] if overlap else b""
        offset += len(data)
        if not data:
            break
    hits.sort(key=lambda item: (int(item.get("offset") or 0), str(item.get("name") or "")))
    result = dict(prepass)
    result["hits"] = hits
    result["formats"] = sorted({_format_for_hit(str(hit["name"])) for hit in hits})
    result["full_scan_bytes"] = offset
    result["full_scan_complete"] = offset >= int(view.size)
    return result


def _format_for_hit(name: str) -> str:
    if name.startswith("zip_"):
        return "zip"
    if name in {"rar4", "rar5"}:
        return "rar"
    return name
