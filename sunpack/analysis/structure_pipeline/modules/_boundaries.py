ARCHIVE_SIGNATURE_HIT_NAMES = {"zip_local", "rar4", "rar5", "7z"}


def next_archive_boundary(prepass: dict, start_offset: int, file_size: int) -> int:
    """Return the next top-level archive signature offset after start_offset.

    This is intentionally conservative: ZIP EOCD hits are excluded because they
    are usually internal to a ZIP segment, not the beginning of the next archive.
    """
    start = int(start_offset)
    offsets = []
    for hit in prepass.get("hits", []):
        if hit.get("name") not in ARCHIVE_SIGNATURE_HIT_NAMES:
            continue
        offset = int(hit.get("offset") or 0)
        if offset > start:
            offsets.append(offset)
    return min(offsets) if offsets else int(file_size)
