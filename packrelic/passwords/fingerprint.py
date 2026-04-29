from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArchiveFingerprint:
    key: str
    archive_path: str
    part_paths: tuple[str, ...] = ()


def build_archive_fingerprint(archive_path: str, part_paths: list[str] | None = None) -> ArchiveFingerprint:
    normalized_archive = str(Path(archive_path).resolve())
    normalized_parts = tuple(str(Path(path).resolve()) for path in part_paths or [])
    digest = hashlib.sha256()
    for path in (normalized_archive, *normalized_parts):
        digest.update(path.encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
        try:
            stat = Path(path).stat()
        except OSError:
            digest.update(b"missing")
            continue
        digest.update(str(stat.st_size).encode("ascii"))
        digest.update(b":")
        digest.update(str(stat.st_mtime_ns).encode("ascii"))
        digest.update(b"\0")
    return ArchiveFingerprint(
        key=digest.hexdigest(),
        archive_path=normalized_archive,
        part_paths=normalized_parts,
    )
