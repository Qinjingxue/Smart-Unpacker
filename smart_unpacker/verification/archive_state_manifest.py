from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from smart_unpacker.contracts.archive_state import ArchiveState
from smart_unpacker.support.archive_state_view import UnsupportedArchivePatch, archive_state_to_bytes
from smart_unpacker.support.sevenzip_native import STATUS_DAMAGED, STATUS_OK, STATUS_UNSUPPORTED


@dataclass(frozen=True)
class ArchiveStateManifest:
    status: int
    is_archive: bool
    damaged: bool
    checksum_error: bool
    item_count: int
    file_count: int
    files: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""
    archive_type: str = ""
    source: str = "archive_state"
    state_aware: bool = True
    patch_digest: str = ""

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.is_archive and not self.damaged and not self.checksum_error

    @property
    def expected_names(self) -> list[str]:
        return [str(item.get("path") or "") for item in self.files if item.get("path")]

    @property
    def total_unpacked_size(self) -> int:
        return sum(max(0, int(item.get("size", 0) or 0)) for item in self.files)


def archive_state_manifest_for_evidence(evidence, *, max_items: int = 200000) -> ArchiveStateManifest:
    cache_key = f"_archive_state_manifest_cache_{max(0, int(max_items or 0))}"
    cached = getattr(evidence, cache_key, None)
    if isinstance(cached, ArchiveStateManifest):
        return cached
    manifest = archive_state_manifest(evidence.archive_state, max_items=max_items)
    object.__setattr__(evidence, cache_key, manifest)
    return manifest


def archive_state_manifest(state: ArchiveState, *, max_items: int = 200000) -> ArchiveStateManifest:
    patch_digest = state.effective_patch_digest()
    try:
        data = archive_state_to_bytes(state)
    except (OSError, ValueError, UnsupportedArchivePatch) as exc:
        return ArchiveStateManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message=f"Archive state cannot be opened as a verification byte view: {exc}",
            patch_digest=patch_digest,
        )

    hint = _format_hint(state)
    if hint and hint != "zip" and not _looks_like_zip(data, state):
        return ArchiveStateManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message=f"Archive-state manifest is not implemented for format: {hint}",
            archive_type=hint,
            patch_digest=patch_digest,
        )
    if not _looks_like_zip(data, state):
        return ArchiveStateManifest(
            status=STATUS_UNSUPPORTED,
            is_archive=False,
            damaged=False,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message="Archive-state manifest could not identify a supported archive format",
            patch_digest=patch_digest,
        )

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            files = []
            encrypted = False
            for info in infos[: max(0, int(max_items or 0))]:
                encrypted = encrypted or bool(info.flag_bits & 0x1)
                if info.is_dir():
                    continue
                files.append({
                    "path": info.filename,
                    "size": int(info.file_size),
                    "packed_size": int(info.compress_size),
                    "has_crc": True,
                    "crc32": int(info.CRC) & 0xFFFFFFFF,
                    "source": "patched_state_zip_central_directory",
                })
            damaged = False
            checksum_error = False
            message = "Archive-state ZIP manifest loaded"
            if not encrypted:
                bad_name = archive.testzip()
                if bad_name:
                    damaged = True
                    checksum_error = True
                    message = f"Patched archive state ZIP payload CRC failed at: {bad_name}"
            return ArchiveStateManifest(
                status=STATUS_DAMAGED if damaged else STATUS_OK,
                is_archive=True,
                damaged=damaged,
                checksum_error=checksum_error,
                item_count=len(infos),
                file_count=len(files),
                files=files,
                message=message,
                archive_type="zip",
                patch_digest=patch_digest,
            )
    except zipfile.BadZipFile as exc:
        return ArchiveStateManifest(
            status=STATUS_DAMAGED,
            is_archive=True,
            damaged=True,
            checksum_error=False,
            item_count=0,
            file_count=0,
            message=f"Patched archive state is not a readable ZIP: {exc}",
            archive_type="zip",
            patch_digest=patch_digest,
        )
    except RuntimeError as exc:
        return ArchiveStateManifest(
            status=STATUS_DAMAGED,
            is_archive=True,
            damaged=True,
            checksum_error=True,
            item_count=0,
            file_count=0,
            message=f"Patched archive state ZIP metadata could not be read: {exc}",
            archive_type="zip",
            patch_digest=patch_digest,
        )


def _looks_like_zip(data: bytes, state: ArchiveState) -> bool:
    if _format_hint(state) == "zip":
        return True
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or b"PK\x05\x06" in data[-66000:]:
        return True
    return Path(state.source.entry_path).suffix.lower() == ".zip"


def _format_hint(state: ArchiveState) -> str:
    return str(state.format_hint or state.source.format_hint or "").strip().lower().lstrip(".")
