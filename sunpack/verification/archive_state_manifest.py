from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.support.archive_state_view import UnsupportedArchivePatch
from sunpack.support.sevenzip_native import STATUS_DAMAGED, STATUS_OK, STATUS_UNSUPPORTED
from sunpack_native import archive_state_zip_manifest_native as _native_archive_state_zip_manifest


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
    manifest = archive_state_manifest(evidence.archive_state, max_items=max_items, password=evidence.password)
    object.__setattr__(evidence, cache_key, manifest)
    return manifest


def archive_state_manifest(state: ArchiveState, *, max_items: int = 200000, password: str | None = None) -> ArchiveStateManifest:
    patch_digest = state.effective_patch_digest()
    hint = _format_hint(state)
    if hint and hint != "zip" and not Path(state.source.entry_path).suffix.lower() == ".zip":
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

    try:
        payload = dict(_native_archive_state_zip_manifest(
            state.source.to_dict(),
            [patch.to_dict() for patch in state.patches],
            max_items,
            password,
        ))
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
    if not bool(payload.get("is_archive")) and not hint:
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
    return ArchiveStateManifest(
        status=int(payload["status"]) if payload.get("status") is not None else STATUS_DAMAGED,
        is_archive=bool(payload.get("is_archive", False)),
        damaged=bool(payload.get("damaged", False)),
        checksum_error=bool(payload.get("checksum_error", False)),
        item_count=int(payload.get("item_count", 0) or 0),
        file_count=int(payload.get("file_count", 0) or 0),
        files=[dict(item) for item in payload.get("files") or [] if isinstance(item, dict)],
        message=str(payload.get("message") or ""),
        archive_type=str(payload.get("archive_type") or "zip"),
        source=str(payload.get("source") or "archive_state_native"),
        state_aware=bool(payload.get("state_aware", True)),
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
