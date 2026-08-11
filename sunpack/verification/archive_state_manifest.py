from __future__ import annotations

from dataclasses import dataclass, field
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from sunpack.contracts.archive_state import ArchiveState
from sunpack.support.archive_state_view import ArchiveStateByteView, UnsupportedArchivePatch
from sunpack.support.sevenzip_bridge import STATUS_DAMAGED, STATUS_OK, STATUS_UNSUPPORTED
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
    archive_walk_complete: bool = False
    verified_item_count: int = 0
    entries_truncated: bool = False
    failure_kind: str = ""

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.is_archive and not self.damaged and not self.checksum_error

    @property
    def expected_names(self) -> list[str]:
        return [
            str(item.get("path") or "")
            for item in self.files
            if item.get("path") and not bool(item.get("shadowed"))
        ]

    @property
    def total_unpacked_size(self) -> int:
        return sum(
            max(0, int(item.get("size", 0) or 0))
            for item in self.files
            if not bool(item.get("shadowed"))
        )

    @property
    def retained_file_count(self) -> int:
        return sum(1 for item in self.files if not bool(item.get("shadowed")))


_EVIDENCE_CACHE_ATTRIBUTE = "_archive_state_manifest_full_cache"
_EVIDENCE_LIMIT_ATTRIBUTE = "_archive_state_manifest_full_max_items"


def configure_archive_state_manifest_cache(evidence, *, max_items: int) -> None:
    """Declare the largest manifest view needed during this verification run."""
    requested = max(0, int(max_items or 0))
    current = max(0, int(getattr(evidence, _EVIDENCE_LIMIT_ATTRIBUTE, 0) or 0))
    object.__setattr__(evidence, _EVIDENCE_LIMIT_ATTRIBUTE, max(current, requested))


def archive_state_manifest_for_evidence(evidence, *, max_items: int = 200000) -> ArchiveStateManifest:
    requested = max(0, int(max_items or 0))
    codepage = str(evidence.selected_codepage or "")
    identity = _evidence_manifest_identity(evidence, codepage)
    configured_limit = max(0, int(getattr(evidence, _EVIDENCE_LIMIT_ATTRIBUTE, 0) or 0))
    full_limit = max(requested, configured_limit)
    cached = getattr(evidence, _EVIDENCE_CACHE_ATTRIBUTE, None)
    if not (
        isinstance(cached, dict)
        and cached.get("identity") == identity
        and isinstance(cached.get("manifest"), ArchiveStateManifest)
        and int(cached.get("max_items", -1)) >= full_limit
    ):
        hint = _format_hint(evidence.archive_state)
        # TAR needs a source-side walk.  A worker manifest only proves that the
        # range it was handed extracted successfully; it cannot prove that an
        # incorrectly planned suffix range covered the source archive.
        full_manifest = None if hint == "tar" else _worker_verified_manifest(evidence)
        if full_manifest is None:
            full_manifest = archive_state_manifest(
                evidence.archive_state,
                max_items=full_limit,
                password=evidence.password,
                codepage=codepage or None,
            )
        cached = {
            "identity": identity,
            "max_items": full_limit,
            "manifest": full_manifest,
        }
        object.__setattr__(evidence, _EVIDENCE_CACHE_ATTRIBUTE, cached)
    return _manifest_view(cached["manifest"], requested)


def _worker_verified_manifest(evidence) -> ArchiveStateManifest | None:
    result = evidence.worker_result if isinstance(evidence.worker_result, dict) else {}
    payload = result.get("verified_manifest") if isinstance(result.get("verified_manifest"), dict) else {}
    from sunpack.support.output_inventory import OutputInventory
    inventory = OutputInventory.from_value(
        getattr(evidence.extraction_result, "output_inventory", None),
        expected_root=evidence.output_dir,
    )
    files = list(inventory.materialize_files()) if inventory is not None and inventory.worker_inventory_complete else []
    if (
        result.get("status") != "ok"
        or not payload.get("validated")
        or int(payload.get("file_count", -1) or 0) != len(files)
        or any(str(item.get("status") or "") != "complete" for item in files)
    ):
        return None
    return ArchiveStateManifest(
        status=STATUS_OK,
        is_archive=True,
        damaged=False,
        checksum_error=False,
        item_count=int(payload.get("item_count", len(files)) or 0),
        file_count=len(files),
        files=files,
        message="Archive payload was verified during extraction",
        archive_type=str(result.get("archive_type") or ""),
        source=str(payload.get("source") or "sevenzip_worker_extract"),
        state_aware=True,
        patch_digest=evidence.patch_digest,
        archive_walk_complete=True,
        verified_item_count=int(payload.get("item_count", len(files)) or 0),
        entries_truncated=False,
    )


def _evidence_manifest_identity(evidence, codepage: str) -> tuple:
    state = evidence.archive_state
    source = state.source
    return (
        repr(source.to_dict()),
        state.effective_patch_digest(),
        str(evidence.password or ""),
        codepage,
    )


def _manifest_view(manifest: ArchiveStateManifest, max_items: int) -> ArchiveStateManifest:
    limit = max(0, int(max_items or 0))
    if len(manifest.files) <= limit:
        return manifest
    files = manifest.files[:limit]
    return replace(manifest, files=files, entries_truncated=True)


def archive_state_manifest(
    state: ArchiveState,
    *,
    max_items: int = 200000,
    password: str | None = None,
    codepage: str | None = None,
) -> ArchiveStateManifest:
    patch_digest = state.effective_patch_digest()
    hint = _format_hint(state)
    if hint == "tar" or (not hint and Path(state.source.entry_path).suffix.lower() == ".tar"):
        return _tar_archive_state_manifest(state, max_items=max_items, patch_digest=patch_digest)
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
            codepage,
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
    files = [dict(item) for item in payload.get("files") or [] if isinstance(item, dict)]
    file_count = int(payload.get("file_count", 0) or 0)
    return ArchiveStateManifest(
        status=int(payload["status"]) if payload.get("status") is not None else STATUS_DAMAGED,
        is_archive=bool(payload.get("is_archive", False)),
        damaged=bool(payload.get("damaged", False)),
        checksum_error=bool(payload.get("checksum_error", False)),
        item_count=int(payload.get("item_count", 0) or 0),
        file_count=file_count,
        files=files,
        message=str(payload.get("message") or ""),
        archive_type=str(payload.get("archive_type") or "zip"),
        source=str(payload.get("source") or "archive_state_native"),
        state_aware=bool(payload.get("state_aware", True)),
        patch_digest=patch_digest,
        archive_walk_complete=(int(payload["status"]) if payload.get("status") is not None else STATUS_DAMAGED) == STATUS_OK,
        verified_item_count=(
            int(payload.get("item_count", 0) or 0)
            if (int(payload["status"]) if payload.get("status") is not None else STATUS_DAMAGED) == STATUS_OK
            else 0
        ),
        entries_truncated=len(files) < file_count,
        failure_kind=str(payload.get("failure_kind") or ""),
    )


def _format_hint(state: ArchiveState) -> str:
    return str(state.format_hint or state.source.format_hint or "").strip().lower().lstrip(".")


def _tar_number(field: bytes) -> int | None:
    if not field:
        return None
    if field[0] & 0x80:
        value = field[0] & 0x7F
        for byte in field[1:]:
            value = value * 256 + byte
        return value
    text = field.rstrip(b"\0 ").lstrip(b" ")
    if not text:
        return 0
    if any(byte not in b"01234567" for byte in text):
        return None
    return int(text, 8)


def _tar_text(field: bytes) -> str:
    return field.split(b"\0", 1)[0].decode("utf-8", errors="surrogateescape")


def _tar_pax(payload: bytes) -> dict[str, str] | None:
    records: dict[str, str] = {}
    cursor = 0
    while cursor < len(payload):
        space = payload.find(b" ", cursor)
        if space <= cursor or not payload[cursor:space].isdigit():
            return None
        length = int(payload[cursor:space])
        end = cursor + length
        if length <= 0 or end > len(payload) or payload[end - 1:end] != b"\n":
            return None
        record = payload[space + 1:end - 1]
        if b"=" not in record:
            return None
        key, value = record.split(b"=", 1)
        try:
            records[key.decode("utf-8")] = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
        cursor = end
    return records


def _tar_sparse_extension_span(data: bytes, header: bytes, header_offset: int) -> tuple[int, int] | None:
    previous_end = 0

    def validate(block: bytes, start: int, count: int) -> bool:
        nonlocal previous_end
        for index in range(count):
            base = start + index * 24
            sparse_offset = _tar_number(block[base:base + 12])
            sparse_length = _tar_number(block[base + 12:base + 24])
            if sparse_offset is None or sparse_length is None:
                return False
            if sparse_offset == 0 and sparse_length == 0:
                continue
            end = sparse_offset + sparse_length
            if end < sparse_offset or sparse_offset < previous_end:
                return False
            previous_end = end
        return True

    if not validate(header, 386, 4):
        return None
    span = 0
    extended = header[482] not in (0, ord("0"))
    while extended:
        if span >= 512 * 65536:
            return None
        start = header_offset + 512 + span
        block = data[start:start + 512]
        if len(block) != 512 or not validate(block, 0, 21):
            return None
        span += 512
        extended = block[504] not in (0, ord("0"))
    return span, previous_end


def _tar_sparse_map(value: str) -> list[tuple[int, int]] | None:
    fields = value.split(",")
    if not fields or len(fields) % 2:
        return None
    extents: list[tuple[int, int]] = []
    previous_end = 0
    for index in range(0, len(fields), 2):
        try:
            offset = int(fields[index])
            length = int(fields[index + 1])
        except ValueError:
            return None
        if offset < 0 or length < 0:
            return None
        end = offset + length
        if end < offset or offset < previous_end:
            return None
        extents.append((offset, length))
        previous_end = end
    return extents


def _tar_archive_state_manifest(
    state: ArchiveState,
    *,
    max_items: int,
    patch_digest: str,
) -> ArchiveStateManifest:
    try:
        data = ArchiveStateByteView(state).to_bytes()
    except (OSError, ValueError, UnsupportedArchivePatch) as exc:
        return ArchiveStateManifest(
            status=STATUS_UNSUPPORTED, is_archive=False, damaged=False, checksum_error=False,
            item_count=0, file_count=0, message=f"TAR state could not be read: {exc}",
            archive_type="tar", patch_digest=patch_digest,
        )

    offset = 0
    item_count = 0
    zero_blocks = 0
    files: list[dict[str, Any]] = []
    global_pax: dict[str, str] = {}
    next_pax: dict[str, str] = {}
    long_name: str | None = None
    long_link: str | None = None
    error = ""
    checksum_error = False
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if not any(header):
            zero_blocks += 1
            offset += 512
            if zero_blocks >= 2:
                break
            continue
        zero_blocks = 0
        stored = _tar_number(header[148:156])
        raw_size = _tar_number(header[124:136])
        checksum = sum(header[:148]) + 32 * 8 + sum(header[156:])
        if stored is None or raw_size is None or stored != checksum:
            checksum_error = stored is not None and stored != checksum
            error = "invalid TAR member header"
            break
        sparse_extension_span = 0
        oldgnu_sparse_extent_end = 0
        if header[156] == ord("S"):
            parsed_sparse = _tar_sparse_extension_span(data, header, offset)
            if parsed_sparse is None:
                error = "invalid old GNU sparse extension map"
                break
            sparse_extension_span, oldgnu_sparse_extent_end = parsed_sparse
        raw_end = offset + 512 + sparse_extension_span + raw_size
        raw_next = raw_end + (-raw_size % 512)
        typeflag = header[156]
        raw_payload_truncated = raw_next > len(data)
        payload_start = offset + 512 + sparse_extension_span
        payload = data[payload_start:min(raw_end, len(data))]
        if typeflag in (ord("x"), ord("g")):
            if raw_payload_truncated:
                error = "TAR metadata member payload is truncated"
                break
            parsed = _tar_pax(payload)
            if parsed is None:
                error = "invalid PAX extended header"
                break
            if typeflag == ord("g"):
                for key, value in parsed.items():
                    if value == "":
                        global_pax.pop(key, None)
                    else:
                        global_pax[key] = value
            else:
                next_pax = parsed
            item_count += 1
            offset = raw_next
            continue
        if typeflag == ord("L"):
            if raw_payload_truncated:
                error = "GNU longname payload is truncated"
                break
            long_name = _tar_text(payload)
            item_count += 1
            offset = raw_next
            continue
        if typeflag == ord("K"):
            if raw_payload_truncated:
                error = "GNU longlink payload is truncated"
                break
            long_link = _tar_text(payload)
            item_count += 1
            offset = raw_next
            continue

        effective = dict(global_pax)
        for key, value in next_pax.items():
            if value == "":
                effective.pop(key, None)
            else:
                effective[key] = value
        physical_size = raw_size
        if "size" in effective and not any(key.startswith("GNU.sparse.") for key in effective):
            try:
                physical_size = max(0, int(effective["size"]))
            except ValueError:
                error = "invalid TAR extended size: size"
        member_next = offset + 512 + sparse_extension_span + physical_size + (-physical_size % 512)
        member_payload_truncated = member_next > len(data)
        if member_payload_truncated:
            error = "TAR extended member payload is truncated"
        prefix = _tar_text(header[345:500])
        raw_name = _tar_text(header[0:100])
        path = long_name or effective.get("path") or (f"{prefix}/{raw_name}" if prefix else raw_name)
        linkpath = long_link or effective.get("linkpath") or _tar_text(header[157:257])
        logical_size = raw_size
        for key in ("GNU.sparse.realsize", "GNU.sparse.size", "size"):
            if key in effective:
                try:
                    logical_size = max(0, int(effective[key]))
                except ValueError:
                    error = f"invalid TAR extended size: {key}"
                break
        if typeflag == ord("S"):
            oldgnu_size = _tar_number(header[483:495])
            if oldgnu_size is not None:
                logical_size = oldgnu_size
            if oldgnu_sparse_extent_end > logical_size:
                error = "old GNU sparse extent exceeds logical size"
        sparse_map = _tar_sparse_map(effective["GNU.sparse.map"]) if "GNU.sparse.map" in effective else []
        if sparse_map is None or any(offset + length > logical_size for offset, length in sparse_map):
            error = "invalid GNU sparse extent map"
        item_count += 1
        if typeflag not in (ord("5"), ord("3"), ord("4"), ord("6")) and path:
            files.append({
                "ordinal": item_count - 1,
                "path": path,
                "raw_path": path,
                "size": logical_size if typeflag not in (ord("1"), ord("2")) else 0,
                "typeflag": chr(typeflag) if typeflag else "0",
                "linkpath": linkpath,
                "has_crc": False,
            })
        next_pax = {}
        long_name = None
        long_link = None
        offset = member_next
        if error or raw_payload_truncated or member_payload_truncated:
            if not error:
                error = "TAR member payload is truncated"
            break

    if not error and offset < len(data) and zero_blocks < 2 and any(data[offset:]):
        error = "TAR ends with a partial header or non-zero trailing data"

    # The worker deliberately preserves duplicate archive members using its
    # browser-style name allocator.  Project the same deterministic names so
    # verification retains every member ordinal instead of folding by path.
    used_paths: set[str] = set()
    for item in files:
        archive_path = str(item["path"])
        projected = archive_path
        candidate = PurePosixPath(archive_path)
        suffix = candidate.suffix
        stem = candidate.name[:-len(suffix)] if suffix else candidate.name
        index = 1
        while projected.replace("\\", "/").casefold() in used_paths:
            name = f"{stem}({index}){suffix}"
            projected = str(candidate.with_name(name)).replace("\\", "/")
            index += 1
        used_paths.add(projected.replace("\\", "/").casefold())
        item["archive_path"] = archive_path
        item["path"] = projected

    retained = files[:max(0, max_items)]
    damaged = bool(error)
    return ArchiveStateManifest(
        status=STATUS_DAMAGED if damaged else STATUS_OK,
        is_archive=item_count > 0,
        damaged=damaged,
        checksum_error=checksum_error,
        item_count=item_count,
        file_count=len(files),
        files=retained,
        message=error or ("TAR source manifest walked to canonical end" if zero_blocks >= 2 else "TAR source manifest walked to EOF"),
        archive_type="tar",
        source="archive_state_tar",
        patch_digest=patch_digest,
        archive_walk_complete=not damaged,
        verified_item_count=item_count if not damaged else 0,
        entries_truncated=len(retained) < len(files),
        failure_kind="corrupted_data" if damaged else "",
    )
