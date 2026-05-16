from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules._common import cached_repair_operation, cache_relevant_module_limits, module_limits
from sunpack_native import zip_rebuild_from_local_headers as _native_zip_rebuild_from_local_headers

try:  # Optional while older editable native builds are still in use.
    from sunpack_native import zip_scan_source as _native_zip_scan_source
except ImportError:  # pragma: no cover - depends on installed native extension version.
    _native_zip_scan_source = None


CD_SIG = b"PK\x01\x02"
EOCD_SIG = b"PK\x05\x06"
ZIP64_EOCD_SIG = b"PK\x06\x06"
ZIP64_LOCATOR_SIG = b"PK\x06\x07"


@dataclass(frozen=True)
class ZipScanResult:
    entries: int
    warnings: list[str]
    skipped_offsets: list[int]
    descriptor_entries: int = 0
    encrypted_entries: int = 0
    verified_entries: int = 0
    timed_out: bool = False
    status: str = ""
    message: str = ""
    native_target: str = ""
    candidate_status: str = ""
    patch_facts: list[str] | None = None
    residual_facts: list[str] | None = None
    validation_details: dict[str, Any] | None = None
    patch_plan: dict[str, Any] | None = None
    native_timing: dict[str, Any] | None = None
    logical_stream_built: bool = False
    split_sidecars_available: bool = False

    @property
    def complete(self) -> bool:
        # Encrypted entries are structurally complete — their payload can't be
        # verified without a password but the archive structure is intact.
        return not self.skipped_offsets and not self.timed_out


def rebuild_zip_from_source(
    source_input: dict[str, Any],
    output_path: Path,
    *,
    require_data_descriptor: bool = False,
    preserve_raw_names: bool = False,
    config: dict[str, Any] | None = None,
    cache_job: RepairJob | None = None,
) -> ZipScanResult:
    limits = module_limits(config)
    # CD suffix rebuilds only need a structural local-header scan. Payload
    # extraction/verification runs later on the selected patched state, so doing
    # CRC/deflate work for every competing CD candidate is duplicated cost.
    verify_scan = bool(limits.get("verify_candidates", True))
    if not require_data_descriptor:
        verify_scan = bool(limits.get("verify_cd_rebuild_payloads", False))
    params = {
        "source_input": source_input,
        "output_path": str(output_path),
        "require_data_descriptor": bool(require_data_descriptor),
        "preserve_raw_names": bool(preserve_raw_names),
        "verify_scan": bool(verify_scan),
        "limits": cache_relevant_module_limits(config),
    }

    def compute() -> dict[str, Any]:
        return dict(_native_zip_rebuild_from_local_headers(
            source_input,
            str(output_path),
            bool(require_data_descriptor),
            bool(preserve_raw_names),
            int(limits.get("max_entries", 20000) or 20000),
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_output_size_mb", 2048) or 0),
            bool(verify_scan),
        ))

    result = dict(cached_repair_operation(cache_job, "native_zip_rebuild_from_local_headers", "zip_rebuild_from_local_headers", params, compute) if cache_job is not None else compute())
    skipped = int(result.get("skipped_entries", 0) or 0)
    return ZipScanResult(
        entries=int(result.get("recovered_entries", 0) or 0),
        warnings=[str(item) for item in result.get("warnings") or []],
        skipped_offsets=list(range(skipped)),
        descriptor_entries=int(result.get("descriptor_entries", 0) or 0),
        encrypted_entries=int(result.get("encrypted_entries", 0) or 0),
        verified_entries=int(result.get("verified_entries", 0) or 0),
        timed_out=bool(result.get("timed_out", False)),
        status=str(result.get("status") or ""),
        message=str(result.get("message") or ""),
        native_target=str(result.get("native_target") or ""),
        candidate_status=str(result.get("candidate_status") or ""),
        patch_facts=[str(item) for item in result.get("patch_facts") or []],
        residual_facts=[str(item) for item in result.get("residual_facts") or []],
        validation_details=dict(result.get("validation_details") or {}),
        patch_plan=dict(result.get("patch_plan") or {}) if isinstance(result.get("patch_plan"), dict) else None,
        native_timing=dict(result.get("native_timing") or {}) if isinstance(result.get("native_timing"), dict) else None,
        logical_stream_built=bool(result.get("logical_stream_built")),
        split_sidecars_available=bool(result.get("split_sidecars_available")),
    )


def cached_zip_scan_artifact(source_input: dict[str, Any], *, config: dict[str, Any] | None = None, cache_job: RepairJob | None = None) -> dict[str, Any]:
    if _native_zip_scan_source is None:
        return {"status": "unavailable", "native_target": "zip_scan_source", "zip_scan_artifact_miss_reason": "native_api_unavailable"}
    limits = module_limits(config)
    params = {
        "source_input": source_input,
        "limits": cache_relevant_module_limits(config, ("max_seconds_per_module",)),
    }

    def compute() -> dict[str, Any]:
        return dict(_native_zip_scan_source(
            source_input,
            int(limits.get("max_entries", 20000) or 20000),
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_entry_uncompressed_mb", 512) or 0),
            float(limits.get("max_seconds_per_module", 30.0) or 0),
            bool(limits.get("verify_candidates", True)),
        ))

    if cache_job is None:
        return compute()
    return dict(cached_repair_operation(cache_job, "zip_scan_artifact", "zip_scan_source", params, compute))
