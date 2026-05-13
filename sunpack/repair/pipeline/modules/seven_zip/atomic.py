from __future__ import annotations

import hashlib
import json
from typing import Any

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import cached_repair_operation, cache_relevant_module_limits, module_limits, source_input_for_job
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult

from ._scan import cached_seven_zip_scan_artifact, password_fingerprint

try:
    from sunpack_native import seven_zip_atomic_repair as _native_seven_zip_atomic_repair
except Exception:  # pragma: no cover - native extension may be unavailable during static tooling
    _native_seven_zip_atomic_repair = None


WRONG_PASSWORD_FLAGS = ("wrong_password", "encrypted_header")
CARRIER_FLAGS = ("carrier_archive", "carrier_prefix", "sfx", "embedded_archive")
CONTENT_FLAGS = ("packed_stream_bad", "payload_crc_bad", "crc_error", "checksum_error", "data_error", "damaged")


class _SevenZipAtomicRepair:
    module_name = ""
    repair_name = ""
    native_target = ""
    route_family = ""
    require_flags: tuple[str, ...] = ()
    reject_flags: tuple[str, ...] = WRONG_PASSWORD_FLAGS
    categories: tuple[str, ...] = ("safe_repair",)
    base_score = 0.8
    confidence = 0.86
    partial = False
    format_hint = "7z"

    @property
    def spec(self) -> RepairModuleSpec:
        route_reject_flags = tuple(flag for flag in self.reject_flags if flag not in WRONG_PASSWORD_FLAGS)
        return RepairModuleSpec(
            name=self.module_name,
            formats=("7z", "seven_zip"),
            categories=self.categories,
            safe=True,
            partial=self.partial,
            atomic=True,
            route_family=self.route_family or self.native_target or self.module_name,
            routes=(
                RepairRoute(
                    formats=("7z", "seven_zip"),
                    require_any_flags=self.require_flags,
                    reject_any_flags=route_reject_flags,
                    require_any_failure_kinds=("structure_recognition", "corrupted_data", "checksum_error", "data_error"),
                    base_score=self.base_score,
                ),
            ),
        )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = _job_flags(job, config)
        reject_flags = set(self.reject_flags)
        if _has_resolved_password(job):
            reject_flags.difference_update(WRONG_PASSWORD_FLAGS)
        elif flags & set(WRONG_PASSWORD_FLAGS) and not _seven_zip_password_blocking(job, config):
            reject_flags.difference_update(WRONG_PASSWORD_FLAGS)
            flags.difference_update(WRONG_PASSWORD_FLAGS)
        if flags & reject_flags:
            return 0.0
        if (flags & set(WRONG_PASSWORD_FLAGS)) and not _has_resolved_password(job):
            return 0.0
        if not flags & set(self.require_flags):
            return 0.0
        return self.confidence

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidates = self.generate_candidates(job, diagnosis, workspace, config)
        if candidates:
            return candidates[0].to_result(selection={"selected_module": self.module_name})
        result = self._run_native(job, workspace, config)
        return RepairResult(
            status="unrepairable",
            confidence=float(result.get("confidence") or 0.0),
            format=self.format_hint,
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=self.partial,
            module_name=self.module_name,
            diagnosis={
                **diagnosis.as_dict(),
                "repair_name": self.repair_name,
                "atomic_action_group": self.module_name,
                "native_key": "native_7z_atomic_repair",
                "native_target": str(result.get("native_target") or self.native_target),
                "candidate_status": str(result.get("candidate_status") or ""),
                "patch_facts": [str(item) for item in result.get("patch_facts") or [] if str(item)],
                "residual_facts": [str(item) for item in result.get("residual_facts") or [] if str(item)],
                "validation_details": dict(result.get("validation_details") or {}),
                "native_7z_atomic_repair": result,
            },
            message=str(result.get("message") or "7z atomic repair did not produce a candidate"),
        )

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        if str(result.get("native_target") or "") not in {"", self.native_target}:
            result["native_target_mismatch"] = True
            result["expected_native_target"] = self.native_target
        return candidates_from_native_result(
            self.module_name,
            result,
            job,
            diagnosis,
            native_key="native_7z_atomic_repair",
            format_hint=self.format_hint,
            partial_default=self.partial,
            default_confidence=self.confidence,
            default_message=f"{self.module_name} produced a candidate",
            repair_name=self.repair_name,
            atomic_action_group=self.module_name,
        )

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict[str, Any]:
        scan = cached_seven_zip_scan_artifact(job, config)
        if _native_seven_zip_atomic_repair is None:
            result = {
                "status": "unavailable",
                "native_key": "native_7z_atomic_repair",
                "native_target": self.native_target,
                "candidate_status": "no_candidate",
                "message": "native seven_zip_atomic_repair API is unavailable",
                "scan_artifact": _compact_scan(scan),
            }
            _record_native_attempt(job, self.module_name, self.native_target, result, scan)
            return result
        limits = module_limits(config)
        params = {
            "target": self.native_target,
            "limits": cache_relevant_module_limits(
                config,
                ("max_input_size_mb", "max_next_header_scan_bytes", "max_output_size_mb", "max_entries", "max_candidates_per_module"),
            ),
            "password_present": bool(getattr(job, "password", None)),
            "password_fingerprint": password_fingerprint(getattr(job, "password", None)),
        }

        def compute() -> dict[str, Any]:
            return dict(_native_seven_zip_atomic_repair(
                source_input_for_job(job),
                workspace,
                self.native_target,
                float(limits.get("max_input_size_mb", 512) or 0),
                int(limits.get("max_next_header_scan_bytes", 1024 * 1024) or 1024 * 1024),
                float(limits.get("max_output_size_mb", 2048) or 0),
                int(limits.get("max_entries", 20000) or 20000),
                int(limits.get("max_candidates_per_module", 8) or 1),
            ))

        result = dict(cached_repair_operation(job, "seven_zip_atomic_repair", self.native_target, params, compute))
        result.setdefault("native_key", "native_7z_atomic_repair")
        result.setdefault("native_target", self.native_target)
        result["scan_artifact"] = _compact_scan(scan)
        _record_native_attempt(job, self.module_name, self.native_target, result, scan)
        return result


class SevenZipTrimTrailingJunk(_SevenZipAtomicRepair):
    module_name = "seven_zip_trim_trailing_junk"
    repair_name = "seven_zip_trim_trailing_junk"
    native_target = "trailing_junk"
    route_family = "seven_zip_boundary"
    require_flags = ("trailing_junk", "boundary_unreliable", "trailing_padding")
    reject_flags = (*WRONG_PASSWORD_FLAGS, *CARRIER_FLAGS)
    categories = ("boundary_repair", "safe_repair")
    base_score = 0.82
    confidence = 0.88


class SevenZipCropCarrierPrefix(_SevenZipAtomicRepair):
    module_name = "seven_zip_crop_carrier_prefix"
    repair_name = "seven_zip_crop_carrier_prefix"
    native_target = "carrier_prefix"
    route_family = "seven_zip_boundary"
    require_flags = CARRIER_FLAGS
    categories = ("boundary_repair", "safe_repair")
    base_score = 0.9
    confidence = 0.94


class SevenZipFixStartHeaderCrc(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_start_header_crc"
    repair_name = "seven_zip_fix_start_header_crc"
    native_target = "start_header_crc"
    route_family = "seven_zip_header_crc"
    require_flags = ("start_header_crc_bad",)
    reject_flags = (*WRONG_PASSWORD_FLAGS, "next_header_out_of_range", "encoded_header_unreadable")
    base_score = 0.86
    confidence = 0.91


class SevenZipFixSignatureHeaderVersion(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_signature_header_version"
    repair_name = "seven_zip_fix_signature_header_version"
    native_target = "signature_header_version"
    route_family = "seven_zip_signature_header"
    require_flags = ("signature_header_version_bad",)
    reject_flags = (*WRONG_PASSWORD_FLAGS, *CARRIER_FLAGS)
    base_score = 0.87
    confidence = 0.91


class SevenZipFixNextHeaderCrc(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_next_header_crc"
    repair_name = "seven_zip_fix_next_header_crc"
    native_target = "next_header_crc"
    route_family = "seven_zip_header_crc"
    require_flags = ("next_header_crc_bad",)
    reject_flags = (*WRONG_PASSWORD_FLAGS, "next_header_out_of_range", "encoded_header_unreadable")
    base_score = 0.86
    confidence = 0.91


class SevenZipFixNextHeaderOffset(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_next_header_offset"
    repair_name = "seven_zip_fix_next_header_offset"
    native_target = "next_header_offset"
    route_family = "seven_zip_next_header_fields"
    require_flags = ("next_header_offset_bad",)
    base_score = 0.84
    confidence = 0.9


class SevenZipFixNextHeaderSize(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_next_header_size"
    repair_name = "seven_zip_fix_next_header_size"
    native_target = "next_header_size"
    route_family = "seven_zip_next_header_fields"
    require_flags = ("next_header_size_bad",)
    base_score = 0.84
    confidence = 0.9


class SevenZipRepointNextHeader(_SevenZipAtomicRepair):
    module_name = "seven_zip_repoint_next_header"
    repair_name = "seven_zip_repoint_next_header"
    native_target = "next_header_repoint"
    route_family = "seven_zip_next_header_fields"
    require_flags = ("next_header_out_of_range", "encoded_header_candidate_found")
    base_score = 0.82
    confidence = 0.88


class SevenZipDecodeEncodedHeader(_SevenZipAtomicRepair):
    module_name = "seven_zip_decode_encoded_header"
    repair_name = "seven_zip_decode_encoded_header"
    native_target = "encoded_header_decode"
    route_family = "seven_zip_encoded_header"
    require_flags = ("encoded_header_present", "encoded_header_decodable")
    reject_flags = WRONG_PASSWORD_FLAGS
    base_score = 0.84
    confidence = 0.88


class SevenZipFixPackStreamOffset(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_pack_stream_offset"
    repair_name = "seven_zip_fix_pack_stream_offset"
    native_target = "pack_stream_offset"
    route_family = "seven_zip_pack_stream"
    require_flags = ("pack_stream_offset_bad",)
    base_score = 0.82
    confidence = 0.87


class SevenZipFixPackStreamSize(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_pack_stream_size"
    repair_name = "seven_zip_fix_pack_stream_size"
    native_target = "pack_stream_size"
    route_family = "seven_zip_pack_stream"
    require_flags = ("pack_stream_size_bad",)
    base_score = 0.82
    confidence = 0.87


class SevenZipFixStreamCrc(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_stream_crc"
    repair_name = "seven_zip_fix_stream_crc"
    native_target = "stream_crc"
    route_family = "seven_zip_stream_crc"
    require_flags = ("stream_crc_bad", "substream_crc_bad")
    base_score = 0.83
    confidence = 0.86


class SevenZipQuarantineBadFolder(_SevenZipAtomicRepair):
    module_name = "seven_zip_quarantine_bad_folder"
    repair_name = "seven_zip_quarantine_bad_folder"
    native_target = "bad_folder_quarantine"
    route_family = "seven_zip_folder_quarantine"
    require_flags = ("bad_folder_detected", "verified_folder_available")
    categories = ("content_recovery",)
    base_score = 0.86
    confidence = 0.74
    partial = True
    format_hint = "7z"


class SevenZipFixEmptyStreamFlags(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_empty_stream_flags"
    repair_name = "seven_zip_fix_empty_stream_flags"
    native_target = "empty_stream_flags"
    route_family = "seven_zip_file_table"
    require_flags = ("empty_stream_flags_bad", "empty_file_flags_bad", "anti_item_flags_bad")
    base_score = 0.81
    confidence = 0.84


class SevenZipFixEncodedHeaderStreamCrc(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_encoded_header_stream_crc"
    repair_name = "seven_zip_fix_encoded_header_stream_crc"
    native_target = "encoded_header_stream_crc"
    route_family = "seven_zip_encoded_header"
    require_flags = ("encoded_header_stream_crc_bad", "encoded_header_decodable")
    reject_flags = WRONG_PASSWORD_FLAGS
    base_score = 0.82
    confidence = 0.85


class SevenZipFixUnpackSize(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_unpack_size"
    repair_name = "seven_zip_fix_unpack_size"
    native_target = "unpack_size"
    route_family = "seven_zip_unpack"
    require_flags = ("unpack_size_bad",)
    base_score = 0.8
    confidence = 0.84


class SevenZipRepairFolderBindPairs(_SevenZipAtomicRepair):
    module_name = "seven_zip_repair_folder_bind_pairs"
    repair_name = "seven_zip_repair_folder_bind_pairs"
    native_target = "folder_bind_pairs"
    route_family = "seven_zip_folder_graph"
    require_flags = ("folder_bind_pairs_bad",)
    base_score = 0.8
    confidence = 0.83


class SevenZipRepairFolderStreamCounts(_SevenZipAtomicRepair):
    module_name = "seven_zip_repair_folder_stream_counts"
    repair_name = "seven_zip_repair_folder_stream_counts"
    native_target = "folder_stream_counts"
    route_family = "seven_zip_folder_graph"
    require_flags = ("folder_stream_counts_bad",)
    base_score = 0.8
    confidence = 0.83


class SevenZipFixFileCountMetadata(_SevenZipAtomicRepair):
    module_name = "seven_zip_fix_file_count_metadata"
    repair_name = "seven_zip_fix_file_count_metadata"
    native_target = "file_count_metadata"
    route_family = "seven_zip_file_table"
    require_flags = ("file_count_metadata_bad",)
    base_score = 0.8
    confidence = 0.83


class SevenZipReconcileFileNamesUtf16(_SevenZipAtomicRepair):
    module_name = "seven_zip_reconcile_file_names_utf16"
    repair_name = "seven_zip_reconcile_file_names_utf16"
    native_target = "file_names_utf16"
    route_family = "seven_zip_file_table"
    require_flags = ("file_names_utf16_bad", "names_utf16_bad", "file_name_metadata_bad")
    base_score = 0.8
    confidence = 0.83


class SevenZipDropUnreferencedFolder(_SevenZipAtomicRepair):
    module_name = "seven_zip_drop_unreferenced_folder"
    repair_name = "seven_zip_drop_unreferenced_folder"
    native_target = "unreferenced_folder"
    route_family = "seven_zip_folder_graph"
    require_flags = ("unreferenced_folder", "unreferenced_folder_record")
    base_score = 0.79
    confidence = 0.82


class SevenZipDropUnreferencedFileRecord(_SevenZipAtomicRepair):
    module_name = "seven_zip_drop_unreferenced_file_record"
    repair_name = "seven_zip_drop_unreferenced_file_record"
    native_target = "unreferenced_file_record"
    route_family = "seven_zip_file_table"
    require_flags = ("unreferenced_file_record", "file_record_unreferenced")
    base_score = 0.79
    confidence = 0.82


class SevenZipClearInvalidStreamCrcDefinedFlag(_SevenZipAtomicRepair):
    module_name = "seven_zip_clear_invalid_stream_crc_defined_flag"
    repair_name = "seven_zip_clear_invalid_stream_crc_defined_flag"
    native_target = "stream_crc_defined_flag"
    route_family = "seven_zip_stream_crc"
    require_flags = ("invalid_stream_crc_defined_flag", "stream_crc_defined_flag_bad")
    base_score = 0.8
    confidence = 0.83


class SevenZipSalvageNonSolidEntries(_SevenZipAtomicRepair):
    module_name = "seven_zip_salvage_non_solid_entries"
    repair_name = "seven_zip_salvage_non_solid_entries"
    native_target = "non_solid_entries"
    route_family = "seven_zip_partial_salvage"
    require_flags = ("non_solid_archive", "packed_stream_bad", "payload_crc_bad", "crc_error", "checksum_error", "data_error", "partial_recovery_possible")
    reject_flags = (*WRONG_PASSWORD_FLAGS, "solid_archive")
    categories = ("content_recovery",)
    base_score = 0.88
    confidence = 0.76
    partial = True
    format_hint = "7z"


class SevenZipSalvageSolidPrefix(_SevenZipAtomicRepair):
    module_name = "seven_zip_salvage_solid_prefix"
    repair_name = "seven_zip_salvage_solid_prefix"
    native_target = "solid_prefix"
    route_family = "seven_zip_partial_salvage"
    require_flags = ("solid_archive", "packed_stream_bad", "payload_crc_bad", "crc_error", "checksum_error", "data_error", "partial_recovery_possible")
    reject_flags = WRONG_PASSWORD_FLAGS
    categories = ("content_recovery",)
    base_score = 0.86
    confidence = 0.72
    partial = True
    format_hint = "7z"


def _job_flags(job: RepairJob, config: dict[str, Any]) -> set[str]:
    flags = {str(item) for item in job.damage_flags if str(item)}
    knowledge = getattr(job, "knowledge", {})
    if not isinstance(knowledge, dict):
        knowledge = {}
    for path in (
        "format.7z.route_evidence_flags",
        "format.7z.route_evidence.flags",
        "repair.route_evidence.flags",
        "repair.damage.flags",
        "verification.residual.flags",
        "repair.residual.flags",
    ):
        values = _get_path(knowledge, path, [])
        if isinstance(values, list):
            flags.update(str(item) for item in values if str(item))
    scan = cached_seven_zip_scan_artifact(job, config)
    flags.update(str(item) for item in scan.get("route_evidence_flags") or [] if str(item))
    return flags


def _record_native_attempt(job: RepairJob, module_name: str, target: str, result: dict[str, Any], scan: dict[str, Any]) -> None:
    if not isinstance(getattr(job, "knowledge", None), dict):
        return
    payload = {
        "module_name": module_name,
        "native_target": str(result.get("native_target") or target),
        "status": str(result.get("status") or ""),
        "candidate_status": str(result.get("candidate_status") or ""),
        "message": str(result.get("message") or ""),
        "patch_facts": [str(item) for item in result.get("patch_facts") or [] if str(item)],
        "residual_facts": [str(item) for item in result.get("residual_facts") or [] if str(item)],
        "validation_details": dict(result.get("validation_details") or {}),
        "scan_artifact": _compact_scan(scan),
        "native_target_mismatch": bool(result.get("native_target_mismatch")),
        "expected_native_target": str(result.get("expected_native_target") or target),
        "password_present": bool(getattr(job, "password", None)),
    }
    payload["_attempt_digest"] = _stable_digest(payload)
    attempts = list(_get_path(job.knowledge, "repair.native_attempts", []) or [])
    if any(isinstance(item, dict) and item.get("_attempt_digest") == payload["_attempt_digest"] for item in attempts):
        return
    attempts.append(payload)
    _set_path(job.knowledge, "repair.native_attempts", attempts[-100:])
    facts = payload["patch_facts"]
    if facts:
        _add_flags(job.knowledge, "repair.patch_facts", facts)
    if {"output_container=7z", "partial=true"}.issubset(set(facts)):
        structure = dict(_get_path(job.knowledge, "format.7z.structure", {}) or {})
        structure["partial_salvage_container"] = True
        recovered_entry_count = result.get("recovered_entry_count")
        if isinstance(recovered_entry_count, int):
            structure["recovered_entry_count"] = recovered_entry_count
        _set_path(job.knowledge, "format.7z.structure", structure)
    residual = payload["residual_facts"]
    if residual:
        _add_flags(job.knowledge, "repair.residual", residual)


def _compact_scan(scan: dict[str, Any]) -> dict[str, Any]:
    structure = scan.get("structure") if isinstance(scan.get("structure"), dict) else {}
    return {
        "status": str(scan.get("status") or ""),
        "native_target": str(scan.get("native_target") or ""),
        "password_present": bool(scan.get("password_present")),
        "route_evidence_flags": [str(item) for item in scan.get("route_evidence_flags") or [] if str(item)],
        "container_tags": [str(item) for item in scan.get("container_tags") or [] if str(item)],
        "structure": {
            key: structure.get(key)
            for key in (
                "signature_offset",
                "password_present",
                "password_required",
                "password_rejected",
                "archive_readable_with_password",
                "encrypted_header",
                "archive_end",
                "trailing_bytes",
                "start_crc_ok",
                "next_header_crc_ok",
                "next_header_nid",
                "next_header_out_of_range",
                "signature_header_version_bad",
                "encoded_header_present",
                "encoded_header_candidate_found",
                "encoded_header_candidate_offset",
                "encoded_header_candidate_size",
                "encoded_header_decodable",
                "encoded_header_stream_crc_bad",
                "pack_stream_offset_bad",
                "pack_stream_size_bad",
                "unpack_size_bad",
                "stream_crc_bad",
                "substream_crc_bad",
                "empty_stream_flags_bad",
                "empty_file_flags_bad",
                "anti_item_flags_bad",
                "folder_bind_pairs_bad",
                "folder_stream_counts_bad",
                "file_count_metadata_bad",
                "file_names_utf16_bad",
                "names_utf16_bad",
                "file_name_metadata_bad",
                "unreferenced_folder",
                "unreferenced_folder_record",
                "unreferenced_file_record",
                "file_record_unreferenced",
                "invalid_stream_crc_defined_flag",
                "stream_crc_defined_flag_bad",
                "bad_folder_detected",
                "verified_folder_available",
            )
            if key in structure
        },
    }


def _has_resolved_password(job: RepairJob) -> bool:
    return bool(getattr(job, "password", None))


def _seven_zip_password_blocking(job: RepairJob, config: dict[str, Any]) -> bool:
    scan = cached_seven_zip_scan_artifact(job, config)
    structure = scan.get("structure") if isinstance(scan.get("structure"), dict) else {}
    if bool(scan.get("password_present")) or _has_resolved_password(job):
        return False
    return bool(
        structure.get("password_required")
        or structure.get("password_rejected")
        or structure.get("encrypted_header")
        or scan.get("password_required")
        or scan.get("password_rejected")
    )


def _get_path(payload: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = payload
    for part in [part for part in str(path or "").split(".") if part]:
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _set_path(payload: dict[str, Any], path: str, value: Any) -> None:
    current = payload
    parts = [part for part in str(path or "").split(".") if part]
    for part in parts[:-1]:
        item = current.setdefault(part, {})
        if not isinstance(item, dict):
            item = {}
            current[part] = item
        current = item
    if parts:
        current[parts[-1]] = _jsonable(value)


def _add_flags(payload: dict[str, Any], namespace: str, flags: list[str]) -> None:
    path = f"{namespace}.flags" if namespace else "flags"
    existing = [str(item) for item in _get_path(payload, path, []) or [] if str(item)]
    merged: list[str] = []
    seen: set[str] = set()
    for item in [*existing, *[str(flag) for flag in flags if str(flag)]]:
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    _set_path(payload, path, merged)


def _stable_digest(payload: Any) -> str:
    data = json.dumps(_jsonable(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "to_dict"):
        try:
            return _jsonable(value.to_dict())
        except Exception:
            return str(value)
    return str(value)


for _module in (
    SevenZipTrimTrailingJunk(),
    SevenZipCropCarrierPrefix(),
    SevenZipFixStartHeaderCrc(),
    SevenZipFixSignatureHeaderVersion(),
    SevenZipFixNextHeaderCrc(),
    SevenZipFixNextHeaderOffset(),
    SevenZipFixNextHeaderSize(),
    SevenZipRepointNextHeader(),
    SevenZipDecodeEncodedHeader(),
    SevenZipFixPackStreamOffset(),
    SevenZipFixPackStreamSize(),
    SevenZipFixStreamCrc(),
    SevenZipQuarantineBadFolder(),
    SevenZipFixEmptyStreamFlags(),
    SevenZipFixEncodedHeaderStreamCrc(),
    SevenZipFixUnpackSize(),
    SevenZipRepairFolderBindPairs(),
    SevenZipRepairFolderStreamCounts(),
    SevenZipFixFileCountMetadata(),
    SevenZipReconcileFileNamesUtf16(),
    SevenZipDropUnreferencedFolder(),
    SevenZipDropUnreferencedFileRecord(),
    SevenZipClearInvalidStreamCrcDefinedFlag(),
    SevenZipSalvageNonSolidEntries(),
    SevenZipSalvageSolidPrefix(),
):
    register_repair_module(_module)
