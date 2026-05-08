from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job, module_limits
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import (
    zip_cd_local_header_reconcile_salvage as _native_zip_cd_local_header_reconcile,
    zip_conflict_resolver_rebuild as _native_zip_conflict_resolver,
    zip_deep_partial_recovery as _native_zip_deep_partial_recovery,
    zip_directory_field_repair as _native_zip_directory_field_repair,
)

from ._entry_salvage import run_verified_entry_salvage, verification_problem_names
from ._native_field_result import repair_result_from_native_zip_field
from ._rebuild import rebuild_zip_from_source


def _unrepairable(module_name: str, diagnosis: RepairDiagnosis, message: str, *, warnings: list[str] | None = None, native_key: str = "", native_result: dict[str, Any] | None = None) -> RepairResult:
    payload = diagnosis.as_dict()
    payload.update({"repair_name": module_name, "atomic_action_group": module_name})
    if native_key:
        payload["native_key"] = native_key
    if native_key and native_result is not None:
        payload[native_key] = native_result
    return RepairResult(
        status="unrepairable",
        confidence=0.0,
        format="zip",
        module_name=module_name,
        diagnosis=payload,
        warnings=list(warnings or []),
        message=message,
    )


class _ZipDirectoryFieldRepair:
    module_name = ""
    repair_name = ""
    categories: tuple[str, ...] = ("directory_rebuild",)
    require_flags: tuple[str, ...] = ()
    reject_flags: tuple[str, ...] = ("wrong_password",)
    base_score = 0.82
    confidence = 0.88
    content_damage_penalty = 0.35

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=("zip",),
            categories=self.categories,
            routes=(
                RepairRoute(
                    formats=("zip",),
                    require_any_categories=self.categories,
                    require_any_flags=self.require_flags,
                    reject_any_flags=self.reject_flags,
                    require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                    base_score=self.base_score,
                ),
            ),
        )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & set(self.reject_flags):
            return 0.0
        if not flags & set(self.require_flags):
            return 0.0
        if self.module_name in {"zip_fix_eocd_record", "zip_fix_cd_offset", "zip_fix_cd_entry_count"} and flags & {
            "checksum_error", "crc_error", "entry_payload_bad", "damaged", "content_integrity_bad_or_unknown", "data_error"
        }:
            return 0.0
        score = self.confidence
        if flags & {"checksum_error", "crc_error", "entry_payload_bad", "damaged", "content_integrity_bad_or_unknown", "data_error"}:
            score = max(0.15, score - self.content_damage_penalty)
        return score

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        limits = module_limits(config)
        result = dict(_native_zip_directory_field_repair(
            source_input_for_job(job),
            workspace,
            self.repair_name,
            float(limits.get("max_input_size_mb", 512) or 0),
        ))
        return repair_result_from_native_zip_field(
            self.module_name,
            result,
            job,
            diagnosis,
            config,
            repair_name=self.module_name,
            atomic_action_group=self.module_name,
        )


class ZipTrimTrailingJunk(_ZipDirectoryFieldRepair):
    module_name = "zip_trim_trailing_junk"
    repair_name = "zip_trailing_junk_trim"
    categories = ("boundary_repair",)
    require_flags = ("trailing_junk", "boundary_unreliable", "trailing_padding")
    reject_flags = ("wrong_password", "carrier_archive", "embedded_archive", "carrier_prefix")
    base_score = 0.83
    confidence = 0.88
    content_damage_penalty = 0.22


class ZipFixEocdCommentLength(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_eocd_comment_length"
    repair_name = "zip_comment_length_fix"
    categories = ("boundary_repair", "directory_rebuild")
    require_flags = ("zip_comment_length_bad", "comment_length_bad")
    base_score = 0.84
    confidence = 0.91


class ZipFixEocdRecord(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_eocd_record"
    repair_name = "zip_eocd_repair"
    categories = ("directory_rebuild", "boundary_repair")
    require_flags = ("eocd_bad",)
    reject_flags = ("wrong_password", "carrier_archive", "embedded_archive", "carrier_prefix", "sfx", "checksum_error", "crc_error", "entry_payload_bad", "damaged", "content_integrity_bad_or_unknown", "data_error")
    base_score = 0.86
    confidence = 0.97


class ZipFixCdOffset(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_cd_offset"
    repair_name = "zip_central_directory_offset_fix"
    categories = ("directory_rebuild",)
    require_flags = ("central_directory_offset_bad",)
    reject_flags = ("wrong_password", "carrier_archive", "embedded_archive", "carrier_prefix", "sfx", "checksum_error", "crc_error", "entry_payload_bad", "damaged", "content_integrity_bad_or_unknown", "data_error")
    base_score = 0.86
    confidence = 0.92


class ZipFixCdEntryCount(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_cd_entry_count"
    repair_name = "zip_central_directory_count_fix"
    categories = ("directory_rebuild",)
    require_flags = ("central_directory_count_bad",)
    reject_flags = ("wrong_password", "carrier_archive", "embedded_archive", "carrier_prefix", "sfx", "checksum_error", "crc_error", "entry_payload_bad", "damaged", "content_integrity_bad_or_unknown", "data_error")
    base_score = 0.85
    confidence = 0.90


class ZipFixLocalHeaderFields(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_local_header_fields"
    repair_name = "zip_local_header_field_repair"
    categories = ("directory_rebuild",)
    require_flags = ("local_header_bad", "local_header_length_bad", "local_header_size_bad")
    reject_flags = ("wrong_password", "carrier_archive", "embedded_archive", "carrier_prefix", "sfx")
    base_score = 0.84
    confidence = 0.88


class _Zip64FieldRepair(_ZipDirectoryFieldRepair):
    repair_name = "zip64_field_repair"
    categories = ("directory_rebuild",)
    base_score = 0.90
    confidence = 0.96
    content_damage_penalty = 0.15


class ZipFixZip64Locator(_Zip64FieldRepair):
    module_name = "zip_fix_zip64_locator"
    require_flags = ("zip64_locator_bad",)


class ZipFixZip64Eocd(_Zip64FieldRepair):
    module_name = "zip_fix_zip64_eocd"
    require_flags = ("zip64_eocd_bad",)


class ZipFixZip64ExtraSize(_Zip64FieldRepair):
    module_name = "zip_fix_zip64_extra_size"
    require_flags = ("zip64_extra_bad", "zip64_extra_size_bad")


class _ZipRebuildFromLocalHeaders:
    module_name = ""
    require_data_descriptor = False
    require_flags: tuple[str, ...] = ()
    reject_flags: tuple[str, ...] = ("missing_volume",)
    base_score = 0.84

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=("zip",),
            categories=("directory_rebuild", "content_recovery"),
            partial=True,
            routes=(
                RepairRoute(
                    formats=("zip",),
                    require_any_categories=("directory_rebuild", "content_recovery"),
                    require_any_flags=self.require_flags,
                    reject_any_flags=self.reject_flags,
                    require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                    base_score=self.base_score,
                ),
            ),
        )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & set(self.reject_flags):
            return 0.0
        if not flags & set(self.require_flags):
            return 0.0
        if self.require_data_descriptor:
            return 0.93
        coverage = coverage_view_from_job(job)
        if coverage.payload_only_suspected and "directory_rebuild" not in diagnosis.categories:
            return 0.15
        return 0.91 if coverage.directory_only_suspected else 0.86

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidate = Path(workspace) / f"{self.module_name}.zip"
        scan = rebuild_zip_from_source(
            source_input_for_job(job),
            candidate,
            require_data_descriptor=self.require_data_descriptor,
            config=config,
        )
        if not scan.entries:
            return _unrepairable(self.module_name, diagnosis, "no recoverable ZIP entries were found", warnings=scan.warnings)
        coverage = coverage_view_from_job(job)
        payload_damage = bool(set(job.damage_flags) & {"checksum_error", "crc_error", "damaged", "entry_payload_bad", "payload_bad", "data_error"})
        partial = not scan.complete or payload_damage or coverage.has_missing_entries or coverage.has_payload_damage
        confidence = 0.74 if partial else 0.92
        confidence += coverage.score_hint(directory=0.04, mixed=-0.04, payload=-0.12)
        return RepairResult(
            status="partial" if partial else "repaired",
            confidence=max(0.1, min(0.98, confidence)),
            format="zip",
            repaired_input={"kind": "file", "path": str(candidate), "format_hint": "zip"},
            actions=["scan_local_file_headers", "rebuild_zip_central_directory", "write_repaired_zip"],
            damage_flags=list(job.damage_flags),
            warnings=scan.warnings,
            workspace_paths=[str(candidate)],
            partial=partial,
            module_name=self.module_name,
            diagnosis={
                **diagnosis.as_dict(),
                "repair_name": self.module_name,
                "native_key": "native_zip_rebuild",
                "atomic_action_group": self.module_name,
                "archive_coverage": coverage.as_dict(),
                "native_zip_rebuild": scan.__dict__,
            },
        )


class ZipRebuildCdFromLocalHeaders(_ZipRebuildFromLocalHeaders):
    module_name = "zip_rebuild_cd_from_local_headers"
    require_data_descriptor = False
    require_flags = ("central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery")
    base_score = 0.85


class ZipRebuildCdFromDataDescriptors(_ZipRebuildFromLocalHeaders):
    module_name = "zip_rebuild_cd_from_data_descriptors"
    require_data_descriptor = True
    require_flags = ("data_descriptor", "compressed_size_bad", "bit3_data_descriptor")
    base_score = 0.90


class ZipReconcileCdLocalHeaders:
    spec = RepairModuleSpec(
        name="zip_reconcile_cd_local_headers",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        partial=True,
        routes=(RepairRoute(formats=("zip",), require_any_flags=("central_directory_offset_bad", "local_header_conflict"), base_score=0.91),),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        return 0.94 if flags & {"central_directory_offset_bad", "local_header_conflict"} else 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidates = self.generate_candidates(job, diagnosis, workspace, config)
        if candidates:
            return candidates[0].to_result(selection={"selected_module": self.spec.name})
        return _unrepairable(self.spec.name, diagnosis, "no verified ZIP entries could be reconciled against local headers")

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        limits = module_limits(config)
        result = dict(_native_zip_cd_local_header_reconcile(
            source_input_for_job(job), workspace,
            int(limits.get("max_entries", 20000) or 20000),
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_output_size_mb", 2048) or 0),
            float(limits.get("max_entry_uncompressed_mb", 512) or 0),
            float(limits.get("max_seconds_per_module", 30.0) or 0),
        ))
        return candidates_from_native_result(
            self.spec.name, result, job, diagnosis,
            native_key="native_zip_cd_local_header_reconcile",
            repair_name=self.spec.name,
            atomic_action_group=self.spec.name,
            format_hint="zip", partial_default=True, default_confidence=0.91,
        )


class ZipReconcileCdDataDescriptorConflict(ZipReconcileCdLocalHeaders):
    spec = RepairModuleSpec(
        name="zip_reconcile_cd_data_descriptor_conflict",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        partial=True,
        routes=(RepairRoute(formats=("zip",), require_any_flags=("data_descriptor", "bit3_data_descriptor", "compressed_size_bad", "local_header_conflict"), base_score=0.93),),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        return 0.95 if flags & {"data_descriptor", "bit3_data_descriptor", "compressed_size_bad"} and flags & {"local_header_conflict", "central_directory_bad", "central_directory_offset_bad"} else 0.0


class ZipQuarantineFailedEntries:
    spec = RepairModuleSpec(
        name="zip_quarantine_failed_entries",
        formats=("zip",),
        categories=("content_recovery",),
        partial=True,
        routes=(RepairRoute(formats=("zip",), require_any_flags=("checksum_error", "crc_error", "entry_payload_bad", "damaged"), base_score=0.88),),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if verification_problem_names(job):
            return 0.93
        return 0.80 if flags & {"checksum_error", "crc_error", "entry_payload_bad", "damaged"} else 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        names = verification_problem_names(job)
        return run_verified_entry_salvage(
            module_name=self.spec.name,
            repair_name=self.spec.name,
            native_key="native_zip_quarantine_failed_entries",
            atomic_action_group=self.spec.name,
            job=job,
            diagnosis=diagnosis,
            workspace=workspace,
            config=config,
            exclude_names=names,
            confidence=0.93,
            message="rebuilt ZIP from verified entries after quarantining names reported by verification",
        )


class ZipSalvageVerifiedEntries:
    spec = RepairModuleSpec(
        name="zip_salvage_verified_entries",
        formats=("zip",),
        categories=("content_recovery",),
        partial=True,
        routes=(RepairRoute(formats=("zip",), require_any_flags=("checksum_error", "crc_error", "entry_payload_bad", "damaged", "payload_damaged", "corrupted_data"), base_score=0.82),),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        return 0.82 if flags & {"checksum_error", "crc_error", "entry_payload_bad", "damaged", "payload_damaged", "corrupted_data"} else 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        return run_verified_entry_salvage(
            module_name=self.spec.name,
            repair_name=self.spec.name,
            native_key="native_zip_salvage_verified_entries",
            atomic_action_group=self.spec.name,
            job=job,
            diagnosis=diagnosis,
            workspace=workspace,
            config=config,
            exclude_names=[],
            confidence=0.86,
            message="rebuilt ZIP from verified local-header entries",
        )


class _ZipLocalHeaderPartialScan:
    module_name = "zip_local_header_partial_scan"
    native_key = "native_zip_local_header_partial_scan"
    require_flags: tuple[str, ...] = ("checksum_error", "crc_error", "entry_payload_bad", "damaged", "payload_damaged", "corrupted_data", "local_header_recovery", "carrier_archive", "sfx", "boundary_unreliable", "trailing_junk")
    base_score = 0.84
    default_confidence = 0.70

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=("zip",),
            categories=("content_recovery", "directory_rebuild"),
            partial=True,
            routes=(RepairRoute(formats=("zip",), require_any_flags=self.require_flags, base_score=self.base_score),),
        )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if not flags & set(self.require_flags):
            return 0.0
        if flags & {"carrier_archive", "sfx"}:
            return 0.78
        return 0.90 if flags & {"local_header_recovery", "entry_payload_bad", "crc_error", "checksum_error"} else 0.74

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidates = self.generate_candidates(job, diagnosis, workspace, config)
        if not candidates:
            return _unrepairable(self.module_name, diagnosis, "local-header partial scan did not produce a candidate")
        return candidates[0].to_result(selection={"selected_module": self.module_name})

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        limits = module_limits(config)
        result = dict(_native_zip_deep_partial_recovery(
            source_input_for_job(job), workspace,
            int(limits.get("max_candidates_per_module", 3) or 3),
            int(limits.get("max_entries", 20000) or 20000),
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_output_size_mb", 2048) or 0),
            float(limits.get("max_entry_uncompressed_mb", 512) or 0),
            float(limits.get("max_seconds_per_module", 30.0) or 0),
            bool(limits.get("verify_candidates", True)),
        ))
        coverage = coverage_view_from_job(job)
        candidates = candidates_from_native_result(
            self.module_name, result, job, diagnosis,
            native_key=self.native_key,
            repair_name=self.module_name,
            atomic_action_group=self.module_name,
            format_hint="zip", partial_default=True, default_confidence=self.default_confidence,
        )
        output = []
        for candidate in candidates:
            native = candidate.diagnosis.get("native_candidate", {}) if isinstance(candidate.diagnosis, dict) else {}
            verified_entries = int(native.get("verified_entries") or 0)
            entry_count = int(native.get("entries") or 0)
            if verified_entries > 0 or (self.module_name == "zip_partial_salvage_missing_volume" and entry_count > 0):
                output.append(replace(candidate, confidence=min(0.99, float(candidate.confidence or 0.0) + coverage.score_hint(payload=0.04, mixed=0.05, partial=0.02))))
        return output


class ZipPartialSalvageMissingVolume(_ZipLocalHeaderPartialScan):
    module_name = "zip_partial_salvage_missing_volume"
    native_key = "native_zip_partial_salvage_missing_volume"
    require_flags = ("missing_volume", "input_truncated", "unexpected_end", "stream_truncated")
    base_score = 0.94
    default_confidence = 0.68

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        return 0.96 if flags & {"missing_volume", "input_truncated", "unexpected_end", "stream_truncated"} and "local_header_recovery" in flags else 0.0


class _ZipConflictResolver:
    module_name = ""
    require_flags: tuple[str, ...] = ()
    base_score = 0.88

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=("zip",),
            categories=("directory_rebuild", "content_recovery"),
            partial=True,
            routes=(RepairRoute(formats=("zip",), require_any_flags=self.require_flags, reject_any_flags=("missing_volume",), base_score=self.base_score),),
        )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        return 0.94 if flags & set(self.require_flags) and "missing_volume" not in flags else 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidates = self.generate_candidates(job, diagnosis, workspace, config)
        if candidates:
            return candidates[0].to_result(selection={"selected_module": self.module_name})
        return _unrepairable(self.module_name, diagnosis, "ZIP conflict resolver did not produce a candidate")

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        limits = module_limits(config)
        result = dict(_native_zip_conflict_resolver(
            source_input_for_job(job), workspace,
            int(limits.get("max_entries", 20000) or 20000),
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_output_size_mb", 2048) or 0),
            float(limits.get("max_entry_uncompressed_mb", 512) or 0),
            bool(limits.get("verify_candidates", True)),
        ))
        return candidates_from_native_result(
            self.module_name, result, job, diagnosis,
            native_key=f"native_{self.module_name}",
            repair_name=self.module_name,
            atomic_action_group=self.module_name,
            format_hint="zip", partial_default=True, default_confidence=0.74,
        )


class ZipResolveDuplicateEntries(_ZipConflictResolver):
    module_name = "zip_resolve_duplicate_entries"
    require_flags = ("duplicate_entries",)
    base_score = 0.91


class ZipResolveOverlappingEntries(_ZipConflictResolver):
    module_name = "zip_resolve_overlapping_entries"
    require_flags = ("overlapping_entries",)
    base_score = 0.91


for _module in (
    ZipTrimTrailingJunk(),
    ZipFixEocdCommentLength(),
    ZipFixEocdRecord(),
    ZipFixCdOffset(),
    ZipFixCdEntryCount(),
    ZipFixLocalHeaderFields(),
    ZipFixZip64Locator(),
    ZipFixZip64Eocd(),
    ZipFixZip64ExtraSize(),
    ZipRebuildCdFromLocalHeaders(),
    ZipRebuildCdFromDataDescriptors(),
    ZipReconcileCdLocalHeaders(),
    ZipReconcileCdDataDescriptorConflict(),
    ZipQuarantineFailedEntries(),
    ZipSalvageVerifiedEntries(),
    ZipPartialSalvageMissingVolume(),
    _ZipLocalHeaderPartialScan(),
    ZipResolveDuplicateEntries(),
    ZipResolveOverlappingEntries(),
):
    register_repair_module(_module)
