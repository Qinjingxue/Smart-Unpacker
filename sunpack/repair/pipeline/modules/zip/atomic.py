from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import cached_repair_operation, cache_relevant_module_limits, source_input_for_job, module_limits
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import (
    zip_cd_local_header_reconcile_salvage as _native_zip_cd_local_header_reconcile,
    zip_conflict_resolver_rebuild as _native_zip_conflict_resolver,
    zip_deep_partial_recovery as _native_zip_deep_partial_recovery,
    zip_directory_field_repair as _native_zip_directory_field_repair,
    zip_remove_spurious_data_descriptor as _native_zip_remove_spurious_data_descriptor,
)

from ._entry_salvage import run_verified_entry_salvage, verification_problem_names
from ._native_field_result import repair_result_from_native_zip_field
from ._rebuild import rebuild_zip_from_source


CONTENT_DAMAGE_FLAGS = (
    "checksum_error",
    "crc_error",
    "entry_payload_bad",
    "payload_bad",
    "payload_damaged",
    "damaged",
    "content_integrity_bad_or_unknown",
    "data_error",
    "corrupted_data",
)
CARRIER_FLAGS = ("carrier_archive", "embedded_archive", "carrier_prefix", "sfx")
MISSING_VOLUME_FLAGS = ("missing_volume", "input_truncated", "unexpected_end", "stream_truncated")
DESCRIPTOR_FLAGS = ("data_descriptor", "bit3_data_descriptor", "compressed_size_bad")


def _unrepairable(module_name: str, diagnosis: RepairDiagnosis, message: str, *, warnings: list[str] | None = None, native_key: str = "", native_result: dict[str, Any] | None = None) -> RepairResult:
    payload = diagnosis.as_dict()
    payload.update({"repair_name": module_name, "atomic_action_group": module_name})
    if native_key:
        payload["native_key"] = native_key
    if native_key and native_result is not None:
        payload[native_key] = native_result
        if bool(native_result.get("native_target_mismatch")):
            payload["native_target_mismatch"] = True
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
    route_family = ""
    expected_native_actions: tuple[str, ...] = ()
    expected_native_target = ""

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=("zip",),
            categories=self.categories,
            atomic=True,
            route_family=self.route_family or self.module_name,
            routes=(
                RepairRoute(
                    formats=("zip",),
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
        if self.module_name in {"zip_fix_eocd_record", "zip_fix_cd_offset", "zip_fix_cd_entry_count"} and flags & set(CONTENT_DAMAGE_FLAGS):
            return 0.0
        score = self.confidence
        if flags & set(CONTENT_DAMAGE_FLAGS):
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
        expected_target = self.expected_native_target or self.repair_name
        native_target = str(result.get("native_target") or "")
        if str(result.get("status") or "") == "repaired" and expected_target and native_target and native_target != expected_target:
            result["native_target_mismatch"] = True
            result["expected_native_target"] = expected_target
            return _unrepairable(
                self.module_name,
                diagnosis,
                "native ZIP field repair produced a different atomic target",
                native_key="native_zip_directory_field_repair",
                native_result=result,
            )
        if self.expected_native_actions and str(result.get("status") or "") == "repaired":
            actions = {str(action) for action in result.get("actions") or []}
            if not actions & set(self.expected_native_actions):
                result["native_target_mismatch"] = True
                result["expected_native_actions"] = list(self.expected_native_actions)
                return _unrepairable(
                    self.module_name,
                    diagnosis,
                    "native ZIP field repair produced a different atomic target",
                    native_key="native_zip_directory_field_repair",
                    native_result=result,
                )
        result_payload = repair_result_from_native_zip_field(
            self.module_name,
            result,
            job,
            diagnosis,
            config,
            repair_name=self.module_name,
            atomic_action_group=self.module_name,
        )
        if result_payload.ok:
            patch_facts = _patch_facts_for_directory_field(self.module_name, result_payload.diagnosis)
            result_payload.diagnosis["patch_facts"] = patch_facts
        return result_payload


class ZipTrimTrailingJunk(_ZipDirectoryFieldRepair):
    module_name = "zip_trim_trailing_junk"
    repair_name = "zip_trailing_junk_trim"
    expected_native_target = "trailing_junk"
    categories = ("boundary_repair",)
    require_flags = ("trailing_junk", "boundary_unreliable", "trailing_padding")
    reject_flags = ("wrong_password", *CARRIER_FLAGS, *MISSING_VOLUME_FLAGS)
    base_score = 0.83
    confidence = 0.88
    content_damage_penalty = 0.22


class ZipFixEocdCommentLength(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_eocd_comment_length"
    repair_name = "zip_comment_length_fix"
    expected_native_target = "comment_length"
    categories = ("boundary_repair", "directory_rebuild")
    require_flags = ("zip_comment_length_bad", "comment_length_bad")
    reject_flags = ("wrong_password", *CARRIER_FLAGS, *MISSING_VOLUME_FLAGS, *CONTENT_DAMAGE_FLAGS, *DESCRIPTOR_FLAGS)
    base_score = 0.84
    confidence = 0.91


class ZipFixEocdRecord(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_eocd_record"
    repair_name = "zip_eocd_repair"
    expected_native_target = "eocd"
    categories = ("directory_rebuild", "boundary_repair")
    require_flags = ("eocd_bad",)
    reject_flags = ("wrong_password", *CARRIER_FLAGS, *MISSING_VOLUME_FLAGS, *CONTENT_DAMAGE_FLAGS)
    base_score = 0.86
    confidence = 0.97


class ZipFixCdOffset(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_cd_offset"
    repair_name = "zip_central_directory_offset_fix"
    expected_native_target = "cd_offset"
    categories = ("directory_rebuild",)
    require_flags = ("central_directory_offset_bad",)
    reject_flags = ("wrong_password", *CARRIER_FLAGS, *MISSING_VOLUME_FLAGS, *CONTENT_DAMAGE_FLAGS)
    base_score = 0.86
    confidence = 0.92


class ZipFixCdEntryCount(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_cd_entry_count"
    repair_name = "zip_central_directory_count_fix"
    expected_native_target = "cd_count"
    categories = ("directory_rebuild",)
    require_flags = ("central_directory_count_bad",)
    reject_flags = ("wrong_password", *CARRIER_FLAGS, *MISSING_VOLUME_FLAGS, *CONTENT_DAMAGE_FLAGS)
    base_score = 0.85
    confidence = 0.90


class ZipFixLocalHeaderFields(_ZipDirectoryFieldRepair):
    module_name = "zip_fix_local_header_fields"
    repair_name = "zip_local_header_field_repair"
    expected_native_target = "local_header"
    categories = ("directory_rebuild",)
    require_flags = ("local_header_bad", "local_header_length_bad", "local_header_size_bad")
    reject_flags = ("wrong_password", *CARRIER_FLAGS, *MISSING_VOLUME_FLAGS, *CONTENT_DAMAGE_FLAGS)
    base_score = 0.84
    confidence = 0.88


class _Zip64FieldRepair(_ZipDirectoryFieldRepair):
    categories = ("directory_rebuild",)
    base_score = 0.90
    confidence = 0.96
    content_damage_penalty = 0.15
    reject_flags = ("wrong_password", *CARRIER_FLAGS, *MISSING_VOLUME_FLAGS, *CONTENT_DAMAGE_FLAGS)


class ZipFixZip64Locator(_Zip64FieldRepair):
    module_name = "zip_fix_zip64_locator"
    repair_name = "zip64_locator"
    expected_native_target = "zip64_locator"
    require_flags = ("zip64_locator_bad",)
    route_family = "zip64_locator"
    expected_native_actions = ("normalize_zip64_eocd_locator", "rewrite_zip64_eocd_locator")


class ZipFixZip64Eocd(_Zip64FieldRepair):
    module_name = "zip_fix_zip64_eocd"
    repair_name = "zip64_eocd"
    expected_native_target = "zip64_eocd"
    require_flags = ("zip64_eocd_bad",)
    route_family = "zip64_eocd"
    expected_native_actions = ("rewrite_zip64_eocd_fields",)


class ZipFixZip64ExtraSize(_Zip64FieldRepair):
    module_name = "zip_fix_zip64_extra_size"
    repair_name = "zip64_extra_size"
    expected_native_target = "zip64_extra_size"
    require_flags = ("zip64_extra_bad", "zip64_extra_size_bad")
    route_family = "zip64_extra"
    expected_native_actions = ("reconcile_zip64_central_extra_fields",)


class _ZipRebuildFromLocalHeaders:
    module_name = ""
    require_data_descriptor = False
    preserve_raw_names = False
    require_flags: tuple[str, ...] = ()
    reject_flags: tuple[str, ...] = ("missing_volume",)
    base_score = 0.84
    route_family = ""

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=("zip",),
            categories=("directory_rebuild", "content_recovery"),
            partial=True,
            atomic=True,
            route_family=self.route_family or self.module_name,
            routes=(
                RepairRoute(
                    formats=("zip",),
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
            preserve_raw_names=self.preserve_raw_names,
            config=config,
            cache_job=job,
        )
        if not scan.entries:
            return _unrepairable(self.module_name, diagnosis, "no recoverable ZIP entries were found", warnings=scan.warnings)
        if self.preserve_raw_names and scan.native_target != "rebuild_cd_preserve_raw_names":
            return _unrepairable(
                self.module_name,
                diagnosis,
                "native ZIP rebuild produced a different atomic target",
                warnings=scan.warnings,
                native_key="native_zip_rebuild",
                native_result={"native_target": scan.native_target, "native_target_mismatch": True, "validation_details": scan.validation_details or {}},
            )
        coverage = coverage_view_from_job(job)
        payload_damage = bool(set(job.damage_flags) & {"checksum_error", "crc_error", "damaged", "entry_payload_bad", "payload_bad", "data_error"})
        partial = not scan.complete or payload_damage or coverage.has_missing_entries or coverage.has_payload_damage
        confidence = 0.74 if partial else 0.92
        confidence += coverage.score_hint(directory=0.04, mixed=-0.04, payload=-0.12)
        patch_facts = _dedupe([str(value) for value in scan.patch_facts or []])
        residual_facts = _dedupe([str(value) for value in scan.residual_facts or []])
        source_input = source_input_for_job(job)
        actions = ["scan_local_file_headers"]
        actions.append("preserve_raw_filename_bytes" if self.preserve_raw_names else "rebuild_zip_central_directory")
        actions.append("write_repaired_zip")
        return RepairResult(
            status="partial" if partial else "repaired",
            confidence=max(0.1, min(0.98, confidence)),
            format="zip",
            repaired_input={"kind": "file", "path": str(candidate), "format_hint": "zip"},
            actions=actions,
            damage_flags=list(job.damage_flags),
            warnings=scan.warnings,
            workspace_paths=[str(candidate)],
            partial=partial,
            module_name=self.module_name,
            diagnosis={
                **diagnosis.as_dict(),
                "repair_name": self.module_name,
                "native_key": "native_zip_rebuild",
                "native_target": scan.native_target,
                "candidate_status": scan.candidate_status,
                "atomic_action_group": self.module_name,
                "patch_facts": patch_facts,
                "residual_facts": residual_facts,
                "validation_details": scan.validation_details or {},
                "logical_stream_built": bool(scan.logical_stream_built) or bool(source_input.get("logical_stream_built")) or str(source_input.get("kind") or "") == "concat_ranges",
                "split_sidecars_available": bool(scan.split_sidecars_available) or "split_sidecars_available" in set(job.damage_flags),
                "raw_name_bytes_preserved": bool((scan.validation_details or {}).get("raw_filename_bytes_preserved")),
                "raw_name_source": "local_header" if "raw_name_source=local_header" in set(patch_facts) else "",
                "archive_coverage": coverage.as_dict(),
                "native_zip_rebuild": scan.__dict__,
            },
        )


class ZipRebuildCdFromLocalHeaders(_ZipRebuildFromLocalHeaders):
    module_name = "zip_rebuild_cd_from_local_headers"
    require_data_descriptor = False
    require_flags = ("central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery")
    base_score = 0.85


class ZipRebuildCdPreserveRawNames(_ZipRebuildFromLocalHeaders):
    module_name = "zip_rebuild_cd_preserve_raw_names"
    require_data_descriptor = False
    preserve_raw_names = True
    require_flags = (
        "non_utf8_filename",
        "filename_encoding_bad",
        "raw_filename_bytes",
        "central_directory_bad",
        "directory_integrity_bad_or_unknown",
        "local_header_recovery",
    )
    base_score = 0.91
    route_family = "raw_name_directory_rebuild"

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & set(self.reject_flags):
            return 0.0
        if flags & {"non_utf8_filename", "filename_encoding_bad", "raw_filename_bytes"}:
            return 0.97
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"} and (
            "directory_rebuild" in diagnosis.categories or "content_recovery" in diagnosis.categories
        ):
            return 0.88
        return 0.0

class ZipRebuildCdFromDataDescriptors(_ZipRebuildFromLocalHeaders):
    module_name = "zip_rebuild_cd_from_data_descriptors"
    require_data_descriptor = True
    require_flags = ("data_descriptor", "compressed_size_bad", "bit3_data_descriptor")
    reject_flags = ("missing_volume", *CARRIER_FLAGS)
    base_score = 0.90
    route_family = "descriptor_rebuild"


class ZipRemoveSpuriousDataDescriptor:
    spec = RepairModuleSpec(
        name="zip_remove_spurious_data_descriptor",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        partial=True,
        atomic=True,
        route_family="descriptor_stream_surgery",
        routes=(RepairRoute(
            formats=("zip",),
            require_any_flags=(
                "spurious_data_descriptor_candidate",
                "descriptor_record_in_payload_gap",
                "descriptor_delete_would_align_next_header",
                *DESCRIPTOR_FLAGS,
            ),
            reject_any_flags=(*MISSING_VOLUME_FLAGS, *CARRIER_FLAGS),
            base_score=0.96,
        ),),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & set(MISSING_VOLUME_FLAGS) or flags & set(CARRIER_FLAGS):
            return 0.0
        descriptor = bool(flags & {"data_descriptor", "bit3_data_descriptor", "compressed_size_bad"})
        structural_shift = bool(flags & {
            "spurious_data_descriptor_candidate",
            "descriptor_record_in_payload_gap",
            "descriptor_delete_would_align_next_header",
            "local_header_conflict",
            "central_directory_offset_bad",
            "central_directory_bad",
        })
        return 0.97 if descriptor and structural_shift else 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidates = self.generate_candidates(job, diagnosis, workspace, config)
        if candidates:
            return candidates[0].to_result(selection={"selected_module": self.spec.name})
        return _unrepairable(self.spec.name, diagnosis, "no spurious ZIP data descriptor could be deleted")

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        limits = module_limits(config)
        result = dict(_native_zip_remove_spurious_data_descriptor(
            source_input_for_job(job),
            workspace,
            int(limits.get("max_candidates_per_module", 3) or 3),
            int(limits.get("max_entries", 20000) or 20000),
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_seconds_per_module", 30.0) or 0),
        ))
        return candidates_from_native_result(
            self.spec.name, result, job, diagnosis,
            native_key="native_zip_remove_spurious_data_descriptor",
            repair_name=self.spec.name,
            atomic_action_group=self.spec.name,
            format_hint="zip",
            partial_default=True,
            default_confidence=0.94,
            prefer_patch_plan=bool(config.get("virtual_patch_candidate", True)),
        )


class ZipNormalizeDataDescriptorFlags(_ZipDirectoryFieldRepair):
    module_name = "zip_normalize_data_descriptor_flags"
    repair_name = "zip_data_descriptor_flag_normalize"
    categories = ("directory_rebuild", "content_recovery")
    require_flags = ("data_descriptor", "bit3_data_descriptor", "compressed_size_bad", "after_descriptor_stream_reconcile")
    reject_flags = (*MISSING_VOLUME_FLAGS, *CARRIER_FLAGS)
    base_score = 0.94
    confidence = 0.93
    route_family = "descriptor_flag_normalize"
    expected_native_actions = ("normalize_zip_data_descriptor_bit_flags",)
    expected_native_target = "data_descriptor_flags"

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & set(self.reject_flags):
            return 0.0
        descriptor = bool(flags & {"data_descriptor", "bit3_data_descriptor", "compressed_size_bad"})
        if descriptor and flags & {"after_descriptor_stream_reconcile", "local_header_conflict", "central_directory_bad", "central_directory_offset_bad"}:
            return 0.95
        return 0.0


class ZipReconcileCdEntryNamesFromLocalHeaders(_ZipDirectoryFieldRepair):
    module_name = "zip_reconcile_cd_entry_names_from_local_headers"
    repair_name = "zip_cd_entry_name_reconcile"
    categories = ("directory_rebuild",)
    require_flags = (
        "central_directory_bad",
        "local_header_conflict",
        "after_descriptor_stream_reconcile",
        "after_descriptor_flag_normalize",
    )
    reject_flags = (*MISSING_VOLUME_FLAGS, *CARRIER_FLAGS)
    base_score = 0.93
    confidence = 0.94
    route_family = "cd_entry_name_reconcile"
    expected_native_actions = ("reconcile_central_directory_names_from_local_headers",)
    expected_native_target = "cd_entry_names"

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & set(self.reject_flags):
            return 0.0
        if flags & {"central_directory_bad", "local_header_conflict"} and flags & {"after_descriptor_stream_reconcile", "after_descriptor_flag_normalize", "exact_match_failed"}:
            return 0.94
        return 0.0


class ZipReconcileCdLocalHeaders:
    spec = RepairModuleSpec(
        name="zip_reconcile_cd_local_headers",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        partial=True,
        atomic=True,
        route_family="cd_local_reconcile",
        routes=(RepairRoute(
            formats=("zip",),
            require_any_flags=("central_directory_offset_bad", "local_header_conflict"),
            reject_any_flags=(*MISSING_VOLUME_FLAGS, *DESCRIPTOR_FLAGS),
            base_score=0.91,
        ),),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & set(MISSING_VOLUME_FLAGS) or flags & set(DESCRIPTOR_FLAGS):
            return 0.0
        return 0.94 if flags & {"central_directory_offset_bad", "local_header_conflict"} else 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidates = self.generate_candidates(job, diagnosis, workspace, config)
        if candidates:
            return candidates[0].to_result(selection={"selected_module": self.spec.name})
        return _unrepairable(self.spec.name, diagnosis, "no verified ZIP entries could be reconciled against local headers")

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        limits = module_limits(config)
        source_input = source_input_for_job(job)
        params = {
            "source_input": source_input,
            "workspace": workspace,
            "module": self.spec.name,
            "limits": cache_relevant_module_limits(config),
        }
        result = dict(cached_repair_operation(
            job,
            "native_zip_cd_local_header_reconcile",
            self.spec.name,
            params,
            lambda: dict(_native_zip_cd_local_header_reconcile(
                source_input, workspace,
                int(limits.get("max_entries", 20000) or 20000),
                float(limits.get("max_input_size_mb", 512) or 0),
                float(limits.get("max_output_size_mb", 2048) or 0),
                float(limits.get("max_entry_uncompressed_mb", 512) or 0),
                float(limits.get("max_seconds_per_module", 30.0) or 0),
            )),
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
        atomic=True,
        route_family="descriptor_conflict_reconcile",
        routes=(RepairRoute(
            formats=("zip",),
            require_any_flags=DESCRIPTOR_FLAGS,
            reject_any_flags=(*MISSING_VOLUME_FLAGS, *CARRIER_FLAGS),
            base_score=0.93,
        ),),
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
        atomic=True,
        route_family="payload_quarantine",
        routes=(RepairRoute(formats=("zip",), require_any_flags=("checksum_error", "crc_error", "entry_payload_bad", "damaged"), reject_any_flags=MISSING_VOLUME_FLAGS, base_score=0.88),),
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
        atomic=True,
        route_family="verified_entry_salvage",
        routes=(RepairRoute(formats=("zip",), require_any_flags=("checksum_error", "crc_error", "entry_payload_bad", "damaged", "payload_damaged", "corrupted_data"), reject_any_flags=MISSING_VOLUME_FLAGS, base_score=0.82),),
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
    require_flags: tuple[str, ...] = ("checksum_error", "crc_error", "entry_payload_bad", "damaged", "payload_damaged", "corrupted_data", "local_header_recovery")
    reject_flags: tuple[str, ...] = (*MISSING_VOLUME_FLAGS, *CARRIER_FLAGS)
    base_score = 0.84
    default_confidence = 0.70
    route_family = "local_header_partial_scan"

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=("zip",),
            categories=("content_recovery", "directory_rebuild"),
            partial=True,
            atomic=True,
            route_family=self.route_family,
            routes=(RepairRoute(formats=("zip",), require_any_flags=self.require_flags, reject_any_flags=self.reject_flags, base_score=self.base_score),),
        )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & set(self.reject_flags):
            return 0.0
        if not flags & set(self.require_flags):
            return 0.0
        return 0.90 if flags & {"local_header_recovery", "entry_payload_bad", "crc_error", "checksum_error"} else 0.74

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidates = self.generate_candidates(job, diagnosis, workspace, config)
        if not candidates:
            return _unrepairable(self.module_name, diagnosis, "local-header partial scan did not produce a candidate")
        return candidates[0].to_result(selection={"selected_module": self.module_name})

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        limits = module_limits(config)
        source_input = source_input_for_job(job)
        params = {
            "source_input": source_input,
            "workspace": workspace,
            "module": self.module_name,
            "native_key": self.native_key,
            "limits": cache_relevant_module_limits(config),
        }
        result = dict(cached_repair_operation(
            job,
            "native_zip_deep_partial_recovery",
            self.module_name,
            params,
            lambda: dict(_native_zip_deep_partial_recovery(
                source_input, workspace,
                int(limits.get("max_candidates_per_module", 3) or 3),
                int(limits.get("max_entries", 20000) or 20000),
                float(limits.get("max_input_size_mb", 512) or 0),
                float(limits.get("max_output_size_mb", 2048) or 0),
                float(limits.get("max_entry_uncompressed_mb", 512) or 0),
                float(limits.get("max_seconds_per_module", 30.0) or 0),
                bool(limits.get("verify_candidates", True)),
            )),
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
    reject_flags = ("wrong_password",)
    base_score = 0.94
    default_confidence = 0.68
    route_family = "missing_volume_partial_salvage"

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        return 0.96 if flags & {"missing_volume", "input_truncated", "unexpected_end", "stream_truncated"} and "local_header_recovery" in flags else 0.0


class _ZipConflictResolver:
    module_name = ""
    require_flags: tuple[str, ...] = ()
    base_score = 0.88
    route_family = ""

    @property
    def spec(self) -> RepairModuleSpec:
        return RepairModuleSpec(
            name=self.module_name,
            formats=("zip",),
            categories=("directory_rebuild", "content_recovery"),
            partial=True,
            atomic=True,
            route_family=self.route_family or self.module_name,
            routes=(RepairRoute(formats=("zip",), require_any_flags=self.require_flags, reject_any_flags=(*MISSING_VOLUME_FLAGS, *DESCRIPTOR_FLAGS), base_score=self.base_score),),
        )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        return 0.94 if flags & set(self.require_flags) and not (flags & set(MISSING_VOLUME_FLAGS) or flags & set(DESCRIPTOR_FLAGS)) else 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        candidates = self.generate_candidates(job, diagnosis, workspace, config)
        if candidates:
            return candidates[0].to_result(selection={"selected_module": self.module_name})
        return _unrepairable(self.module_name, diagnosis, "ZIP conflict resolver did not produce a candidate")

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        limits = module_limits(config)
        source_input = source_input_for_job(job)
        policy = "crc_match" if self.module_name == "zip_resolve_duplicate_entries" else "first"
        params = {
            "source_input": source_input,
            "workspace": workspace,
            "module": self.module_name,
            "policy": policy,
            "limits": cache_relevant_module_limits(config),
        }
        result = dict(cached_repair_operation(
            job,
            "native_zip_conflict_resolver_rebuild",
            self.module_name,
            params,
            lambda: dict(_native_zip_conflict_resolver(
                source_input, workspace,
                int(limits.get("max_entries", 20000) or 20000),
                float(limits.get("max_input_size_mb", 512) or 0),
                float(limits.get("max_output_size_mb", 2048) or 0),
                float(limits.get("max_entry_uncompressed_mb", 512) or 0),
                bool(limits.get("verify_candidates", True)),
                policy,
            )),
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

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        candidates = super().generate_candidates(job, diagnosis, workspace, config)
        output = []
        for candidate in candidates:
            diagnosis_payload = dict(candidate.diagnosis)
            diagnosis_payload["patch_facts"] = _dedupe([
                *[str(value) for value in diagnosis_payload.get("patch_facts") or []],
                "resolved_duplicate_entries",
                "kept_entry_policy=crc_match",
            ])
            output.append(replace(candidate, diagnosis=diagnosis_payload, actions=_dedupe([*candidate.actions, "resolve_duplicate_entries"])))
        return output


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
    ZipRebuildCdPreserveRawNames(),
    ZipRebuildCdFromDataDescriptors(),
    ZipRemoveSpuriousDataDescriptor(),
    ZipNormalizeDataDescriptorFlags(),
    ZipReconcileCdEntryNamesFromLocalHeaders(),
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


def _patch_facts_for_directory_field(module_name: str, diagnosis: dict[str, Any]) -> list[str]:
    mapping = {
        "zip_fix_eocd_comment_length": ["fixed_field=eocd_comment_length", "after_eocd_repair"],
        "zip_fix_eocd_record": ["fixed_field=eocd_record", "after_eocd_repair"],
        "zip_fix_cd_offset": ["fixed_field=central_directory_offset"],
        "zip_fix_cd_entry_count": ["fixed_field=central_directory_entry_count"],
        "zip_fix_local_header_fields": ["fixed_field=local_header_fields", "after_local_header_repair"],
        "zip_fix_zip64_locator": ["fixed_field=zip64_locator"],
        "zip_fix_zip64_eocd": ["fixed_field=zip64_eocd"],
        "zip_fix_zip64_extra_size": ["fixed_field=zip64_extra_size"],
        "zip_trim_trailing_junk": ["fixed_field=trailing_junk"],
    }
    return _dedupe([*[str(value) for value in diagnosis.get("patch_facts") or []], *mapping.get(module_name, [])])


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output
