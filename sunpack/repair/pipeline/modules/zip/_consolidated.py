from __future__ import annotations

"""Consolidated ZIP repair operations.

Seven atomic operations replacing the original 16 overlapping modules.
Each maps to a single native backend function with parameterized behavior.
"""

from pathlib import Path

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import (
    zip_rebuild_from_local_headers,
    zip_directory_field_repair,
    zip_deep_partial_recovery,
    zip_conflict_resolver_rebuild,
    zip_verified_entry_salvage,
    zip_cd_local_header_reconcile_salvage,
)

from ._rebuild import rebuild_zip_from_source
from ._entry_salvage import run_verified_entry_salvage, verification_problem_names
from ._native_field_result import repair_result_from_native_zip_field


# ── Operation 1: fix_boundary ──────────────────────────────────────
# Covers: EOCD comment length fix, trailing junk trim
# Native: zip_directory_field_repair("zip_comment_length_fix" / "zip_trailing_junk_trim")

class ZipFixBoundary:
    spec = RepairModuleSpec(
        name="zip_fix_boundary",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "boundary_repair"),
                require_any_flags=(
                    "zip_comment_length_bad", "comment_length_bad", "eocd_bad",
                    "trailing_junk", "boundary_unreliable", "trailing_padding",
                ),
                require_any_fuzzy_hints=("trailing_text_junk_likely", "tail_printable_region", "trailing_padding_likely"),
                reject_any_flags=("wrong_password", "carrier_archive", "sfx", "embedded_archive", "carrier_prefix"),
                base_score=0.80,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.0
        if flags & {"trailing_junk", "boundary_unreliable"}:
            return 0.88
        if flags & {"zip_comment_length_bad", "comment_length_bad", "eocd_bad"}:
            if flags & {"trailing_junk"}:
                return 0.50
            return 0.90
        if "boundary_repair" in diagnosis.categories:
            return 0.74
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        flags = set(job.damage_flags)
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}

        # Pick the best repair target
        if flags & {"trailing_junk", "boundary_unreliable"}:
            repair_name = "zip_trailing_junk_trim"
        else:
            repair_name = "zip_comment_length_fix"

        result = zip_directory_field_repair(
            source_input_for_job(job),
            workspace,
            repair_name,
            float(deep.get("max_input_size_mb", 512) or 0),
        )
        # Fallback: if native couldn't fix, try a full rebuild from local headers
        if str(dict(result).get("status") or "") != "repaired":
            coverage = coverage_view_from_job(job)
            if coverage.has_recovered_output or flags & {"central_directory_bad", "directory_integrity_bad_or_unknown"}:
                output = Path(workspace) / "zip_fix_boundary_fallback.zip"
                scan = rebuild_zip_from_source(source_input_for_job(job), output, config=config)
                if scan.entries and scan.complete:
                    return RepairResult(
                        status="repaired",
                        confidence=0.82,
                        format="zip",
                        repaired_input={"kind": "file", "path": str(output), "format_hint": "zip"},
                        actions=["native_rebuild_zip_from_local_headers"],
                        damage_flags=list(job.damage_flags),
                        warnings=scan.warnings,
                        workspace_paths=[str(output)],
                        module_name=self.spec.name,
                        diagnosis={**diagnosis.as_dict(), "native_zip_rebuild": scan.__dict__},
                        message="ZIP was rebuilt natively from local headers after boundary repair could not trust the directory",
                    )
        return repair_result_from_native_zip_field(self.spec.name, dict(result), job, diagnosis, config)


# ── Operation 2: fix_pointers ──────────────────────────────────────
# Covers: CD offset fix, CD count fix, EOCD record repair
# Native: zip_directory_field_repair("zip_central_directory_count_fix" / "zip_central_directory_offset_fix" / "zip_eocd_repair")

class ZipFixPointers:
    spec = RepairModuleSpec(
        name="zip_fix_pointers",
        formats=("zip",),
        categories=("directory_rebuild", "boundary_repair"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "boundary_repair"),
                require_any_flags=(
                    "central_directory_offset_bad", "central_directory_count_bad",
                    "central_directory_bad", "eocd_bad", "directory_integrity_bad_or_unknown",
                ),
                require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                base_score=0.82,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        content_damage = {"checksum_error", "crc_error", "entry_payload_bad", "damaged",
                          "content_integrity_bad_or_unknown", "data_error"}
        if flags & {"carrier_archive", "sfx", "embedded_archive", "carrier_prefix"}:
            return 0.0
        if flags & content_damage:
            return 0.0
        if "eocd_bad" in flags:
            return 0.97
        if flags & {"central_directory_offset_bad", "central_directory_count_bad", "central_directory_bad"}:
            return 0.90
        if flags & {"directory_integrity_bad_or_unknown"}:
            return 0.85
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        flags = set(job.damage_flags)
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}

        if "eocd_bad" in flags:
            repair_name = "zip_eocd_repair"
        elif flags & {"central_directory_offset_bad"}:
            repair_name = "zip_central_directory_offset_fix"
        elif flags & {"central_directory_count_bad"}:
            repair_name = "zip_central_directory_count_fix"
        else:
            repair_name = "zip_eocd_repair"

        result = zip_directory_field_repair(
            source_input_for_job(job),
            workspace,
            repair_name,
            float(deep.get("max_input_size_mb", 512) or 0),
        )
        return repair_result_from_native_zip_field(self.spec.name, dict(result), job, diagnosis, config)


# ── Operation 3: fix_zip64 ─────────────────────────────────────────
# Covers: ZIP64 EOCD, locator, and extra field repair
# Native: zip_directory_field_repair("zip64_field_repair")

class ZipFix64:
    spec = RepairModuleSpec(
        name="zip_fix_zip64",
        formats=("zip",),
        categories=("directory_rebuild",),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_flags=(
                    "zip64", "zip64_eocd_bad", "zip64_locator_bad",
                    "zip64_extra_bad", "central_directory_bad",
                ),
                require_any_failure_kinds=("structure_recognition",),
                base_score=0.90,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"zip64_eocd_bad", "zip64_locator_bad", "zip64_extra_bad"}:
            return 0.99
        if "zip64" in flags and flags & {"central_directory_bad", "compressed_size_bad", "local_header_bad"}:
            return 0.88
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = zip_directory_field_repair(
            source_input_for_job(job),
            workspace,
            "zip64_field_repair",
            float(deep.get("max_input_size_mb", 512) or 0),
        )
        return repair_result_from_native_zip_field(self.spec.name, dict(result), job, diagnosis, config)


# ── Operation 4: rebuild ───────────────────────────────────────────
# Covers: Full rebuild from local headers, data descriptor recovery, partial recovery
# Native: zip_rebuild_from_local_headers

class ZipRebuild:
    spec = RepairModuleSpec(
        name="zip_rebuild",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        stage="targeted",
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "content_recovery"),
                require_any_flags=(
                    "central_directory_bad", "directory_integrity_bad_or_unknown",
                    "local_header_recovery", "data_descriptor", "compressed_size_bad",
                    "bit3_data_descriptor",
                ),
                require_any_failure_kinds=("structure_recognition", "corrupted_data"),
                reject_any_flags=("missing_volume",),
                base_score=0.84,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)
        if "missing_volume" in flags:
            return 0.0
        if "eocd_bad" in flags and "local_header_recovery" not in flags:
            return 0.0
        if flags & {"data_descriptor", "compressed_size_bad", "bit3_data_descriptor"}:
            return 0.90
        if coverage.payload_only_suspected and "directory_rebuild" not in diagnosis.categories:
            return 0.15
        if coverage.directory_only_suspected:
            return 0.94
        if coverage.mixed_damage_suspected:
            return 0.88
        if flags & {"central_directory_bad", "central_directory_offset_bad", "central_directory_count_bad"} and flags & {
            "checksum_error", "crc_error", "damaged", "entry_payload_bad",
        }:
            return 0.97
        if flags & {"central_directory_offset_bad", "central_directory_count_bad"} and not (
            flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}
        ):
            return 0.0
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}:
            return 0.90
        if "content_recovery" in diagnosis.categories:
            return 0.85
        if "safe_repair" in diagnosis.categories:
            return 0.25
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)

        if "eocd_bad" in flags and "local_header_recovery" not in flags:
            return RepairResult(
                status="unrepairable", confidence=0.0, format="zip",
                module_name=self.spec.name, diagnosis=diagnosis.as_dict(),
                message="EOCD-only damage should be handled by fix_pointers first",
            )

        require_dd = bool(flags & {"data_descriptor", "compressed_size_bad", "bit3_data_descriptor"})
        candidate = Path(workspace) / "zip_rebuild.zip"
        scan = rebuild_zip_from_source(
            source_input_for_job(job), candidate,
            require_data_descriptor=require_dd, config=config,
        )

        if not scan.entries:
            return RepairResult(
                status="unrepairable", confidence=0.0, format="zip",
                module_name=self.spec.name, diagnosis=diagnosis.as_dict(),
                warnings=scan.warnings,
                message="no recoverable ZIP entries were found",
            )

        payload_damage_flags = {
            "checksum_error", "crc_error", "damaged", "entry_payload_bad", "payload_bad", "data_error",
        }
        partial = (
            not scan.complete
            or (coverage.known and scan.entries and coverage.has_missing_entries)
            or coverage.has_payload_damage
            or bool(flags & payload_damage_flags)
        )
        confidence = 0.72 if partial else 0.92
        confidence += coverage.score_hint(directory=0.04, mixed=-0.04, payload=-0.12)
        confidence = max(0.1, min(0.98, confidence))

        return RepairResult(
            status="partial" if partial else "repaired",
            confidence=confidence,
            format="zip",
            repaired_input={"kind": "file", "path": str(candidate), "format_hint": "zip"},
            actions=["scan_local_file_headers", "rebuild_zip_central_directory", "write_repaired_zip"],
            damage_flags=list(job.damage_flags),
            warnings=scan.warnings,
            workspace_paths=[str(candidate)],
            partial=partial,
            module_name=self.spec.name,
            diagnosis={
                **diagnosis.as_dict(),
                "archive_coverage": coverage.as_dict(),
                "coverage_strategy": "directory_rebuild" if not coverage.payload_only_suspected else "low_priority_payload_only",
            },
        )


# ── Operation 5: salvage ───────────────────────────────────────────
# Covers: Deep partial recovery, entry quarantine, verified entry salvage,
#         CD-local header reconcile, missing volume partial salvage
# Native: zip_deep_partial_recovery / zip_verified_entry_salvage /
#          zip_cd_local_header_reconcile_salvage

class ZipSalvage:
    spec = RepairModuleSpec(
        name="zip_salvage",
        formats=("zip",),
        categories=("content_recovery", "directory_rebuild", "boundary_repair"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("content_recovery", "directory_rebuild", "boundary_repair"),
                require_any_flags=(
                    "damaged", "crc_error", "checksum_error", "payload_damaged",
                    "entry_payload_bad", "corrupted_data", "local_header_recovery",
                    "central_directory_bad", "directory_integrity_bad_or_unknown",
                    "data_descriptor", "missing_volume",
                ),
                require_any_failure_kinds=("checksum_error", "corrupted_data", "data_error", "structure_recognition", "unexpected_end", "input_truncated"),
                reject_any_flags=("wrong_password",),
                base_score=0.88,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        coverage = coverage_view_from_job(job)

        # Missing volume is a strong signal for salvage
        if "missing_volume" in flags and "local_header_recovery" in flags:
            return 0.96

        # Reconcile mode: CD/local conflicts
        if flags & {"central_directory_offset_bad", "local_header_conflict"}:
            return 0.94

        # Standard salvage modes
        if coverage.mixed_damage_suspected:
            return 0.98
        if coverage.payload_only_suspected and coverage.low_yield_partial:
            return 0.97
        if coverage.payload_only_suspected:
            return 0.94
        if flags & {"crc_error", "checksum_error", "payload_damaged", "entry_payload_bad", "corrupted_data"}:
            return 0.92
        if flags & {"central_directory_bad", "directory_integrity_bad_or_unknown", "local_header_recovery"}:
            return 0.90
        if "content_recovery" in diagnosis.categories:
            return 0.96
        if "directory_rebuild" in diagnosis.categories:
            return 0.88
        if "boundary_repair" in diagnosis.categories:
            return 0.55
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        flags = set(job.damage_flags)
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}

        # Mode 1: Reconcile — CD/local header conflicts
        if flags & {"central_directory_offset_bad", "local_header_conflict"} and "local_header_recovery" in flags:
            return self._reconcile(job, diagnosis, workspace, config)

        # Mode 2: Entry quarantine — verification has problem names
        problem_names = verification_problem_names(job)
        if problem_names:
            return run_verified_entry_salvage(
                module_name=self.spec.name, job=job, diagnosis=diagnosis,
                workspace=workspace, config=config, exclude_names=problem_names,
                confidence=0.93,
                message="rebuilt ZIP from verified entries after quarantining names reported by verification",
            )

        # Mode 3: Missing volume salvage
        if "missing_volume" in flags and "local_header_recovery" in flags:
            return self._missing_volume_salvage(job, diagnosis, workspace, config)

        # Mode 4: Full deep partial recovery
        return self._deep_salvage(job, diagnosis, workspace, config)

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        """Generate multiple candidates for LTR ranking."""
        flags = set(job.damage_flags)
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        all_candidates = []

        # Reconciliation candidates (for CD/local conflicts)
        if flags & {"central_directory_offset_bad", "local_header_conflict"}:
            result = dict(zip_cd_local_header_reconcile_salvage(
                source_input_for_job(job), workspace,
                int(deep.get("max_entries", 20000) or 20000),
                float(deep.get("max_input_size_mb", 512) or 0),
                float(deep.get("max_output_size_mb", 2048) or 0),
                float(deep.get("max_entry_uncompressed_mb", 512) or 0),
                float(deep.get("max_seconds_per_module", 30.0) or 0),
            ))
            all_candidates.extend(candidates_from_native_result(
                self.spec.name, result, job, diagnosis,
                native_key="native_zip_salvage_reconcile",
                format_hint="zip", partial_default=True,
                default_confidence=0.88,
                default_message="ZIP salvage: CD entries reconciled against verified local headers",
            ))

        # Deep partial recovery candidates
        result = dict(zip_deep_partial_recovery(
            source_input_for_job(job), workspace,
            int(deep.get("max_candidates_per_module", 3) or 3),
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
            bool(deep.get("verify_candidates", True)),
        ))
        coverage = coverage_view_from_job(job)
        deep_candidates = candidates_from_native_result(
            self.spec.name, result, job, diagnosis,
            native_key="native_zip_salvage_deep",
            format_hint="zip", partial_default=True,
            default_confidence=0.70,
            default_message="ZIP salvage: deep partial recovery produced a candidate",
        )
        for c in deep_candidates:
            if int(c.diagnosis.get("native_candidate", {}).get("verified_entries") or 0) > 0:
                if coverage.known:
                    from dataclasses import replace
                    c = replace(c, confidence=min(0.99, float(c.confidence or 0.0) + coverage.score_hint(payload=0.04, mixed=0.05, partial=0.02)))
                all_candidates.append(c)

        # Quarantine candidates
        problem_names = verification_problem_names(job)
        if problem_names:
            qr = dict(zip_verified_entry_salvage(
                source_input_for_job(job), workspace, self.spec.name,
                problem_names,
                int(deep.get("max_entries", 20000) or 20000),
                float(deep.get("max_input_size_mb", 512) or 0),
                float(deep.get("max_output_size_mb", 2048) or 0),
                float(deep.get("max_entry_uncompressed_mb", 512) or 0),
                float(deep.get("max_seconds_per_module", 30.0) or 0),
            ))
            all_candidates.extend(candidates_from_native_result(
                self.spec.name, qr, job, diagnosis,
                native_key="native_zip_salvage_quarantine",
                format_hint="zip", partial_default=True,
                default_confidence=0.93,
                default_message="ZIP salvage: quarantined entries reported by verification",
            ))

        return all_candidates

    def _reconcile(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(zip_cd_local_header_reconcile_salvage(
            source_input_for_job(job), workspace,
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
        ))
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status in {"repaired", "partial"} and selected_path:
            coverage = coverage_view_from_job(job)
            return RepairResult(
                status="partial",
                confidence=min(0.995, 0.91 + coverage.score_hint(directory=0.04, mixed=0.04, partial=0.03)),
                format="zip",
                repaired_input={"kind": "file", "path": selected_path, "format_hint": "zip"},
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or []),
                partial=True,
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "archive_coverage": coverage.as_dict(), "native_zip_salvage_reconcile": result},
                message="rebuilt ZIP after cross-checking central directory entries against physical local headers",
            )
        return run_verified_entry_salvage(
            module_name=self.spec.name, job=job, diagnosis=diagnosis,
            workspace=workspace, config=config, confidence=0.88,
            message="rebuilt ZIP from verified local headers after CD/local reconcile fallback",
        )

    def _missing_volume_salvage(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(zip_deep_partial_recovery(
            source_input_for_job(job), workspace,
            int(deep.get("max_candidates_per_module", 3) or 3),
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
            bool(deep.get("verify_candidates", True)),
        ))
        candidates = candidates_from_native_result(
            self.spec.name, result, job, diagnosis,
            native_key="native_zip_salvage_missing_vol",
            format_hint="zip", partial_default=True,
            default_confidence=0.68,
            default_message="ZIP salvage: missing-volume partial salvage produced a candidate",
        )
        coverage = coverage_view_from_job(job)
        candidates = [
            __import__("dataclasses").replace(c, confidence=min(0.98, float(c.confidence or 0.0) + coverage.score_hint(directory=0.02, partial=0.04)))
            for c in candidates
            if int(c.diagnosis.get("native_candidate", {}).get("verified_entries") or 0) > 0
        ]
        if not candidates:
            return RepairResult(
                status="unrepairable", confidence=0.0, format="zip",
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_zip_salvage_missing_vol": result},
                message="ZIP salvage: missing-volume partial salvage did not produce a candidate",
            )
        return candidates[0].to_result(selection={"selected_module": self.spec.name})

    def _deep_salvage(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(zip_deep_partial_recovery(
            source_input_for_job(job), workspace,
            int(deep.get("max_candidates_per_module", 3) or 3),
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            float(deep.get("max_seconds_per_module", 30.0) or 0),
            bool(deep.get("verify_candidates", True)),
        ))
        coverage = coverage_view_from_job(job)
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")

        if int(result.get("encrypted_entries", 0) or 0) > 0 and (job.password is None or str(job.password) == ""):
            return RepairResult(
                status="needs_password", confidence=0.0, format="zip",
                module_name=self.spec.name, diagnosis=diagnosis.as_dict(),
                message="encrypted ZIP entries require a resolved password before salvage",
            )

        if status not in {"repaired", "partial"} or not selected_path:
            return RepairResult(
                status="unrepairable", confidence=0.0, format="zip",
                module_name=self.spec.name, diagnosis=diagnosis.as_dict(),
                message="ZIP salvage: deep recovery did not produce a candidate",
            )

        return RepairResult(
            status="partial",
            confidence=min(0.99, float(result.get("confidence") or 0.7) + coverage.score_hint(payload=0.04, mixed=0.05, partial=0.02)),
            format="zip",
            repaired_input={"kind": "file", "path": selected_path, "format_hint": "zip"},
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=True,
            module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), "archive_coverage": coverage.as_dict(), "native_zip_salvage_deep": result},
            message="ZIP salvage: deep partial recovery produced a candidate",
        )


# ── Operation 6: resolve_conflicts ─────────────────────────────────
# Covers: Duplicate entries, overlapping entries, local header conflicts
# Native: zip_conflict_resolver_rebuild

class ZipResolveConflicts:
    spec = RepairModuleSpec(
        name="zip_resolve_conflicts",
        formats=("zip",),
        categories=("directory_rebuild", "content_recovery"),
        stage="deep",
        safe=True,
        partial=True,
        routes=(
            RepairRoute(
                formats=("zip",),
                require_any_categories=("directory_rebuild", "content_recovery"),
                require_any_flags=("duplicate_entries", "overlapping_entries", "local_header_conflict"),
                require_any_failure_kinds=("structure_recognition", "corrupted_data", "checksum_error"),
                reject_any_flags=("trailing_junk", "boundary_unreliable", "missing_volume"),
                base_score=0.90,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"duplicate_entries", "overlapping_entries", "local_header_conflict"}:
            return 0.96
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict) -> RepairResult:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(zip_conflict_resolver_rebuild(
            source_input_for_job(job), workspace,
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            bool(deep.get("verify_candidates", True)),
        ))
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status in {"repaired", "partial"} and selected_path:
            return RepairResult(
                status="partial",
                confidence=float(result.get("confidence") or 0.74),
                format="zip",
                repaired_input={"kind": "file", "path": selected_path, "format_hint": "zip"},
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or [selected_path]),
                partial=True,
                module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_zip_resolve_conflicts": result},
                message="ZIP duplicate/overlapping entry conflicts were resolved into a clean candidate",
            )
        return RepairResult(
            status="unrepairable", confidence=0.0, format="zip",
            module_name=self.spec.name, diagnosis={**diagnosis.as_dict(), "native_zip_resolve_conflicts": result},
            message="ZIP conflict resolver did not produce a candidate",
        )

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        result = dict(zip_conflict_resolver_rebuild(
            source_input_for_job(job), workspace,
            int(deep.get("max_entries", 20000) or 20000),
            float(deep.get("max_input_size_mb", 512) or 0),
            float(deep.get("max_output_size_mb", 2048) or 0),
            float(deep.get("max_entry_uncompressed_mb", 512) or 0),
            bool(deep.get("verify_candidates", True)),
        ))
        return candidates_from_native_result(
            self.spec.name, result, job, diagnosis,
            native_key="native_zip_resolve_conflicts",
            format_hint="zip", partial_default=True,
            default_confidence=0.74,
            default_message="ZIP conflict resolver produced a candidate",
        )


# ── Register all operations ────────────────────────────────────────
register_repair_module(ZipFixBoundary())
register_repair_module(ZipFixPointers())
register_repair_module(ZipFix64())
register_repair_module(ZipRebuild())
register_repair_module(ZipSalvage())
register_repair_module(ZipResolveConflicts())
