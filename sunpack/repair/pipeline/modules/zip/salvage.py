from __future__ import annotations

from dataclasses import replace

from sunpack.repair.coverage import coverage_view_from_job
from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._common import source_input_for_job, module_limits
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.pipeline.registry import register_repair_module
from sunpack.repair.result import RepairResult
from sunpack_native import (
    zip_deep_partial_recovery as _native_zip_deep_partial_recovery,
    zip_verified_entry_salvage as _native_zip_verified_entry_salvage,
    zip_cd_local_header_reconcile_salvage as _native_zip_cd_local_header_reconcile,
)

from ._entry_salvage import run_verified_entry_salvage, verification_problem_names


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
        if "missing_volume" in flags and "local_header_recovery" in flags:
            return 0.96
        if flags & {"central_directory_offset_bad", "local_header_conflict"}:
            return 0.94
        if coverage.mixed_damage_suspected:
            return 0.98
        if coverage.payload_only_suspected and coverage.low_yield_partial:
            return 0.97
        if coverage.payload_only_suspected:
            return 0.94
        # store method: no compression to validate against, lower confidence but still try
        if not flags & {"data_descriptor", "compressed_size_bad", "bit3_data_descriptor"} and flags & {"crc_error", "checksum_error", "entry_payload_bad", "corrupted_data"}:
            return 0.78
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
        limits = module_limits(config)

        # Mode 1: Reconcile
        if flags & {"central_directory_offset_bad", "local_header_conflict"} and "local_header_recovery" in flags:
            return self._reconcile(job, diagnosis, workspace, config)

        # Mode 2: Quarantine by verification
        problem_names = verification_problem_names(job)
        if problem_names:
            return run_verified_entry_salvage(
                module_name=self.spec.name, job=job, diagnosis=diagnosis,
                workspace=workspace, config=config, exclude_names=problem_names,
                confidence=0.93,
                message="rebuilt ZIP from verified entries after quarantining names reported by verification",
            )

        # Mode 3: Missing volume
        if "missing_volume" in flags and "local_header_recovery" in flags:
            return self._missing_volume_salvage(job, diagnosis, workspace, config)

        # Mode 4: Deep partial recovery
        result = self._deep_salvage(job, diagnosis, workspace, config)
        if result.ok or result.status != "unrepairable":
            return result
        # Fallback: try lightweight salvage even when deep recovery fails
        return self._lightweight_salvage(job, diagnosis, workspace, config)

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        flags = set(job.damage_flags)
        limits = module_limits(config)
        all_candidates = []

        # Reconciliation candidates
        if flags & {"central_directory_offset_bad", "local_header_conflict"}:
            result = dict(_native_zip_cd_local_header_reconcile(
                source_input_for_job(job), workspace,
                int(limits.get("max_entries", 20000) or 20000),
                float(limits.get("max_input_size_mb", 512) or 0),
                float(limits.get("max_output_size_mb", 2048) or 0),
                float(limits.get("max_entry_uncompressed_mb", 512) or 0),
                float(limits.get("max_seconds_per_module", 30.0) or 0),
            ))
            all_candidates.extend(candidates_from_native_result(
                self.spec.name, result, job, diagnosis,
                native_key="native_zip_salvage_reconcile",
                format_hint="zip", partial_default=True, default_confidence=0.88,
            ))

        # Deep partial candidates
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
        for c in candidates_from_native_result(
            self.spec.name, result, job, diagnosis,
            native_key="native_zip_salvage_deep",
            format_hint="zip", partial_default=True, default_confidence=0.70,
        ):
            if int(c.diagnosis.get("native_candidate", {}).get("verified_entries") or 0) > 0 or int(c.diagnosis.get("native_candidate", {}).get("entries") or 0) > 0:
                if coverage.known:
                    c = replace(c, confidence=min(0.99, float(c.confidence or 0.0) + coverage.score_hint(payload=0.04, mixed=0.05, partial=0.02)))
                all_candidates.append(c)

        # Quarantine candidates
        problem_names = verification_problem_names(job)
        if problem_names:
            qr = dict(_native_zip_verified_entry_salvage(
                source_input_for_job(job), workspace, self.spec.name,
                problem_names,
                int(limits.get("max_entries", 20000) or 20000),
                float(limits.get("max_input_size_mb", 512) or 0),
                float(limits.get("max_output_size_mb", 2048) or 0),
                float(limits.get("max_entry_uncompressed_mb", 512) or 0),
                float(limits.get("max_seconds_per_module", 30.0) or 0),
            ))
            all_candidates.extend(candidates_from_native_result(
                self.spec.name, qr, job, diagnosis,
                native_key="native_zip_salvage_quarantine",
                format_hint="zip", partial_default=True, default_confidence=0.93,
            ))

        return all_candidates

    def _reconcile(self, job, diagnosis, workspace, config):
        limits = module_limits(config)
        result = dict(_native_zip_cd_local_header_reconcile(
            source_input_for_job(job), workspace,
            int(limits.get("max_entries", 20000) or 20000),
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_output_size_mb", 2048) or 0),
            float(limits.get("max_entry_uncompressed_mb", 512) or 0),
            float(limits.get("max_seconds_per_module", 30.0) or 0),
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
                partial=True, module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "archive_coverage": coverage.as_dict(), "native_zip_salvage_reconcile": result},
                message="rebuilt ZIP after cross-checking CD entries against physical local headers",
            )
        return run_verified_entry_salvage(
            module_name=self.spec.name, job=job, diagnosis=diagnosis,
            workspace=workspace, config=config, confidence=0.88,
            message="rebuilt ZIP from verified local headers after CD/local reconcile fallback",
        )

    def _missing_volume_salvage(self, job, diagnosis, workspace, config):
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
        candidates = candidates_from_native_result(
            self.spec.name, result, job, diagnosis,
            native_key="native_zip_salvage_missing_vol",
            format_hint="zip", partial_default=True, default_confidence=0.68,
        )
        coverage = coverage_view_from_job(job)
        for i in range(len(candidates)):
            candidates[i] = replace(candidates[i],
                confidence=min(0.98, float(candidates[i].confidence or 0.0) + coverage.score_hint(directory=0.02, partial=0.04)),
            )
        candidates = [c for c in candidates if int(c.diagnosis.get("native_candidate", {}).get("verified_entries") or 0) > 0 or int(c.diagnosis.get("native_candidate", {}).get("entries") or 0) > 0]
        if not candidates:
            return RepairResult(
                status="unrepairable", confidence=0.0, format="zip",
                module_name=self.spec.name, diagnosis={**diagnosis.as_dict(), "native_zip_salvage_missing_vol": result},
                message="missing-volume partial salvage did not produce a candidate",
            )
        return candidates[0].to_result(selection={"selected_module": self.spec.name})

    def _deep_salvage(self, job, diagnosis, workspace, config):
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
                message="deep recovery did not produce a candidate",
            )

        coverage = coverage_view_from_job(job)
        return RepairResult(
            status="partial",
            confidence=min(0.99, float(result.get("confidence") or 0.7) + coverage.score_hint(payload=0.04, mixed=0.05, partial=0.02)),
            format="zip",
            repaired_input={"kind": "file", "path": selected_path, "format_hint": "zip"},
            actions=list(result.get("actions") or []),
            damage_flags=list(job.damage_flags),
            warnings=list(result.get("warnings") or []),
            workspace_paths=list(result.get("workspace_paths") or []),
            partial=True, module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), "archive_coverage": coverage.as_dict(), "native_zip_salvage_deep": result},
            message="deep partial recovery produced a candidate",
        )


    def _lightweight_salvage(self, job, diagnosis, workspace, config):
        """Fallback: try verified entry salvage with empty quarantine list when deep recovery fails."""
        limits = module_limits(config)
        result = dict(_native_zip_verified_entry_salvage(
            source_input_for_job(job), workspace, self.spec.name,
            [],
            int(limits.get("max_entries", 20000) or 20000),
            float(limits.get("max_input_size_mb", 512) or 0),
            float(limits.get("max_output_size_mb", 2048) or 0),
            float(limits.get("max_entry_uncompressed_mb", 512) or 0),
            float(limits.get("max_seconds_per_module", 30.0) or 0),
        ))
        status = str(result.get("status") or "unrepairable")
        selected_path = str(result.get("selected_path") or "")
        if status in {"repaired", "partial"} and selected_path:
            return RepairResult(
                status="partial", confidence=0.65, format="zip",
                repaired_input={"kind": "file", "path": selected_path, "format_hint": "zip"},
                actions=list(result.get("actions") or []),
                damage_flags=list(job.damage_flags),
                warnings=list(result.get("warnings") or []),
                workspace_paths=list(result.get("workspace_paths") or []),
                partial=True, module_name=self.spec.name,
                diagnosis={**diagnosis.as_dict(), "native_zip_salvage_lightweight": result},
                message="lightweight salvage produced a candidate",
            )
        return RepairResult(
            status="unrepairable", confidence=0.0, format="zip",
            module_name=self.spec.name, diagnosis=diagnosis.as_dict(),
            message="lightweight salvage did not produce a candidate",
        )

# Legacy coarse module kept for historical imports only. ZIP repair registration
# now happens through atomic.py.
