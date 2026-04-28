from __future__ import annotations

from smart_unpacker.repair.diagnosis import RepairDiagnosis
from smart_unpacker.repair.job import RepairJob
from smart_unpacker.repair.pipeline.module import RepairModuleSpec, RepairRoute
from smart_unpacker.repair.pipeline.modules._common import patch_plan_for_crop_append, source_input_for_job
from smart_unpacker.repair.pipeline.modules.archive_carrier_crop import _result_from_native
from smart_unpacker.repair.pipeline.modules._native_candidates import candidates_from_native_result
from smart_unpacker.repair.pipeline.registry import register_repair_module

from smart_unpacker_native import rar_end_block_repair as _native_rar_end_block_repair


class RarEndBlockRepair:
    spec = RepairModuleSpec(
        name="rar_end_block_repair",
        formats=("rar",),
        categories=("boundary_repair",),
        stage="deep",
        safe=True,
        routes=(
            RepairRoute(
                formats=("rar",),
                require_any_categories=("boundary_repair",),
                require_any_flags=("missing_end_block", "probably_truncated", "unexpected_end", "boundary_unreliable"),
                require_any_failure_kinds=("unexpected_end",),
                base_score=0.78,
            ),
        ),
    )

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        flags = set(job.damage_flags)
        if flags & {"missing_end_block", "probably_truncated", "unexpected_end", "boundary_unreliable"}:
            return 0.84
        if "boundary_repair" in diagnosis.categories:
            return 0.68
        return 0.0

    def repair(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        return _result_from_native(self.spec.name, result, job, diagnosis, config)

    def generate_candidates(self, job: RepairJob, diagnosis: RepairDiagnosis, workspace: str, config: dict):
        result = self._run_native(job, workspace, config)
        if bool(config.get("virtual_patch_candidate")):
            _attach_rar_end_block_patch_plans(result, job, self.spec.name)
        return candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key="native_archive_deep_repair",
            format_hint="rar",
            default_confidence=0.8,
            default_message="RAR end-block repair produced a candidate",
            prefer_patch_plan=bool(config.get("virtual_patch_candidate")),
        )

    def _run_native(self, job: RepairJob, workspace: str, config: dict) -> dict:
        deep = config.get("deep") if isinstance(config.get("deep"), dict) else {}
        return _native_rar_end_block_repair(
            source_input_for_job(job),
            workspace,
            float(deep.get("max_input_size_mb", 512) or 0),
            int(deep.get("max_candidates_per_module", 8) or 1),
        )


register_repair_module(RarEndBlockRepair())


def _attach_rar_end_block_patch_plans(result: dict, job: RepairJob, module_name: str) -> None:
    for item in result.get("candidates") or []:
        if not isinstance(item, dict) or isinstance(item.get("patch_plan"), dict):
            continue
        actions = list(item.get("actions") or result.get("actions") or [])
        end_block = _rar_end_block_for_actions(actions)
        if not end_block:
            continue
        try:
            start = int(item.get("offset") or 0)
            output_end = int(item.get("end_offset") or 0)
        except (TypeError, ValueError):
            continue
        source_end = output_end - len(end_block)
        if source_end < start:
            continue
        confidence = float(item.get("confidence", result.get("confidence", 0.0)) or 0.0)
        item["patch_plan"] = patch_plan_for_crop_append(
            job,
            module_name,
            start,
            source_end,
            end_block,
            confidence=confidence,
            actions=actions,
        ).to_dict()


def _rar_end_block_for_actions(actions: list[str]) -> bytes:
    if "append_rar4_end_block" in actions:
        return _rar4_end_block()
    if "append_rar5_end_block" in actions:
        return _rar5_end_block()
    return b""


def _rar4_end_block() -> bytes:
    body = b"\x7b\x00\x00\x07\x00"
    import zlib

    return (zlib.crc32(body) & 0xFFFF).to_bytes(2, "little") + body


def _rar5_end_block() -> bytes:
    header_data = b"\x02\x05\x00"
    import zlib

    return (zlib.crc32(header_data) & 0xFFFFFFFF).to_bytes(4, "little") + header_data
