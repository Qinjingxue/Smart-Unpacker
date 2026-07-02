from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.modules._common import (
    load_source_bytes,
    module_limits,
    source_input_for_job,
    write_candidate,
)
from sunpack.repair.pipeline.modules._native_candidates import candidates_from_native_result
from sunpack.repair.result import RepairResult


@dataclass(frozen=True)
class AtomicMutation:
    name: str
    data: bytes
    action: str
    confidence: float
    details: dict[str, Any]
    partial: bool = False


class PythonAtomicRepair:
    """Small field-level repair base used when a native rewrite is unnecessary.

    Each returned mutation must represent one independently verifiable repair
    hypothesis.  A module may return several parameterized candidates, but it
    must not combine unrelated hypotheses in one candidate.
    """

    spec: Any
    format_hint = "archive"
    output_extension = "bin"
    native_key = "python_atomic_repair"
    default_message = "atomic repair produced a candidate"

    def repair(
        self,
        job: RepairJob,
        diagnosis: RepairDiagnosis,
        workspace: str,
        config: dict,
    ) -> RepairResult:
        candidates = self.generate_candidates(job, diagnosis, workspace, config)
        if candidates:
            return candidates[0].to_result(selection={"selected_module": self.spec.name})
        return RepairResult(
            status="unrepairable",
            confidence=0.0,
            format=self.format_hint,
            damage_flags=list(job.damage_flags),
            module_name=self.spec.name,
            diagnosis={**diagnosis.as_dict(), self.native_key: {"status": "no_candidate"}},
            message=f"{self.spec.name} found no independently verifiable mutation",
        )

    def generate_candidates(
        self,
        job: RepairJob,
        diagnosis: RepairDiagnosis,
        workspace: str,
        config: dict,
    ):
        source_input = source_input_for_job(job)
        try:
            data = load_source_bytes(source_input)
        except (OSError, ValueError, KeyError) as exc:
            result = {"status": "unrepairable", "message": str(exc), "candidates": []}
        else:
            limits = module_limits(config)
            runtime_config = {**config, **limits}
            max_bytes = int(float(limits.get("max_input_size_mb", 512) or 0) * 1024 * 1024)
            if max_bytes > 0 and len(data) > max_bytes:
                result = {
                    "status": "skipped",
                    "message": "atomic field repair input exceeds configured limit",
                    "candidates": [],
                }
            else:
                result = self._materialize_mutations(data, workspace, runtime_config)
        return candidates_from_native_result(
            self.spec.name,
            result,
            job,
            diagnosis,
            native_key=self.native_key,
            format_hint=self.format_hint,
            partial_default=bool(getattr(self.spec, "partial", False)),
            default_confidence=0.8,
            default_message=self.default_message,
            repair_name=self.spec.name,
            atomic_action_group=self.spec.name,
        )

    def _materialize_mutations(self, data: bytes, workspace: str, config: dict) -> dict[str, Any]:
        limit = max(1, int(config.get("max_candidates_per_module", 8) or 1))
        candidates: list[dict[str, Any]] = []
        for index, mutation in enumerate(self.mutations(data, config)):
            if index >= limit:
                break
            filename = f"{self.spec.name}_{index + 1}.{self.output_extension}"
            path = write_candidate(mutation.data, workspace, filename)
            candidates.append(
                {
                    "name": mutation.name,
                    "path": path,
                    "format": self.format_hint,
                    "status": "partial" if mutation.partial else "repaired",
                    "confidence": mutation.confidence,
                    "actions": [mutation.action],
                    "validation_details": dict(mutation.details),
                    "patch_facts": [mutation.action],
                    "candidate_status": "materialized",
                }
            )
        status = "repaired" if candidates else "unrepairable"
        if candidates and all(item["status"] == "partial" for item in candidates):
            status = "partial"
        return {
            "status": status,
            "format": self.format_hint,
            "native_target": self.spec.name,
            "candidate_status": "materialized" if candidates else "no_candidate",
            "candidates": candidates,
            "confidence": max((float(item["confidence"]) for item in candidates), default=0.0),
            "message": self.default_message if candidates else "no valid atomic mutation found",
            "workspace_paths": [item["path"] for item in candidates],
        }

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        raise NotImplementedError
