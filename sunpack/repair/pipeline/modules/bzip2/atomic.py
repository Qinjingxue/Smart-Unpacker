from __future__ import annotations

import bz2
from typing import Iterable

from sunpack.repair.diagnosis import RepairDiagnosis
from sunpack.repair.job import RepairJob
from sunpack.repair.pipeline.module import RepairModuleSpec, RepairRoute
from sunpack.repair.pipeline.modules._python_atomic import AtomicMutation, PythonAtomicRepair
from sunpack.repair.pipeline.registry import register_repair_module


class Bzip2BlockSizeHeaderRepair(PythonAtomicRepair):
    spec = RepairModuleSpec(
        name="bzip2_block_size_header_repair",
        formats=("bzip2", "bz2"),
        categories=("safe_repair", "header_repair"),
        stage="targeted",
        safe=True,
        atomic=True,
        route_family="bzip2_stream_header",
        routes=(
            RepairRoute(
                formats=("bzip2", "bz2"),
                require_any_flags=("bzip2_header_bad", "bzip2_block_size_bad", "header_field_bad"),
                require_any_failure_kinds=("structure_recognition", "corrupted_data", "data_error"),
                base_score=0.78,
            ),
        ),
    )
    format_hint = "bzip2"
    output_extension = "bz2"
    native_key = "python_bzip2_block_size_header_repair"
    default_message = "BZIP2 block-size header repair produced validated candidates"

    def can_handle(self, job: RepairJob, diagnosis: RepairDiagnosis, config: dict) -> float:
        if set(job.damage_flags) & set(self.spec.routes[0].require_any_flags):
            return 0.82
        return 0.0

    def mutations(self, data: bytes, config: dict) -> Iterable[AtomicMutation]:
        if len(data) < 10 or data[:3] != b"BZh" or data[3:4] in b"123456789":
            return
        max_decode = int(float(config.get("max_bzip2_header_probe_mb", 64) or 64) * 1024 * 1024)
        for level in range(1, 10):
            repaired = bytearray(data)
            repaired[3] = ord("0") + level
            try:
                decoded = bz2.decompress(repaired)
            except (OSError, EOFError, ValueError):
                continue
            if max_decode > 0 and len(decoded) > max_decode:
                continue
            yield AtomicMutation(
                name=f"bzip2_block_size_{level}",
                data=bytes(repaired),
                action=f"repair_bzip2_block_size_header={level}",
                confidence=0.9,
                details={
                    "original_block_size_byte": data[3],
                    "block_size_100k": level,
                    "decoded_size": len(decoded),
                    "full_stream_validation": True,
                    "mutation_scope": "stream_header_field",
                },
            )


register_repair_module(Bzip2BlockSizeHeaderRepair())
