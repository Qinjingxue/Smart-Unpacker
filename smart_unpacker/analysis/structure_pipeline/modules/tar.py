from smart_unpacker.analysis.structure_pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.structure_pipeline.registry import register_analysis_module
from smart_unpacker.analysis.structure_pipeline.modules._fuzzy import apply_fuzzy_routes
from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment


class TarAnalysisModule:
    spec = AnalysisModuleSpec(name="tar", formats=("tar",), signatures=(b"ustar",), io_profile="head_heavy")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        max_entries = int(config.get("max_entries_to_walk", 64) or 64)
        candidates = [0]
        candidates.extend(max(0, int(hit.get("offset") or 0) - 257) for hit in prepass.get("hits", []) if hit.get("name") == "tar_ustar")
        for start in sorted(set(candidates)):
            result = view.probe_tar(start_offset=start, max_entries_to_walk=max_entries)
            if result and result.get("plausible"):
                confidence = 0.94 if result.get("end_zero_blocks") else 0.86
                details = dict(result)
                evidence = list(result.get("evidence") or [])
                damage_flags = []
                apply_fuzzy_routes(
                    details,
                    evidence,
                    damage_flags,
                    prepass,
                    start_offset=start,
                    end_offset=result.get("segment_end"),
                    file_size=int(view.size),
                    format_hint="tar",
                )
                return ArchiveFormatEvidence(
                    format="tar",
                    confidence=confidence,
                    status="extractable",
                    segments=[ArchiveSegment(start_offset=start, end_offset=result.get("segment_end"), confidence=confidence, damage_flags=damage_flags, evidence=evidence)],
                    details=details,
                )
        return ArchiveFormatEvidence(format="tar", confidence=0.0, status="not_found")


register_analysis_module(TarAnalysisModule())
