from sunpack.analysis.structure_pipeline.module import AnalysisModuleSpec
from sunpack.analysis.structure_pipeline.modules._read_fault import read_fault_damage_flags
from sunpack.analysis.structure_pipeline.registry import register_analysis_module
from sunpack.analysis.structure_pipeline.modules._fuzzy import apply_fuzzy_routes
from sunpack.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.analysis.structure_pipeline.modules._combine import combine_format_candidates
from sunpack.analysis.probes.tar import TarProbeOptions, probe_tar_view


class TarAnalysisModule:
    spec = AnalysisModuleSpec(name="tar", formats=("tar",), signatures=(b"ustar",), io_profile="head_heavy")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        max_entries = int(config.get("max_entries_to_walk", 64) or 64)
        candidates = [0]
        candidates.extend(max(0, int(hit.get("offset") or 0) - 257) for hit in prepass.get("hits", []) if hit.get("name") == "tar_ustar")
        evidences = []
        for start in sorted(set(candidates)):
            result = probe_tar_view(
                view,
                TarProbeOptions(start_offset=start, max_entries_to_walk=max_entries),
            ).to_raw_dict()
            if result and result.get("plausible"):
                confidence = 0.94 if result.get("end_zero_blocks") else 0.86
                details = dict(result)
                evidence = list(result.get("evidence") or [])
                damage_flags = read_fault_damage_flags(result)
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
                evidences.append(ArchiveFormatEvidence(
                    format="tar",
                    confidence=confidence,
                    status="extractable",
                    segments=[ArchiveSegment(start_offset=start, end_offset=result.get("segment_end"), confidence=confidence, damage_flags=damage_flags, evidence=evidence)],
                    details=details,
                ))
                continue
            if result and result.get("magic_matched"):
                details = dict(result)
                damage_flags = read_fault_damage_flags(result) or ["tar_metadata_bad"]
                evidences.append(ArchiveFormatEvidence(
                    format="tar", confidence=0.72, status="damaged",
                    segments=[ArchiveSegment(start_offset=start, end_offset=None, confidence=0.72,
                                             damage_flags=damage_flags, evidence=list(result.get("evidence") or ["tar:header"]))],
                    details={**details, "route_evidence_flags": damage_flags},
                ))
        return combine_format_candidates("tar", evidences, preserve_multiple=prepass.get("source") == "embedded_scan")
register_analysis_module(TarAnalysisModule())
