from packrelic.analysis.structure_pipeline.module import AnalysisModuleSpec
from packrelic.analysis.structure_pipeline.registry import register_analysis_module
from packrelic.analysis.structure_pipeline.modules._boundaries import next_archive_boundary
from packrelic.analysis.structure_pipeline.modules._fuzzy import apply_fuzzy_routes
from packrelic.analysis.result import ArchiveFormatEvidence, ArchiveSegment


class RarAnalysisModule:
    spec = AnalysisModuleSpec(name="rar", formats=("rar",), signatures=(b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"))

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if str(hit.get("name", "")).startswith("rar")]
        if not hits:
            return ArchiveFormatEvidence(format="rar", confidence=0.0, status="not_found")
        start = min(hit["offset"] for hit in hits)
        native = view.probe_rar(start_offset=start, max_blocks_to_walk=int(config.get("max_blocks_to_walk", 4096) or 4096))
        return self._from_native(dict(native), start, next_archive_boundary(prepass, start, view.size), prepass, view.size)

    def _from_native(self, native: dict, start: int, boundary: int, prepass: dict, file_size: int) -> ArchiveFormatEvidence:
        if not native.get("magic_matched"):
            return ArchiveFormatEvidence(format="rar", confidence=0.0, status="not_found", details=native)
        evidence = list(native.get("evidence") or ["rar:signature"])
        strong = bool(native.get("strong_accept"))
        plausible = bool(native.get("plausible"))
        error = str(native.get("error") or "")
        taxonomy = self._classify_damage(native)
        segment_end = int(native.get("segment_end") or 0) or boundary
        if strong:
            status = "extractable"
            confidence = 0.97
        elif taxonomy == "probably_truncated":
            status = "damaged"
            confidence = 0.82
            segment_end = None
        elif taxonomy == "valid_encrypted_but_unwalkable":
            status = "damaged"
            confidence = 0.72
            segment_end = None
        elif plausible:
            status = "damaged"
            confidence = 0.65
        else:
            status = "weak"
            confidence = 0.35
        damage_flags = []
        if error:
            damage_flags.append(str(error))
        if taxonomy:
            damage_flags.append(taxonomy)
        native.setdefault("boundary_confidence", "high" if strong else ("low" if taxonomy else "unknown"))
        native.setdefault("integrity_confidence", "unknown")
        if taxonomy == "probably_truncated":
            native["boundary_confidence"] = "low"
            native["recovery_strategy"] = "block_chain_prefix"
        elif taxonomy == "valid_encrypted_but_unwalkable":
            native["boundary_confidence"] = "low"
            native["password_required"] = True
            native["header_encrypted"] = True
        apply_fuzzy_routes(
            native,
            evidence,
            damage_flags,
            prepass,
            start_offset=start,
            end_offset=segment_end,
            file_size=file_size,
            format_hint="rar",
        )
        return ArchiveFormatEvidence(
            format="rar",
            confidence=confidence,
            status=status,
            segments=[ArchiveSegment(start_offset=start, end_offset=segment_end, confidence=confidence, damage_flags=damage_flags, evidence=evidence)],
            warnings=[] if strong else self._warnings_for_taxonomy(taxonomy),
            details=native,
        )

    def _classify_damage(self, native: dict) -> str:
        error = str(native.get("error") or "")
        blocks_checked = int(native.get("blocks_checked") or 0)
        if error in {"rar4_block_header_out_of_range", "rar5_block_header_out_of_range"} and blocks_checked > 0:
            return "probably_truncated"
        if error in {"rar5_main_header_missing", "rar4_main_header_missing"}:
            return "valid_encrypted_but_unwalkable"
        return ""

    def _warnings_for_taxonomy(self, taxonomy: str) -> list[str]:
        if taxonomy == "probably_truncated":
            return ["rar block chain is incomplete; archive is probably truncated"]
        if taxonomy == "valid_encrypted_but_unwalkable":
            return ["rar header appears encrypted or unreadable; password is required before boundary walk"]
        return ["rar segment end inferred from next archive signature or EOF"]


register_analysis_module(RarAnalysisModule())
