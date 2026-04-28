from smart_unpacker.analysis.structure_pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.structure_pipeline.registry import register_analysis_module
from smart_unpacker.analysis.structure_pipeline.modules._boundaries import next_archive_boundary
from smart_unpacker.analysis.structure_pipeline.modules._fuzzy import apply_fuzzy_routes
from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment


class SevenZipAnalysisModule:
    spec = AnalysisModuleSpec(name="seven_zip", formats=("7z",), signatures=(b"7z\xbc\xaf\x27\x1c",))

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if hit.get("name") == "7z"]
        if not hits:
            return ArchiveFormatEvidence(format="7z", confidence=0.0, status="not_found")
        start = min(hit["offset"] for hit in hits)
        native = view.probe_seven_zip(
            start_offset=start,
            max_next_header_check_bytes=int(config.get("max_next_header_check_bytes", 1024 * 1024) or 1024 * 1024),
        )
        return self._from_native(dict(native), start, next_archive_boundary(prepass, start, view.size), prepass, view.size)

    def _from_native(self, native: dict, start: int, boundary: int, prepass: dict, file_size: int) -> ArchiveFormatEvidence:
        if not native.get("magic_matched"):
            return ArchiveFormatEvidence(format="7z", confidence=0.0, status="not_found", details=native)
        evidence = list(native.get("evidence") or ["7z:signature"])
        strong = bool(native.get("strong_accept"))
        plausible = bool(native.get("plausible"))
        if strong:
            status = "extractable"
            confidence = 0.97
        elif plausible:
            status = "damaged"
            confidence = 0.65
        else:
            status = "weak"
            confidence = 0.35
        damage_flags = []
        error = str(native.get("error") or "")
        if error:
            damage_flags.append(str(error))
        boundary_unreliable = error in {"start_header_crc_mismatch", "next_header_out_of_range", "invalid_next_header_range"}
        if boundary_unreliable:
            damage_flags.append("boundary_unreliable")
            native["boundary_confidence"] = "none"
        elif native.get("next_header_crc_checked") and not native.get("next_header_crc_ok"):
            damage_flags.append("directory_integrity_bad_or_unknown")
            native["boundary_confidence"] = "medium"
            native["integrity_confidence"] = "low"
        else:
            native.setdefault("boundary_confidence", "high" if strong else "medium")
            native.setdefault("integrity_confidence", "medium" if strong else "unknown")
        next_header_offset = int(native.get("next_header_offset") or 0)
        next_header_size = int(native.get("next_header_size") or 0)
        end_offset = int(native.get("segment_end") or 0) or (start + 32 + next_header_offset + next_header_size if next_header_size else None)
        if boundary_unreliable:
            end_offset = None
        apply_fuzzy_routes(
            native,
            evidence,
            damage_flags,
            prepass,
            start_offset=start,
            end_offset=end_offset,
            file_size=file_size,
            format_hint="7z",
        )
        return ArchiveFormatEvidence(
            format="7z",
            confidence=confidence,
            status=status,
            segments=[ArchiveSegment(start_offset=start, end_offset=end_offset, confidence=confidence, damage_flags=damage_flags, evidence=evidence)],
            warnings=[] if end_offset or boundary_unreliable else ["7z segment end inferred from next archive signature or EOF"],
            details=native,
        )


register_analysis_module(SevenZipAnalysisModule())
