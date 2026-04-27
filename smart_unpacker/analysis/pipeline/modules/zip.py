from smart_unpacker.analysis.pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.pipeline.registry import register_analysis_module
from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment

try:
    from smart_unpacker_native import inspect_zip_eocd_structure as _inspect_zip_eocd_structure
except (ImportError, AttributeError):
    _inspect_zip_eocd_structure = None


class ZipAnalysisModule:
    spec = AnalysisModuleSpec(name="zip", formats=("zip",), signatures=(b"PK\x03\x04", b"PK\x05\x06"), io_profile="tail_heavy")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if str(hit.get("name", "")).startswith("zip_")]
        if not hits:
            return ArchiveFormatEvidence(format="zip", confidence=0.0, status="not_found")

        max_entries = int(config.get("max_cd_entries_to_walk", 64) or 64)
        eocd_hits = [int(hit["offset"]) for hit in hits if hit.get("name") == "zip_eocd"]
        native = None
        if eocd_hits and hasattr(view, "probe_zip"):
            for eocd_offset in sorted(eocd_hits, reverse=True):
                candidate = view.probe_zip(eocd_offset=eocd_offset, max_cd_entries_to_walk=max_entries)
                if candidate and candidate.get("plausible"):
                    native = candidate
                    break
            if native is None:
                native = view.probe_zip(eocd_offset=max(eocd_hits), max_cd_entries_to_walk=max_entries)
        if native is None and _inspect_zip_eocd_structure:
            native = _inspect_zip_eocd_structure(str(view.path), max_entries)
        if native and (native.get("magic_matched") or native.get("plausible")):
            return self._from_native(view, dict(native), hits)

        local_hits = [hit["offset"] for hit in hits if hit.get("name") == "zip_local"]
        start = min(local_hits or [hits[0]["offset"]])
        end = None
        evidence = []
        confidence = 0.45
        status = "weak"
        if local_hits:
            evidence.append("local_header")
            confidence += 0.25
        if eocd_hits:
            evidence.append("eocd")
            eocd = max(eocd_hits)
            end = min(view.size, eocd + 22)
            confidence += 0.25
        if local_hits and eocd_hits:
            status = "extractable"
            confidence = 0.95
        elif local_hits or eocd_hits:
            status = "damaged"

        return ArchiveFormatEvidence(
            format="zip",
            confidence=min(confidence, 1.0),
            status=status,
            segments=[ArchiveSegment(start_offset=start, end_offset=end, confidence=min(confidence, 1.0), evidence=evidence)],
        )

    def _from_native(self, view, native: dict, hits: list[dict]) -> ArchiveFormatEvidence:
        if not native.get("magic_matched") and not hits:
            return ArchiveFormatEvidence(format="zip", confidence=0.0, status="not_found", details=native)

        archive_offset = int(native.get("archive_offset") or 0)
        eocd_offset = int(native.get("eocd_offset") or 0)
        comment_length = int(native.get("comment_length") or 0)
        end_offset = eocd_offset + 22 + comment_length if eocd_offset else None
        evidence = list(native.get("evidence") or [])
        if native.get("central_directory_present"):
            evidence.append("zip:central_directory")
        if native.get("central_directory_walk_ok"):
            evidence.append("zip:central_directory_walk")
        if native.get("local_header_links_ok"):
            evidence.append("zip:local_header_links")

        plausible = bool(native.get("plausible"))
        walk_ok = bool(native.get("central_directory_walk_ok")) and bool(native.get("local_header_links_ok"))
        if plausible and walk_ok:
            status = "extractable"
            confidence = 0.99
        elif plausible:
            status = "damaged"
            confidence = 0.65
        else:
            status = "weak"
            confidence = 0.35 if hits else 0.0

        damage_flags = []
        error = native.get("error") or ""
        if error:
            damage_flags.append(str(error))
        return ArchiveFormatEvidence(
            format="zip",
            confidence=confidence,
            status=status,
            segments=[
                ArchiveSegment(
                    start_offset=archive_offset,
                    end_offset=min(end_offset, int(view.size)) if end_offset is not None else None,
                    confidence=confidence,
                    damage_flags=damage_flags,
                    evidence=evidence or ["zip:eocd" if native.get("magic_matched") else "zip:signature"],
                )
            ] if confidence > 0 else [],
            warnings=[],
            details=native,
        )


register_analysis_module(ZipAnalysisModule())
