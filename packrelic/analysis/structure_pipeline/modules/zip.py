from packrelic.analysis.structure_pipeline.module import AnalysisModuleSpec
from packrelic.analysis.structure_pipeline.registry import register_analysis_module
from packrelic.analysis.structure_pipeline.modules._fuzzy import apply_fuzzy_routes
from packrelic.analysis.result import ArchiveFormatEvidence, ArchiveSegment


class ZipAnalysisModule:
    spec = AnalysisModuleSpec(name="zip", formats=("zip",), signatures=(b"PK\x03\x04", b"PK\x05\x06"), io_profile="tail_heavy")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if str(hit.get("name", "")).startswith("zip_")]
        if not hits:
            return ArchiveFormatEvidence(format="zip", confidence=0.0, status="not_found")

        max_entries = int(config.get("max_cd_entries_to_walk", 64) or 64)
        eocd_hits = [int(hit["offset"]) for hit in hits if hit.get("name") == "zip_eocd"]
        native = None
        for eocd_offset in sorted(eocd_hits, reverse=True):
            candidate = view.probe_zip(eocd_offset=eocd_offset, max_cd_entries_to_walk=max_entries)
            if candidate and candidate.get("plausible"):
                native = candidate
                break
        if native is None and eocd_hits:
            native = view.probe_zip(eocd_offset=max(eocd_hits), max_cd_entries_to_walk=max_entries)
        if native and (native.get("magic_matched") or native.get("plausible")):
            native = dict(native)
            recovered = self._local_header_recovery(view, native, hits, prepass)
            if recovered:
                return recovered
            return self._from_native(view, native, hits, prepass)
        return ArchiveFormatEvidence(format="zip", confidence=0.0, status="not_found")

    def _from_native(self, view, native: dict, hits: list[dict], prepass: dict) -> ArchiveFormatEvidence:
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
        crc_warning = str(native.get("content_integrity_warning") or "")
        if crc_warning:
            damage_flags.append("content_integrity_bad_or_unknown")
            native["integrity_confidence"] = "low"
            native["content_damage_reason"] = crc_warning
            confidence = min(confidence, 0.90)
        else:
            native.setdefault("integrity_confidence", "unknown" if not plausible else "medium")
        native.setdefault("boundary_confidence", "high" if plausible and walk_ok else "low")
        segment_end = min(end_offset, int(view.size)) if end_offset is not None else None
        apply_fuzzy_routes(
            native,
            evidence,
            damage_flags,
            prepass,
            start_offset=archive_offset,
            end_offset=segment_end,
            file_size=int(view.size),
            format_hint="zip",
        )
        return ArchiveFormatEvidence(
            format="zip",
            confidence=confidence,
            status=status,
            segments=[
                ArchiveSegment(
                    start_offset=archive_offset,
                    end_offset=segment_end,
                    confidence=confidence,
                    damage_flags=damage_flags,
                    evidence=evidence or ["zip:eocd" if native.get("magic_matched") else "zip:signature"],
                )
            ] if confidence > 0 else [],
            warnings=[],
            details=native,
        )

    def _local_header_recovery(self, view, native: dict, hits: list[dict], prepass: dict) -> ArchiveFormatEvidence | None:
        error = str(native.get("error") or "")
        if error not in {"bad_central_directory_signature", "archive_offset_underflow", "central_directory_size_out_of_range"}:
            return None
        local_hits = [int(hit["offset"]) for hit in hits if hit.get("name") == "zip_local"]
        if not local_hits:
            return None
        start = min(local_hits)
        details = {
            **native,
            "boundary_confidence": "low",
            "integrity_confidence": "unknown",
            "recovery_strategy": "local_header_scan",
            "directory_confidence": "low",
        }
        evidence = ["zip:local_header"]
        damage_flags = ["central_directory_unreliable", "local_header_recovery"]
        apply_fuzzy_routes(
            details,
            evidence,
            damage_flags,
            prepass,
            start_offset=start,
            end_offset=None,
            file_size=int(view.size),
            format_hint="zip",
        )
        return ArchiveFormatEvidence(
            format="zip",
            confidence=0.70,
            status="damaged",
            segments=[
                ArchiveSegment(
                    start_offset=start,
                    end_offset=None,
                    confidence=0.70,
                    damage_flags=damage_flags,
                    evidence=evidence,
                )
            ],
            warnings=["zip central directory is damaged; recovered candidate from local headers"],
            details=details,
        )



register_analysis_module(ZipAnalysisModule())
