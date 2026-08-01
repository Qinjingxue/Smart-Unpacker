from __future__ import annotations

from dataclasses import dataclass, field

from sunpack.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence


@dataclass(frozen=True, slots=True)
class RepairInspectionFeedback:
    """Stable repair feedback derived from a neutral Analysis report."""

    status: str
    format: str = ""
    confidence: float = 0.0
    damage_flags: tuple[str, ...] = ()
    start_trusted: bool = False
    end_trusted: bool = False
    report: ArchiveAnalysisReport | None = field(default=None, repr=False, compare=False)

    @classmethod
    def from_report(cls, report: ArchiveAnalysisReport) -> "RepairInspectionFeedback":
        selected = _best_selected(report)
        evidence = selected or _best_evidence(report)
        segments = list(getattr(evidence, "segments", None) or []) if evidence is not None else []
        flags = _dedupe(
            flag
            for segment in segments
            for flag in list(getattr(segment, "damage_flags", None) or [])
        )
        start_trusted = any(getattr(segment, "start_offset", None) is not None for segment in segments)
        end_trusted = bool(segments) and all(
            getattr(segment, "end_offset", None) is not None
            and "boundary_unreliable" not in getattr(segment, "damage_flags", [])
            for segment in segments
        )
        return cls(
            status=(
                str(getattr(evidence, "status", "") or "")
                if evidence is not None
                else "not_found"
            ),
            format=str(getattr(evidence, "format", "") or "") if evidence is not None else "",
            confidence=float(getattr(evidence, "confidence", 0.0) or 0.0) if evidence is not None else 0.0,
            damage_flags=tuple(flags),
            start_trusted=start_trusted,
            end_trusted=end_trusted,
            report=report,
        )

    def to_score_payload(self) -> dict:
        return {
            "status": self.status,
            "format": self.format,
            "confidence": self.confidence,
            "damage_flags": list(self.damage_flags),
            "start_trusted": self.start_trusted,
            "end_trusted": self.end_trusted,
        }


def _best_selected(report: ArchiveAnalysisReport) -> ArchiveFormatEvidence | None:
    if not report.selected:
        return None
    return max(report.selected, key=lambda item: float(item.confidence or 0.0))


def _best_evidence(report: ArchiveAnalysisReport) -> ArchiveFormatEvidence | None:
    if not report.evidences:
        return None
    return max(report.evidences, key=lambda item: float(item.confidence or 0.0))


def _dedupe(values) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "")
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output
