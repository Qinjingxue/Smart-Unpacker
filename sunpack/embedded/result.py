from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_HIT_FORMATS = {
    "zip_local": "zip",
    "zip_eocd": "zip",
    "rar4": "rar",
    "rar5": "rar",
    "7z": "7z",
    "gzip": "gzip",
    "bzip2": "bzip2",
    "xz": "xz",
    "zstd": "zstd",
    "tar_ustar": "tar",
}


@dataclass(frozen=True, slots=True)
class EmbeddedCandidate:
    format: str
    detected_ext: str
    offset: int
    end_offset: int | None
    confidence: float
    validation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "detected_ext": self.detected_ext,
            "offset": self.offset,
            "end_offset": self.end_offset,
            "confidence": self.confidence,
            "validation": self.validation,
        }


@dataclass(frozen=True, slots=True)
class SignatureHit:
    name: str
    offset: int

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "offset": self.offset, "source": "embedded_scan"}


@dataclass(frozen=True, slots=True)
class EmbeddedScanResult:
    complete: bool
    candidates: tuple[EmbeddedCandidate, ...]
    hits: tuple[SignatureHit, ...]
    read_bytes: int
    file_size: int

    @property
    def found(self) -> bool:
        return bool(self.candidates)

    @classmethod
    def empty(cls, *, complete: bool = False) -> "EmbeddedScanResult":
        return cls(complete=complete, candidates=(), hits=(), read_bytes=0, file_size=0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "found": self.found,
            "complete": self.complete,
            "candidates": [item.to_dict() for item in self.candidates],
            "hits": [item.to_dict() for item in self.hits],
            "read_bytes": self.read_bytes,
            "file_size": self.file_size,
        }

    def to_prepass(self) -> dict[str, Any]:
        validated_formats = {item.format for item in self.candidates}
        hits = [
            item.to_dict()
            for item in self.hits
            if _HIT_FORMATS.get(item.name) in validated_formats
        ]
        return {
            "hits": hits,
            "formats": sorted(validated_formats),
            "full_scan_bytes": self.read_bytes,
            "full_scan_complete": self.complete,
            "source": "embedded_scan",
            "embedded_candidates": [item.to_dict() for item in self.candidates],
        }
