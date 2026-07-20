import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from sunpack.contracts.detection import FactBag
from sunpack.support.extensions import normalize_exts


DEFAULT_STRUCTURE_EVIDENCE_EXTENSIONS = (
    ".001",
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tbz2",
    ".tgz",
    ".txz",
    ".tzst",
    ".xz",
    ".zip",
    ".zst",
    ".zstd",
)
DEFAULT_STRUCTURE_EVIDENCE_MAGICS = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"Rar!\x1a\x07\x00",
    b"Rar!\x1a\x07\x01\x00",
    b"7z\xbc\xaf\x27\x1c",
    b"\x1f\x8b\x08",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"\x28\xb5\x2f\xfd",
)
def _extension_values_key(values) -> tuple[str, ...]:
    return tuple(value for value in values or [] if isinstance(value, str))


class FactCondition(Protocol):
    required_facts: set[str]

    def matches(self, facts: FactBag, config: dict[str, Any]) -> bool:
        ...


@dataclass(frozen=True)
class PathExtensionInConfig:
    fields: tuple[str, ...]
    defaults: dict[str, tuple[str, ...]] = field(default_factory=dict)
    required_facts: set[str] = field(default_factory=lambda: {"file.path"})
    _allowed_cache: dict[tuple[tuple[str, tuple[str, ...]], ...], frozenset[str]] = field(
        default_factory=dict,
        init=False,
        repr=False,
        compare=False,
    )

    def matches(self, facts: FactBag, config: dict[str, Any]) -> bool:
        path = facts.get("file.path") or ""
        ext = os.path.splitext(path)[1].lower()
        if not ext:
            return False

        return ext in self._allowed_extensions(config)

    def _allowed_extensions(self, config: dict[str, Any]) -> frozenset[str]:
        cache_key = tuple(
            (
                field_name,
                _extension_values_key(config.get(field_name, self.defaults.get(field_name, ()))),
            )
            for field_name in self.fields
        )
        cached = self._allowed_cache.get(cache_key)
        if cached is not None:
            return cached

        allowed: set[str] = set()
        for field_name in self.fields:
            values = config.get(field_name, self.defaults.get(field_name, ()))
            allowed.update(normalize_exts(values))
        normalized = frozenset(allowed)
        self._allowed_cache[cache_key] = normalized
        return normalized


@dataclass(frozen=True)
class MagicBytesStartsWith:
    prefixes: tuple[bytes, ...]
    required_facts: set[str] = field(default_factory=lambda: {"file.magic_bytes"})

    def matches(self, facts: FactBag, config: dict[str, Any]) -> bool:
        magic = facts.get("file.magic_bytes") or b""
        if not isinstance(magic, (bytes, bytearray)):
            return False
        return any(bytes(magic).startswith(prefix) for prefix in self.prefixes)


@dataclass(frozen=True)
class ArchiveStructureCandidate:
    """Gate expensive structural evidence behind a positive archive prior."""

    required_facts: set[str] = field(default_factory=lambda: {"file.path", "file.magic_bytes"})

    def matches(self, facts: FactBag, config: dict[str, Any]) -> bool:
        magic = facts.get("file.magic_bytes") or b""
        magic_bytes = bytes(magic) if isinstance(magic, (bytes, bytearray)) else b""
        if any(magic_bytes.startswith(prefix) for prefix in DEFAULT_STRUCTURE_EVIDENCE_MAGICS):
            return True

        path = str(facts.get("candidate.entry_path") or facts.get("file.path") or "").lower()
        extensions = normalize_exts(
            config.get("candidate_extensions", DEFAULT_STRUCTURE_EVIDENCE_EXTENSIONS)
        )
        if any(path.endswith(extension) for extension in extensions):
            return True

        if bool(facts.get("file.probe_detected_archive") or facts.get("file.embedded_archive_found")):
            return True
        overlay = facts.get("pe.overlay_structure") or {}
        if isinstance(overlay, dict) and overlay.get("archive_like"):
            return True
        if bool(
            facts.get("relation.is_split_related")
            or int(facts.get("relation.split_member_count") or 0) > 1
        ):
            return True
        # A merely unknown binary is not enough evidence to run the forensic
        # structure pipeline during the initial detection pass. Arbitrary-offset
        # embedded archives are handled by the separately budgeted embedded deep
        # scan after candidate selection.
        return False


@dataclass(frozen=True)
class FactRequirement:
    fact_name: str
    condition: FactCondition | None = None

    @property
    def prerequisite_facts(self) -> set[str]:
        return set(getattr(self.condition, "required_facts", set()))

    def matches(self, facts: FactBag, config: dict[str, Any]) -> bool:
        if self.condition is None:
            return True
        return self.condition.matches(facts, config)
