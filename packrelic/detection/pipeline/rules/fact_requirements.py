import os
from dataclasses import dataclass, field
from typing import Any, Protocol

from packrelic.contracts.detection import FactBag
from packrelic.support.extensions import normalize_exts


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
