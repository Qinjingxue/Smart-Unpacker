from dataclasses import dataclass, field
from typing import Any

from sunpack.contracts.detection import FactBag


@dataclass(frozen=True)
class FactCollectorContext:
    base_path: str
    fact_bag: FactBag
    fact_name: str
    config: dict[str, Any] = field(default_factory=dict)
    fact_config: dict[str, Any] = field(default_factory=dict)
    scan_session: Any | None = None


@dataclass(frozen=True)
class BatchFactCollectorContext:
    fact_bags: list[FactBag]
    fact_name: str
    config: dict[str, Any] = field(default_factory=dict)
    fact_configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    scan_session: Any | None = None
