from dataclasses import dataclass
from typing import Any

from packrelic.contracts.detection import FactBag


@dataclass(frozen=True)
class FactProcessorContext:
    fact_bag: FactBag
    output_fact: str
    config: dict[str, Any]
    fact_config: dict[str, Any]
    scan_session: Any | None = None
