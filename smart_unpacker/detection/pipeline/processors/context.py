from dataclasses import dataclass
from typing import Any

from smart_unpacker.contracts.detection import FactBag


@dataclass(frozen=True)
class FactProcessorContext:
    fact_bag: FactBag
    output_fact: str
    config: dict[str, Any]
    fact_config: dict[str, Any]
