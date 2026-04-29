from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class PreparedRule:
    name: str
    instance: Any
    config: Dict[str, Any]
