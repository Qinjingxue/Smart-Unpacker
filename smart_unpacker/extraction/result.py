from dataclasses import dataclass
from typing import Optional


@dataclass
class ExtractionResult:
    success: bool
    archive: str
    out_dir: str
    all_parts: list[str]
    error: str = ""
    password_used: Optional[str] = None
    selected_codepage: Optional[str] = None
