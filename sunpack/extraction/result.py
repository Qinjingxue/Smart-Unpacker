from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ExtractionResult:
    success: bool
    archive: str
    out_dir: str
    all_parts: list[str]
    error: str = ""
    password_used: Optional[str] = None
    selected_codepage: Optional[str] = None
    diagnostics: dict[str, Any] = field(default_factory=dict)
    partial_outputs: bool = False
    progress_manifest: str = ""
    progress_manifest_payload: dict[str, Any] | None = None
