from dataclasses import dataclass, field
from typing import Any, Optional

from sunpack.contracts.failures import FailureInfo


@dataclass
class ExtractionResult:
    success: bool
    archive: str
    out_dir: str
    all_parts: list[str]
    error: str = ""
    failure: FailureInfo | None = None
    password_used: Optional[str] = None
    selected_codepage: Optional[str] = None
    diagnostics: dict[str, Any] = field(default_factory=dict)
    partial_outputs: bool = False
    progress_manifest: str = ""
    progress_manifest_payload: dict[str, Any] | None = None
    # Canonical in-process inventory. The payload field is reserved for
    # explicit persistence or IPC serialization boundaries.
    output_inventory: Any = None
    output_inventory_payload: dict[str, Any] | None = None
    files_written: int = 0
    bytes_written: int = 0
