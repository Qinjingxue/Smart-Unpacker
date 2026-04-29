from dataclasses import dataclass
from typing import Optional


@dataclass
class PasswordResolution:
    password: Optional[str]
    test_result: object = None
    error_text: str = ""
    archive_key: str = ""
    encrypted: bool | None = None

