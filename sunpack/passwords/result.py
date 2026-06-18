from dataclasses import dataclass
from enum import Enum
from typing import Optional

from sunpack.passwords.verifier.base import VerifierStatus


class PasswordResolutionStatus(str, Enum):
    RESOLVED = "resolved"
    UNENCRYPTED = "unencrypted"
    PASSWORD_REQUIRED = "password_required"
    CANDIDATES_EXHAUSTED = "candidates_exhausted"
    INCONCLUSIVE = "inconclusive"
    DAMAGED = "damaged"
    UNSUPPORTED = "unsupported"
    BACKEND_ERROR = "backend_error"


@dataclass(frozen=True)
class PasswordProbeResult:
    status: VerifierStatus
    message: str = ""
    backend_result: object = None

    @property
    def ok(self) -> bool:
        return self.status == "match"

    @property
    def returncode(self) -> int:
        return 0 if self.ok else 2


@dataclass
class PasswordResolution:
    password: Optional[str]
    status: PasswordResolutionStatus
    test_result: object = None
    error_text: str = ""
    archive_key: str = ""
    encrypted: bool | None = None
    requires_extraction_confirmation: bool = False
    fingerprint_key: str = ""

