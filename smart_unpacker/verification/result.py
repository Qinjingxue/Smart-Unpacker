from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VerificationIssue:
    method: str
    code: str
    message: str
    path: str = ""
    expected: Any = None
    actual: Any = None


@dataclass(frozen=True)
class VerificationStepResult:
    method: str
    score_delta: int = 0
    status: str = "passed"
    issues: list[VerificationIssue] = field(default_factory=list)
    hard_fail: bool = False


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    status: str
    score: int
    pass_threshold: int
    fail_fast_threshold: int
    methods_run: list[str] = field(default_factory=list)
    issues: list[VerificationIssue] = field(default_factory=list)

    @property
    def failures(self) -> list[VerificationIssue]:
        return [issue for issue in self.issues if issue.code.startswith("fail")]

    @property
    def warnings(self) -> list[VerificationIssue]:
        return [issue for issue in self.issues if not issue.code.startswith("fail")]

