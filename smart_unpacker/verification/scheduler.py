from typing import Any

from smart_unpacker.contracts.tasks import ArchiveTask
from smart_unpacker.extraction.result import ExtractionResult
from smart_unpacker.passwords import PasswordSession
from smart_unpacker.verification.evidence import build_verification_evidence
from smart_unpacker.verification.pipeline import VerificationPipeline
from smart_unpacker.verification.result import VerificationResult


DEFAULT_VERIFICATION_CONFIG = {
    "enabled": False,
    "initial_score": 100,
    "pass_threshold": 70,
    "fail_fast_threshold": 40,
    "max_retries": 0,
    "cleanup_failed_output": True,
    "methods": [
        {"name": "extraction_exit_signal", "enabled": True},
        {"name": "output_presence", "enabled": True},
        {"name": "expected_name_presence", "enabled": True},
        {"name": "manifest_size_match", "enabled": True},
    ],
}


class VerificationScheduler:
    def __init__(self, config: dict[str, Any] | None = None, password_session: PasswordSession | None = None):
        self.config = self._verification_config(config or {})
        self.password_session = password_session

    def verify(self, task: ArchiveTask, extraction_result: ExtractionResult) -> VerificationResult:
        evidence = build_verification_evidence(task, extraction_result, self.password_session)
        if not self.config.get("enabled", False):
            return VerificationResult(
                ok=True,
                status="disabled",
                score=int(self.config.get("initial_score", 100)),
                pass_threshold=int(self.config.get("pass_threshold", 70)),
                fail_fast_threshold=int(self.config.get("fail_fast_threshold", 40)),
            )
        return VerificationPipeline(self.config).run(evidence)

    def _verification_config(self, config: dict[str, Any]) -> dict:
        if "verification" in config and isinstance(config.get("verification"), dict):
            config = config["verification"]
        merged = dict(DEFAULT_VERIFICATION_CONFIG)
        merged.update(config or {})
        return merged
