from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

from smart_unpacker.passwords.cache import PasswordAttemptCache
from smart_unpacker.passwords.candidates import PasswordCandidate
from smart_unpacker.passwords.fingerprint import build_archive_fingerprint
from smart_unpacker.passwords.job import PasswordJob
from smart_unpacker.passwords.verifier import PasswordVerifier, PasswordVerifierRegistry, SevenZipDllVerifier
from smart_unpacker.passwords.verifier.rar_fast import RarFastVerifier
from smart_unpacker.passwords.verifier.seven_zip_fast import SevenZipFastVerifier
from smart_unpacker.passwords.verifier.zip_fast import ZipFastVerifier


@dataclass(frozen=True)
class PasswordSearchResult:
    password: str | None
    test_result: object = None
    error_text: str = ""
    attempts: int = 0
    exhausted: bool = False
    stopped_reason: str = ""


@dataclass(frozen=True)
class PasswordProgressEvent:
    stage: Literal["started", "batch_started", "batch_finished", "skipped_cached_negative", "finished"]
    attempts: int = 0
    candidates_seen: int = 0
    skipped: int = 0
    batch_size: int = 0
    elapsed_seconds: float = 0.0
    password_found: bool = False
    stopped_reason: str = ""
    error_text: str = ""


class PasswordScheduler:
    def __init__(
        self,
        verifier: PasswordVerifier,
        *,
        cache: PasswordAttemptCache | None = None,
        default_batch_size: int = 256,
    ):
        self.verifier = verifier
        self.cache = cache or PasswordAttemptCache()
        self.default_batch_size = max(1, int(default_batch_size))

    @classmethod
    def from_archive_password_tester(cls, password_tester: object) -> "PasswordScheduler":
        final_verifier = SevenZipDllVerifier.from_archive_password_tester(password_tester)
        registry = PasswordVerifierRegistry(
            fast_verifiers=[ZipFastVerifier(), RarFastVerifier(), SevenZipFastVerifier()],
            final_verifier=final_verifier,
        )
        return cls(registry.build())

    def run(self, job: PasswordJob) -> PasswordSearchResult:
        started_at = time.monotonic()
        self._emit_progress(job, PasswordProgressEvent(stage="started"))
        fingerprint = job.fingerprint or build_archive_fingerprint(job.archive_path, job.part_paths)
        cached_success = self.cache.get_success(fingerprint.key)
        if cached_success is not None:
            result = PasswordSearchResult(password=cached_success, attempts=0, stopped_reason="cache_hit")
            self._emit_finished(job, result, started_at, candidates_seen=0, skipped=0)
            return result

        attempts = 0
        candidates_seen = 0
        skipped = 0
        last_result = None
        last_error = ""
        batch_size = max(1, int(job.batch_size or self.default_batch_size))
        batch: list[str] = []

        for candidate in job.candidate_pipeline():
            stop_reason = self._stop_reason(job, attempts, started_at)
            if stop_reason:
                result = PasswordSearchResult(
                    password=None,
                    test_result=last_result,
                    error_text=last_error or "password search stopped",
                    attempts=attempts,
                    stopped_reason=stop_reason,
                )
                self._emit_finished(job, result, started_at, candidates_seen, skipped)
                return result
            password = _candidate_value(candidate)
            candidates_seen += 1
            if self.cache.has_negative(fingerprint.key, password):
                skipped += 1
                self._emit_progress(job, PasswordProgressEvent(
                    stage="skipped_cached_negative",
                    attempts=attempts,
                    candidates_seen=candidates_seen,
                    skipped=skipped,
                    elapsed_seconds=time.monotonic() - started_at,
                ))
                continue
            batch.append(password)
            if len(batch) >= self._allowed_batch_size(job, attempts, batch_size):
                outcome = self._verify_batch(job, fingerprint.key, batch, attempts, started_at, candidates_seen, skipped)
                attempts = outcome.attempts
                last_result = outcome.test_result
                last_error = outcome.error_text
                if outcome.password is not None or outcome.stopped_reason:
                    self._emit_finished(job, outcome, started_at, candidates_seen, skipped)
                    return outcome
                batch = []

        if batch:
            outcome = self._verify_batch(job, fingerprint.key, batch, attempts, started_at, candidates_seen, skipped)
            attempts = outcome.attempts
            last_result = outcome.test_result
            last_error = outcome.error_text
            if outcome.password is not None or outcome.stopped_reason:
                self._emit_finished(job, outcome, started_at, candidates_seen, skipped)
                return outcome

        result = PasswordSearchResult(
            password=None,
            test_result=last_result,
            error_text=last_error or "wrong password",
            attempts=attempts,
            exhausted=True,
        )
        self._emit_finished(job, result, started_at, candidates_seen, skipped)
        return result

    def _verify_batch(
        self,
        job: PasswordJob,
        fingerprint_key: str,
        batch: list[str],
        previous_attempts: int,
        started_at: float,
        candidates_seen: int,
        skipped: int,
    ) -> PasswordSearchResult:
        batch = batch[: self._allowed_batch_size(job, previous_attempts, len(batch))]
        if not batch:
            return PasswordSearchResult(
                password=None,
                attempts=previous_attempts,
                error_text="password attempt limit reached",
                stopped_reason="max_attempts",
            )
        self._emit_progress(job, PasswordProgressEvent(
            stage="batch_started",
            attempts=previous_attempts,
            candidates_seen=candidates_seen,
            skipped=skipped,
            batch_size=len(batch),
            elapsed_seconds=time.monotonic() - started_at,
        ))
        verification = _call_verifier(
            self.verifier,
            job.archive_path,
            batch,
            part_paths=job.part_paths,
            archive_input=job.archive_input,
        )
        attempted_in_batch = max(0, min(max(verification.attempts, 0), len(batch)))
        if not verification.ok and attempted_in_batch == 0:
            attempted_in_batch = len(batch)
        total_attempts = previous_attempts + attempted_in_batch
        self._emit_progress(job, PasswordProgressEvent(
            stage="batch_finished",
            attempts=total_attempts,
            candidates_seen=candidates_seen,
            skipped=skipped,
            batch_size=len(batch),
            elapsed_seconds=time.monotonic() - started_at,
            password_found=verification.ok,
            error_text=verification.error_text,
        ))
        if verification.ok:
            password = batch[verification.matched_index]
            self.cache.remember_success(fingerprint_key, password)
            return PasswordSearchResult(
                password=password,
                test_result=verification.test_result,
                error_text="",
                attempts=total_attempts,
                stopped_reason="found",
            )
        self.cache.remember_negative_batch(fingerprint_key, batch[:attempted_in_batch])
        return PasswordSearchResult(
            password=None,
            test_result=verification.test_result,
            error_text=verification.error_text,
            attempts=total_attempts,
            stopped_reason="terminal" if verification.terminal else "",
        )

    @staticmethod
    def _stop_reason(job: PasswordJob, attempts: int, started_at: float) -> str:
        if job.max_attempts is not None and attempts >= job.max_attempts:
            return "max_attempts"
        if job.timeout_seconds is not None and time.monotonic() - started_at >= job.timeout_seconds:
            return "timeout"
        return ""

    @staticmethod
    def _allowed_batch_size(job: PasswordJob, attempts: int, requested_batch_size: int) -> int:
        requested_batch_size = max(1, int(requested_batch_size))
        if job.max_attempts is None:
            return requested_batch_size
        return max(0, min(requested_batch_size, job.max_attempts - attempts))

    @staticmethod
    def _emit_progress(job: PasswordJob, event: PasswordProgressEvent) -> None:
        if job.progress_callback is None:
            return
        job.progress_callback(event)

    def _emit_finished(
        self,
        job: PasswordJob,
        result: PasswordSearchResult,
        started_at: float,
        candidates_seen: int,
        skipped: int,
    ) -> None:
        self._emit_progress(job, PasswordProgressEvent(
            stage="finished",
            attempts=result.attempts,
            candidates_seen=candidates_seen,
            skipped=skipped,
            elapsed_seconds=time.monotonic() - started_at,
            password_found=result.password is not None,
            stopped_reason=result.stopped_reason,
            error_text=result.error_text,
        ))


def _candidate_value(candidate: PasswordCandidate | str) -> str:
    if isinstance(candidate, PasswordCandidate):
        return candidate.value
    return str(candidate)


def _call_verifier(
    verifier: PasswordVerifier,
    archive_path: str,
    passwords: list[str],
    *,
    part_paths: list[str] | None = None,
    archive_input: dict | None = None,
):
    try:
        return verifier.verify_batch(
            archive_path,
            passwords,
            part_paths=part_paths,
            archive_input=archive_input,
        )
    except TypeError as error:
        if "archive_input" not in str(error):
            raise
        return verifier.verify_batch(archive_path, passwords, part_paths=part_paths)
