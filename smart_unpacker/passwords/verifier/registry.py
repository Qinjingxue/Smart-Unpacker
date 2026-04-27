from __future__ import annotations

from dataclasses import dataclass, field

from smart_unpacker.passwords.verifier.base import PasswordBatchVerification, PasswordVerifier


@dataclass
class PasswordVerifierRegistry:
    fast_verifiers: list[PasswordVerifier] = field(default_factory=list)
    final_verifier: PasswordVerifier | None = None

    def add_fast(self, verifier: PasswordVerifier) -> None:
        self.fast_verifiers.append(verifier)

    def set_final(self, verifier: PasswordVerifier) -> None:
        self.final_verifier = verifier

    def build(self) -> PasswordVerifier:
        if self.final_verifier is None:
            if len(self.fast_verifiers) == 1:
                return self.fast_verifiers[0]
            return PasswordVerifierChain(list(self.fast_verifiers), None)
        return PasswordVerifierChain(list(self.fast_verifiers), self.final_verifier)


class PasswordVerifierChain:
    def __init__(self, fast_verifiers: list[PasswordVerifier], final_verifier: PasswordVerifier | None):
        self.fast_verifiers = list(fast_verifiers)
        self.final_verifier = final_verifier

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
    ) -> PasswordBatchVerification:
        if not self.fast_verifiers:
            return self._run_final_verifier(archive_path, passwords, part_paths=part_paths)

        remaining = list(passwords)
        offset = 0
        total_fast_attempts = 0
        last_error = ""
        while remaining:
            fast_outcome = self._run_fast_verifiers(archive_path, remaining, part_paths=part_paths)
            total_fast_attempts += max(fast_outcome.attempts, len(remaining) if fast_outcome.status == "no_match" else 0)
            last_error = fast_outcome.error_text or last_error

            if fast_outcome.status == "match" and fast_outcome.matched_index >= 0:
                candidate_index = offset + fast_outcome.matched_index
                candidate = passwords[candidate_index]
                confirmation = self._confirm_match(archive_path, candidate, part_paths=part_paths)
                if confirmation.ok:
                    return PasswordBatchVerification(
                        ok=True,
                        status="match",
                        matched_index=candidate_index,
                        attempts=candidate_index + 1,
                        test_result=confirmation.test_result,
                        error_text="",
                        terminal=True,
                    )
                next_offset = fast_outcome.matched_index + 1
                remaining = remaining[next_offset:]
                offset = candidate_index + 1
                continue

            if fast_outcome.status == "no_match":
                return PasswordBatchVerification(
                    ok=False,
                    status="no_match",
                    matched_index=-1,
                    attempts=len(passwords),
                    test_result=fast_outcome.test_result,
                    error_text=fast_outcome.error_text or "wrong password",
                    terminal=False,
                )

            if fast_outcome.status in {"damaged", "backend_unavailable"}:
                return fast_outcome

            final_outcome = self._run_final_verifier(archive_path, passwords, part_paths=part_paths)
            return PasswordBatchVerification(
                ok=final_outcome.ok,
                status=final_outcome.status,
                matched_index=final_outcome.matched_index,
                attempts=final_outcome.attempts or total_fast_attempts,
                test_result=final_outcome.test_result,
                error_text=final_outcome.error_text or last_error,
                terminal=final_outcome.terminal,
            )

        return PasswordBatchVerification(
            ok=False,
            status="no_match",
            matched_index=-1,
            attempts=len(passwords),
            error_text=last_error or "wrong password",
            terminal=False,
        )

    def _run_fast_verifiers(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
    ) -> PasswordBatchVerification:
        for verifier in self.fast_verifiers:
            outcome = verifier.verify_batch(archive_path, passwords, part_paths=part_paths)
            if outcome.status in {"unsupported_method", "unknown_needs_final_verifier"}:
                continue
            return outcome
        return PasswordBatchVerification(
            ok=False,
            status="unknown_needs_final_verifier",
            attempts=0,
            error_text="no fast verifier accepted archive",
        )

    def _confirm_match(
        self,
        archive_path: str,
        password: str,
        *,
        part_paths: list[str] | None = None,
    ) -> PasswordBatchVerification:
        if self.final_verifier is None:
            return PasswordBatchVerification(ok=True, status="match", matched_index=0, attempts=1, terminal=True)
        return self.final_verifier.verify_batch(archive_path, [password], part_paths=part_paths)

    def _run_final_verifier(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
    ) -> PasswordBatchVerification:
        if self.final_verifier is None:
            return PasswordBatchVerification(
                ok=False,
                status="unknown_needs_final_verifier",
                attempts=0,
                error_text="no final password verifier configured",
                terminal=True,
            )
        return self.final_verifier.verify_batch(archive_path, passwords, part_paths=part_paths)
