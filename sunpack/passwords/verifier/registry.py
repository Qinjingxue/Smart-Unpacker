from __future__ import annotations

import os
from dataclasses import dataclass, field

from sunpack.passwords.verifier.base import PasswordBatchVerification, PasswordVerifier


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
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        if not self.fast_verifiers:
            return self._run_final_verifier(archive_path, passwords, part_paths=part_paths, archive_input=archive_input)

        remaining = list(passwords)
        offset = 0
        total_fast_attempts = 0
        last_error = ""
        while remaining:
            fast_outcome = self._run_fast_verifiers(archive_path, remaining, part_paths=part_paths, archive_input=archive_input)
            total_fast_attempts += max(fast_outcome.attempts, len(remaining) if fast_outcome.status == "no_match" else 0)
            last_error = fast_outcome.error_text or last_error

            if fast_outcome.status == "match" and fast_outcome.matched_index >= 0:
                candidate_index = offset + fast_outcome.matched_index
                candidate = passwords[candidate_index]
                if not fast_outcome.final_confirmation_required:
                    return PasswordBatchVerification(
                        ok=True,
                        status="match",
                        matched_index=candidate_index,
                        attempts=candidate_index + 1,
                        test_result=fast_outcome.test_result,
                        error_text="",
                        terminal=True,
                        final_confirmation_required=False,
                    )
                confirmation = self._confirm_match(archive_path, candidate, part_paths=part_paths, archive_input=archive_input)
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

            final_outcome = self._run_final_verifier(archive_path, passwords, part_paths=part_paths, archive_input=archive_input)
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
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        for verifier in self._ordered_fast_verifiers(archive_path, archive_input):
            outcome = _call_verifier(
                verifier,
                archive_path,
                passwords,
                part_paths=part_paths,
                archive_input=archive_input,
            )
            if outcome.status in {"unsupported_method", "unknown_needs_final_verifier"}:
                continue
            return outcome
        return PasswordBatchVerification(
            ok=False,
            status="unknown_needs_final_verifier",
            attempts=0,
            error_text="no fast verifier accepted archive",
        )

    def _ordered_fast_verifiers(self, archive_path: str, archive_input: dict | None = None) -> list[PasswordVerifier]:
        preferred = _preferred_archive_format(archive_path, archive_input)
        if not preferred:
            return list(self.fast_verifiers)
        matching = [
            verifier
            for verifier in self.fast_verifiers
            if _normalize_archive_format(str(getattr(verifier, "format_hint", ""))) == preferred
        ]
        if not matching:
            return list(self.fast_verifiers)
        return matching + [
            verifier
            for verifier in self.fast_verifiers
            if verifier not in matching
        ]

    def _confirm_match(
        self,
        archive_path: str,
        password: str,
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        if self.final_verifier is None:
            return PasswordBatchVerification(ok=True, status="match", matched_index=0, attempts=1, terminal=True)
        return _call_verifier(
            self.final_verifier,
            archive_path,
            [password],
            part_paths=part_paths,
            archive_input=archive_input,
        )

    def _run_final_verifier(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        if self.final_verifier is None:
            return PasswordBatchVerification(
                ok=False,
                status="unknown_needs_final_verifier",
                attempts=0,
                error_text="no final password verifier configured",
                terminal=True,
            )
        return _call_verifier(
            self.final_verifier,
            archive_path,
            passwords,
            part_paths=part_paths,
            archive_input=archive_input,
        )


def _call_verifier(
    verifier: PasswordVerifier,
    archive_path: str,
    passwords: list[str],
    *,
    part_paths: list[str] | None = None,
    archive_input: dict | None = None,
) -> PasswordBatchVerification:
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


def _preferred_archive_format(archive_path: str, archive_input: dict | None = None) -> str:
    if isinstance(archive_input, dict):
        hinted = _normalize_archive_format(str(archive_input.get("format_hint") or archive_input.get("format") or ""))
        if hinted:
            return hinted
    return _format_from_path(archive_path)


def _format_from_path(archive_path: str) -> str:
    name = os.path.basename(str(archive_path or "")).lower()
    if name.endswith(".part1.rar") or name.endswith(".part01.rar"):
        return "rar"
    suffixes = []
    root = name
    while True:
        root, ext = os.path.splitext(root)
        if not ext:
            break
        suffixes.append(ext)
    if not suffixes:
        return ""
    if suffixes[0] == ".001" and len(suffixes) > 1:
        return _normalize_archive_format(suffixes[1].lstrip("."))
    return _normalize_archive_format(suffixes[0].lstrip("."))


def _normalize_archive_format(value: str) -> str:
    normalized = (value or "").strip().lower().lstrip(".")
    if normalized in {"7zip", "sevenzip", "seven_zip"}:
        return "7z"
    if normalized in {"zip", "rar", "7z"}:
        return normalized
    return ""
