from __future__ import annotations

import os
from dataclasses import dataclass, field

from sunpack.passwords.verifier.base import PasswordBatchVerification, PasswordVerifier
from sunpack.support.sevenzip_bridge import OPERATION_RESULT_HEADERS_ERROR


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
                local_matched_indices = fast_outcome.matched_indices or (fast_outcome.matched_index,)
                candidate_indices = tuple(
                    offset + index
                    for index in local_matched_indices
                    if 0 <= index < len(remaining)
                )
                candidate_index = candidate_indices[0]
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
                        final_confirmation_required=False,
                    )
                if confirmation.status in {"unknown_needs_final_verifier", "backend_unavailable"}:
                    return PasswordBatchVerification(
                        ok=False,
                        status=confirmation.status,
                        matched_index=candidate_index,
                        matched_indices=candidate_indices,
                        attempts=total_fast_attempts,
                        test_result=confirmation.test_result,
                        error_text=confirmation.error_text or fast_outcome.error_text,
                        terminal=confirmation.terminal,
                        final_confirmation_required=True,
                        match_evidence=fast_outcome.match_evidence,
                    )
                if _is_headers_error(confirmation):
                    next_offset = fast_outcome.matched_index + 1
                    remaining = remaining[next_offset:]
                    offset = candidate_index + 1
                    continue
                if confirmation.status in {"damaged", "needs_volume_or_tail_damaged"}:
                    return PasswordBatchVerification(
                        ok=False,
                        status=confirmation.status,
                        matched_index=-1,
                        attempts=total_fast_attempts,
                        test_result=confirmation.test_result,
                        error_text=confirmation.error_text or fast_outcome.error_text,
                        terminal=True,
                        final_confirmation_required=False,
                        match_evidence=fast_outcome.match_evidence,
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
                    error_text=fast_outcome.error_text,
                    terminal=False,
                )

            if fast_outcome.status in {
                "damaged",
                "backend_unavailable",
                "needs_volume_or_tail_damaged",
            }:
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
            error_text=last_error,
            terminal=False,
        )

    def verify_fast_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        """Run bounded verifiers only; never invoke the full-payload fallback."""
        return self._run_fast_verifiers(
            archive_path,
            passwords,
            part_paths=part_paths,
            archive_input=archive_input,
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
            outcome = verifier.verify_batch(
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
        generic = [
            verifier
            for verifier in self.fast_verifiers
            if not _normalize_archive_format(str(getattr(verifier, "format_hint", "")))
        ]
        if not matching:
            return list(self.fast_verifiers)
        if _explicit_archive_format(archive_input):
            # Analysis-derived format is content evidence, unlike a filename
            # suffix. Avoid probing unrelated parsers for renamed large files.
            return matching + [verifier for verifier in generic if verifier not in matching]
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
            return PasswordBatchVerification(
                ok=False,
                status="unknown_needs_final_verifier",
                matched_index=0,
                matched_indices=(0,),
                attempts=1,
                error_text="fast password match requires final confirmation",
                terminal=False,
                final_confirmation_required=True,
            )
        return self.final_verifier.verify_batch(
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
        return self.final_verifier.verify_batch(
            archive_path,
            passwords,
            part_paths=part_paths,
            archive_input=archive_input,
        )




def _preferred_archive_format(archive_path: str, archive_input: dict | None = None) -> str:
    if isinstance(archive_input, dict):
        hinted = _normalize_archive_format(str(archive_input.get("format_hint") or archive_input.get("format") or ""))
        if hinted:
            return hinted
    return _format_from_path(archive_path)


def _explicit_archive_format(archive_input: dict | None = None) -> str:
    if not isinstance(archive_input, dict):
        return ""
    return _normalize_archive_format(str(archive_input.get("format_hint") or archive_input.get("format") or ""))


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


def _is_headers_error(confirmation: PasswordBatchVerification) -> bool:
    if confirmation.status != "damaged":
        return False
    if getattr(confirmation.test_result, "operation_result", None) == OPERATION_RESULT_HEADERS_ERROR:
        return True
    return "operation_result=headers_error" in (confirmation.error_text or "").lower()
