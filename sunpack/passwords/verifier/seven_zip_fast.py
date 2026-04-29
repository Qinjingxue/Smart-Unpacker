from __future__ import annotations

from sunpack.passwords.verifier.base import PasswordBatchVerification
from sunpack.passwords.verifier.input import verifier_input
from sunpack_native import seven_zip_fast_verify_passwords, seven_zip_fast_verify_passwords_from_ranges


class SevenZipFastVerifier:
    format_hint = "7z"

    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        if part_paths:
            if archive_input:
                part_paths = None
            else:
                return PasswordBatchVerification(
                    ok=False,
                    status="unknown_needs_final_verifier",
                    attempts=0,
                    error_text="7z fast verifier does not support split archives yet",
                )
        verifier_path, ranges = verifier_input(
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        normalized_passwords = list(passwords or [""])
        outcome = (
            seven_zip_fast_verify_passwords_from_ranges(ranges, normalized_passwords)
            if ranges
            else seven_zip_fast_verify_passwords(verifier_path, normalized_passwords)
        )
        status = str(outcome.get("status") or "unknown_needs_final_verifier")
        matched_index = int(outcome.get("matched_index", -1))
        attempts = int(outcome.get("attempts", 0))
        message = str(outcome.get("message") or "")
        return PasswordBatchVerification(
            ok=status == "match" and matched_index >= 0,
            status=status,
            matched_index=matched_index,
            attempts=attempts,
            error_text=message.lower(),
            terminal=status == "damaged",
            final_confirmation_required="7z encrypted header opened" not in message.lower(),
        )
