from __future__ import annotations

from smart_unpacker.passwords.verifier.base import PasswordBatchVerification
from smart_unpacker.passwords.verifier.input import verifier_input
from smart_unpacker_native import rar_fast_verify_passwords, rar_fast_verify_passwords_from_ranges


class RarFastVerifier:
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
                    error_text="rar fast verifier does not support split archives yet",
                )
        verifier_path, ranges = verifier_input(
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        normalized_passwords = list(passwords or [""])
        outcome = (
            rar_fast_verify_passwords_from_ranges(ranges, normalized_passwords)
            if ranges
            else rar_fast_verify_passwords(verifier_path, normalized_passwords)
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
            final_confirmation_required="rar5 password check matched" not in message.lower(),
        )
