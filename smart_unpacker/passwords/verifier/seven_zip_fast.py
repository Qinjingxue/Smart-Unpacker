from __future__ import annotations

from smart_unpacker.passwords.verifier.base import PasswordBatchVerification
from smart_unpacker_native import seven_zip_fast_verify_passwords


class SevenZipFastVerifier:
    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
    ) -> PasswordBatchVerification:
        if part_paths:
            return PasswordBatchVerification(
                ok=False,
                status="unknown_needs_final_verifier",
                attempts=0,
                error_text="7z fast verifier does not support split archives yet",
            )
        normalized_passwords = list(passwords or [""])
        outcome = seven_zip_fast_verify_passwords(archive_path, normalized_passwords)
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
        )
