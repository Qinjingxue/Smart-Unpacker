from __future__ import annotations

from smart_unpacker.passwords.verifier.base import PasswordBatchVerification
from smart_unpacker.passwords.verifier.input import cleanup_fast_verifier_path, fast_verifier_archive_path
from smart_unpacker_native import seven_zip_fast_verify_passwords


class SevenZipFastVerifier:
    def verify_batch(
        self,
        archive_path: str,
        passwords: list[str],
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> PasswordBatchVerification:
        if part_paths:
            if archive_input and archive_input.get("open_mode") == "file_range":
                part_paths = None
            else:
                return PasswordBatchVerification(
                    ok=False,
                    status="unknown_needs_final_verifier",
                    attempts=0,
                    error_text="7z fast verifier does not support split archives yet",
                )
        verifier_path, temporary = fast_verifier_archive_path(
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        try:
            normalized_passwords = list(passwords or [""])
            outcome = seven_zip_fast_verify_passwords(verifier_path, normalized_passwords)
        finally:
            cleanup_fast_verifier_path(verifier_path, temporary)
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
