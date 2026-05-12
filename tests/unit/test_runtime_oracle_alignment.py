from __future__ import annotations

import zlib

from repair_training.collect_runtime_repair_graph import (
    _runtime_oracle_disagreement_reason,
    verify_extraction_output_against_oracle,
)
from sunpack.extraction.result import ExtractionResult
from sunpack.verification.result import DECISION_ACCEPT, VerificationResult


def _crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def _result(tmp_path, files: dict[str, bytes]) -> ExtractionResult:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    manifest_files = []
    for name, payload in files.items():
        path = out_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        manifest_files.append(
            {
                "path": str(path),
                "archive_path": name,
                "status": "complete",
                "bytes_written": len(payload),
            }
        )
    return ExtractionResult(
        success=True,
        archive="sample.zip",
        out_dir=str(out_dir),
        all_parts=[],
        progress_manifest_payload={"files": manifest_files},
    )


def test_extraction_oracle_rejects_metadata_only_payload_match(tmp_path):
    extraction = _result(tmp_path, {"a.txt": b"BAD!"})
    oracle = {
        "expected_files": {
            "a.txt": {
                "name": "a.txt",
                "size": 4,
                "crc32": _crc32(b"GOOD"),
            }
        }
    }

    result = verify_extraction_output_against_oracle(extraction, oracle)

    assert result["status"] == "hard_negative"
    assert result["label"] == -1
    assert result["complete_files"] == 0
    assert result["failed_files"] == 1


def test_zero_byte_entry_requires_actual_output_file(tmp_path):
    oracle = {
        "expected_files": {
            "empty.txt": {
                "name": "empty.txt",
                "size": 0,
                "crc32": _crc32(b""),
            }
        }
    }

    complete = verify_extraction_output_against_oracle(_result(tmp_path, {"empty.txt": b""}), oracle)
    missing = verify_extraction_output_against_oracle(None, oracle)

    assert complete["status"] == "complete"
    assert complete["label"] == 3
    assert missing["status"] == "missing_extraction_output"
    assert missing["label"] == 0


def test_physical_partial_without_payload_hash_cannot_be_complete(tmp_path):
    extraction = _result(tmp_path, {"a.txt": b"payload"})
    oracle = {
        "expected_files": {
            "a.txt": {
                "name": "a.txt",
                "size": 7,
            }
        }
    }

    result = verify_extraction_output_against_oracle(
        extraction,
        oracle,
        record={"physical_complete_expected": False, "damage_profile": "partial_payload_many_entries_bad"},
    )

    assert result["status"] == "partial"
    assert result["label"] == 1
    assert result["oracle_cap_reason"] == "physical_complete_not_expected_or_payload_oracle_missing"


def test_missing_extraction_output_does_not_fallback_to_archive_metadata():
    oracle = {
        "expected_files": {
            "a.txt": {
                "name": "a.txt",
                "size": 4,
                "crc32": _crc32(b"data"),
            }
        }
    }

    result = verify_extraction_output_against_oracle(None, oracle)

    assert result["status"] == "missing_extraction_output"
    assert result["oracle_source"] == "extraction_output"
    assert result["completeness"] == 0.0


def test_runtime_accept_but_oracle_partial_reports_disagreement_reason(tmp_path):
    extraction = _result(tmp_path, {"a.txt": b"BAD!"})
    oracle = {
        "expected_files": {
            "a.txt": {
                "name": "a.txt",
                "size": 4,
                "crc32": _crc32(b"GOOD"),
            }
        }
    }
    result = verify_extraction_output_against_oracle(extraction, oracle)
    verification = VerificationResult(decision_hint=DECISION_ACCEPT)

    reason = _runtime_oracle_disagreement_reason(verification, result)

    assert reason == "payload_hash_mismatch"
