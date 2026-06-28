from types import SimpleNamespace

from sunpack.contracts.extraction import ExtractionResult
from sunpack.postprocess.recovery_outputs import (
    cleanup_beam_evaluations,
    cleanup_shelved_outcome,
    promote_beam_output,
    promote_recovery_outcome,
    shelve_outcome_if_needed,
)


def _outcome(path, attempt_id="attempt"):
    return SimpleNamespace(
        attempt_id=attempt_id,
        attempt_source="original",
        round_index=0,
        result=ExtractionResult(archive="archive.zip", all_parts=["archive.zip"], success=False, out_dir=str(path)),
    )


def test_shelve_and_promote_recovery_output(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "payload.bin").write_bytes(b"payload")
    outcome = _outcome(output)

    shelve_outcome_if_needed(outcome, str(output))

    held = tmp_path / "output.incumbent_attempt"
    assert held.is_dir()
    assert outcome.result.out_dir == str(held)

    promote_recovery_outcome(outcome, str(output))
    assert (output / "payload.bin").read_bytes() == b"payload"
    assert outcome.result.out_dir == str(output)


def test_cleanup_recovery_temporaries(tmp_path):
    held = tmp_path / "output.incumbent_old"
    held.mkdir()
    cleanup_shelved_outcome(_outcome(held))
    assert not held.exists()

    first = tmp_path / "candidate-1"
    second = tmp_path / "candidate-2"
    first.mkdir()
    second.mkdir()
    cleanup_beam_evaluations({"a": (None, None, None, str(first)), "b": (None, None, None, str(second))}, keep=str(second))
    assert not first.exists()
    assert second.is_dir()


def test_promote_beam_output_retargets_inventory_and_manifest(tmp_path):
    temporary = tmp_path / "candidate"
    manifest = temporary / ".sunpack" / "extraction_manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{}", encoding="utf-8")
    output = tmp_path / "output"
    result = ExtractionResult(
        archive="archive.zip",
        all_parts=["archive.zip"],
        success=True,
        out_dir=str(temporary),
        output_inventory_payload={"root": str(temporary)},
    )

    promoted = promote_beam_output(result, str(temporary), str(output))

    assert promoted.out_dir == str(output)
    assert promoted.output_inventory_payload["root"] == str(output.resolve())
    assert promoted.progress_manifest == str(output / ".sunpack" / "extraction_manifest.json")
