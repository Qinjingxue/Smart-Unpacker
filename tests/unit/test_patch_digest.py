from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState, PatchPlan


def test_patch_digest_is_stable_across_roundtrip_and_observation_changes(tmp_path):
    source = tmp_path / "sample.zip"
    source.write_bytes(b"broken")
    patch = PatchPlan(
        id="empty-attempt",
        operations=[],
        provenance={
            "module": "zip_fix_eocd_record",
            "policy_patch_status": "empty_failed",
            "failure_reason": "not_applicable",
            "diagnostics": {"elapsed_ms": 12},
        },
        confidence=0.9,
    )
    state = ArchiveState.from_archive_input(
        ArchiveInputDescriptor(entry_path=str(source), open_mode="file", format_hint="zip"),
        patches=[patch],
    )
    observed = ArchiveState(
        source=state.source,
        patches=list(state.patches),
        patch_digest=state.patch_digest,
        logical_name="renamed-display-name",
        format_hint="zip",
        analysis={"status": "damaged"},
        verification={"completeness": 0.2},
        knowledge={"large": "observation"},
    )

    assert PatchPlan.from_dict(patch.to_dict()).digest() == patch.digest()
    assert ArchiveState.from_dict(observed.to_dict()).effective_patch_digest() == state.effective_patch_digest()


def test_empty_patch_semantics_affect_patch_digest(tmp_path):
    source = tmp_path / "sample.zip"
    source.write_bytes(b"broken")
    descriptor = ArchiveInputDescriptor(entry_path=str(source), open_mode="file", format_hint="zip")
    first = ArchiveState.from_archive_input(descriptor, patches=[
        PatchPlan(operations=[], provenance={"module": "zip_fix_eocd_record", "failure_reason": "not_applicable"})
    ])
    second = ArchiveState.from_archive_input(descriptor, patches=[
        PatchPlan(operations=[], provenance={"module": "zip_fix_cd_offset", "failure_reason": "not_applicable"})
    ])

    assert first.effective_patch_digest() != second.effective_patch_digest()


def test_stale_serialized_digest_is_replaced_by_canonical_digest(tmp_path):
    source = tmp_path / "sample.zip"
    source.write_bytes(b"broken")
    state = ArchiveState.from_archive_input(
        ArchiveInputDescriptor(entry_path=str(source), open_mode="file", format_hint="zip"),
        patches=[PatchPlan(module="zip_fix_eocd_record")],
    )
    payload = state.to_dict()
    payload["patch_digest"] = "stale-digest"

    restored = ArchiveState.from_dict(payload)

    assert restored.patch_digest == state.effective_patch_digest()
    assert restored.patch_digest != "stale-digest"
