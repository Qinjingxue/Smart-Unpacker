from __future__ import annotations

import argparse
import json
from pathlib import Path

from repair_training.schemas import (
    TrainingAction,
    TrainingCandidateSnapshot,
    TrainingEpisode,
    TrainingTransition,
    TrainingVerificationSnapshot,
)
from sunpack.contracts.archive_input import ArchiveInputDescriptor
from sunpack.contracts.archive_state import ArchiveState
from sunpack.repair.job import RepairJob
from sunpack.repair.policy.training_runtime import archive_state_for_job, runtime_context_from_job


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "schema-smoke":
        return _schema_smoke()
    if args.command == "runtime-smoke":
        return _runtime_smoke(Path(args.archive), args.format)
    raise SystemExit(f"unknown command: {args.command}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Policy-lab training utilities.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("schema-smoke", help="Validate training episode schema round trip.")
    runtime = sub.add_parser("runtime-smoke", help="Validate training runtime adapter on one archive.")
    runtime.add_argument("archive")
    runtime.add_argument("--format", default="zip")
    return parser


def _schema_smoke() -> int:
    episode = TrainingEpisode(
        episode_id="schema-smoke",
        format="zip",
        source_identity={"kind": "smoke"},
        corrupted_input={"kind": "file", "path": "smoke.zip"},
        initial_state={"source": {"kind": "file", "path": "smoke.zip"}},
        initial_state_digest="root",
        transitions=[
            TrainingTransition(
                round_index=1,
                state_digest="root",
                patch_depth=0,
                candidate_snapshots=[
                    TrainingCandidateSnapshot(candidate_id="c1", module_name="smoke", format="zip")
                ],
                available_actions=[TrainingAction(action_type="module", candidate_id="c1")],
                selected_action=TrainingAction(action_type="module", candidate_id="c1"),
                next_state_digest="patched",
                verification_before=TrainingVerificationSnapshot(score=0.0),
                verification_after=TrainingVerificationSnapshot(score=1.0),
                reward=1.0,
                terminal=True,
            )
        ],
        terminal={"status": "ok"},
    )
    restored = TrainingEpisode.from_dict(episode.to_dict())
    print(json.dumps({"ok": restored.to_dict() == episode.to_dict(), "schema_version": restored.schema_version}, sort_keys=True))
    return 0


def _runtime_smoke(path: Path, fmt: str) -> int:
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(path), format_hint=fmt)
    state = ArchiveState.from_archive_input(descriptor)
    job = RepairJob(
        source_input=descriptor.to_source_input(),
        format=fmt,
        archive_state=state,
        knowledge={"source": {"input": descriptor.to_source_input()}, "analysis": {"summary": {"format": fmt}}},
    )
    restored = archive_state_for_job(job)
    context = runtime_context_from_job(job)
    print(json.dumps({
        "ok": restored is not None,
        "patch_digest": restored.effective_patch_digest() if restored is not None else "",
        "runtime_schema": context.get("schema_version"),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

