from types import SimpleNamespace

import pytest

from sunpack.cli.cli import build_cli_parser
from sunpack.cli.cli_context import CliContext
from sunpack.cli.cli_runtime import apply_runtime_config_overrides
from sunpack.config.fields.extraction import normalize_extraction_config
from sunpack.config.fields.verification import normalize_verification_config
from sunpack.contracts.content_recovery import (
    CONTENT_REQUIREMENT_ALLOW_PARTIAL,
    CONTENT_REQUIREMENT_COMPLETE,
    ContentRecoveryPolicy,
    require_complete_content,
)
from sunpack.repair.config import normalize_repair_config
from sunpack.repair.scheduler import RepairScheduler


@pytest.mark.parametrize("flag", ["--allow-partial", "--ap"])
def test_extract_cli_partial_flags_share_one_policy_override(flag):
    parser = build_cli_parser(CliContext(language="en"), command="extract")
    args = parser.parse_args(["extract", flag, "archive.zip"])
    config = {"extraction": {"content_requirement": CONTENT_REQUIREMENT_COMPLETE}}

    overrides = apply_runtime_config_overrides(config, args)

    assert args.allow_partial is True
    assert overrides["content_requirement"] == CONTENT_REQUIREMENT_ALLOW_PARTIAL
    assert ContentRecoveryPolicy.from_config(config).allows_partial


def test_content_requirement_defaults_to_complete_and_validates_values():
    assert normalize_extraction_config({})["content_requirement"] == CONTENT_REQUIREMENT_COMPLETE
    with pytest.raises(ValueError, match="content_requirement"):
        normalize_extraction_config({"content_requirement": "best-effort-ish"})


def test_watch_runtime_force_overrides_partial_without_mutating_other_settings():
    config = {
        "extraction": {"content_requirement": CONTENT_REQUIREMENT_ALLOW_PARTIAL, "quiet": True},
        "watch": {"enabled": True},
    }

    require_complete_content(config)

    assert config["extraction"] == {"content_requirement": CONTENT_REQUIREMENT_COMPLETE, "quiet": True}


def test_obsolete_partial_acceptance_switches_are_removed_from_normalized_config():
    verification = normalize_verification_config({
        "enabled": True,
        "accept_partial_when_source_damaged": True,
        "partial_min_completeness": 0.1,
    })
    repair = normalize_repair_config({
        "continue_after_partial": False,
        "safety": {
            "allow_unsafe": False,
            "allow_partial": False,
            "allow_lossy": False,
        },
        "beam": {"return_best_partial": False},
    })

    assert "accept_partial_when_source_damaged" not in verification
    assert "partial_min_completeness" not in verification
    assert "continue_after_partial" not in repair
    assert "allow_partial" not in repair["safety"]
    assert "return_best_partial" not in repair["beam"]


def test_partial_repair_modules_are_not_filtered_by_final_content_policy():
    scheduler = RepairScheduler.__new__(RepairScheduler)
    module = SimpleNamespace(
        spec=SimpleNamespace(safe=True, partial=True, lossy=False),
    )

    reasons = scheduler._safety_reasons(
        module,
        {"safety": {"allow_unsafe": False, "allow_partial": False, "allow_lossy": False}},
    )

    assert reasons == []
