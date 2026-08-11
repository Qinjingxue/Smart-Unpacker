from __future__ import annotations

import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1


def _git_revision() -> str | None:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


@dataclass
class BenchmarkReport:
    scenario: str
    parameters: dict[str, Any] = field(default_factory=dict)
    samples: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if not result["environment"]:
            result["environment"] = {
                "revision": _git_revision(),
                "python": sys.version.split()[0],
                "platform": platform.platform(),
            }
        return result


def render_report(report: BenchmarkReport | dict[str, Any]) -> str:
    payload = report.to_dict() if isinstance(report, BenchmarkReport) else report
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def write_report(report: BenchmarkReport | dict[str, Any], path: Path | None) -> str:
    rendered = render_report(report)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    return rendered


def report_from_payload(scenario: str, payload: Any) -> BenchmarkReport:
    """Place an existing scenario result into the versioned report envelope."""
    if isinstance(payload, list):
        return BenchmarkReport(scenario=scenario, samples=payload)
    if not isinstance(payload, dict):
        return BenchmarkReport(scenario=scenario, summary={"result": payload})
    body = dict(payload)
    parameters = body.pop("parameters", body.pop("configuration", {}))
    environment = body.pop("environment", {})
    samples = body.pop("samples", [])
    if not samples and isinstance(body.get("runs"), list):
        samples = body.pop("runs")
    if not samples and isinstance(body.get("results"), list):
        samples = body.pop("results")
    summary = body.pop("summary", {})
    if not isinstance(summary, dict):
        summary = {"value": summary}
    summary.update(body)
    return BenchmarkReport(
        scenario=scenario,
        parameters=parameters if isinstance(parameters, dict) else {"value": parameters},
        samples=samples if isinstance(samples, list) else [{"value": samples}],
        summary=summary,
        environment=environment if isinstance(environment, dict) else {"value": environment},
    )
