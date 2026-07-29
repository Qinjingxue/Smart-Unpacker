from typing import Any

from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.identity import file_identity_for_context
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.analysis import EmbeddedScanResult, scan_embedded_archives


def _empty_result(*, complete: bool = False) -> dict[str, Any]:
    return EmbeddedScanResult.empty(complete=complete).to_dict()


@register_processor(
    "embedded_archive",
    input_facts={"file.path", "file.size", "executable.carrier"},
    output_facts={"embedded_archive.analysis"},
    schemas={
        "embedded_archive.analysis": {
            "type": "dict",
            "description": "Complete extension-independent embedded archive scan with every validated candidate.",
        },
    },
)
def process_embedded_archive_analysis(context: FactProcessorContext) -> dict[str, Any]:
    embedded_config = context.config.get("embedded_scan")
    if isinstance(embedded_config, dict) and not bool(embedded_config.get("enabled", True)):
        return _empty_result()
    if not bool(context.fact_bag.get("candidate.embedded_payload_precheck_enabled")):
        return _empty_result()
    carrier = context.fact_bag.get("executable.carrier") or {}
    if carrier.get("kind") == "runtime_bundle":
        return _empty_result()
    path = str(context.fact_bag.get("file.path") or "")
    file_size = context.fact_bag.get("file.size")
    if not path or not isinstance(file_size, int) or file_size <= 0:
        return _empty_result()
    try:
        return scan_embedded_archives(
            path,
            expected_size=file_size,
            identity=file_identity_for_context(context, path),
        ).to_dict()
    except OSError:
        return _empty_result()
