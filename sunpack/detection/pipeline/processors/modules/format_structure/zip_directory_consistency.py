from typing import Any

from sunpack.analysis import ArchiveAnalyzer, ZipDeepProbeOptions
from sunpack.analysis.probes.zip import DEFAULT_MAX_DEEP_ENTRIES, probe_zip_directory_consistency_path
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor


DEFAULT_MAX_ENTRIES = DEFAULT_MAX_DEEP_ENTRIES


def inspect_zip_directory_consistency(
    path: str,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    identity: tuple[str, int, int] | None = None,
) -> dict[str, Any]:
    return probe_zip_directory_consistency_path(
        path,
        ZipDeepProbeOptions(max_entries=max_entries),
        identity=identity,
    ).to_raw_dict()


@register_processor(
    "zip_directory_consistency",
    input_facts={"file.path"},
    output_facts={"zip.directory_consistency"},
    schemas={
        "zip.directory_consistency": {
            "type": "dict",
            "description": "ZIP central directory, local header, descriptor, and ZIP64 consistency facts.",
        },
    },
)
def process_zip_directory_consistency(context: FactProcessorContext) -> dict[str, Any]:
    path = context.fact_bag.get("file.path") or ""
    return ArchiveAnalyzer(context.config).probe_zip_directory_consistency(
        path,
        ZipDeepProbeOptions(max_entries=int(context.fact_config.get("max_entries", DEFAULT_MAX_ENTRIES))),
    ).to_raw_dict()
