from typing import Any

from sunpack.analysis import ArchiveAnalyzer, MultiVolumeAnalysisSource
from sunpack.detection.pipeline.processors.context import FactProcessorContext
from sunpack.detection.pipeline.processors.registry import register_processor
from sunpack.detection.pipeline.processors.modules.format_structure.multi_volume import detection_analysis_volumes


def inspect_zip_local_header(path: str, offset: int, identity: tuple[str, int, int] | None = None) -> dict[str, Any]:
    del identity
    return ArchiveAnalyzer().probe_zip_local_header(path, offset=offset).to_raw_dict()


@register_processor(
    "zip_structure",
    input_facts={"file.path"},
    output_facts={"zip.local_header"},
    schemas={
        "zip.local_header": {
            "type": "dict",
            "description": "ZIP local header plausibility at the beginning of the candidate file.",
        },
    },
)
def process_zip_local_header(context: FactProcessorContext) -> dict[str, Any]:
    return ArchiveAnalyzer(context.config).probe_zip_local_header(
        MultiVolumeAnalysisSource(tuple(detection_analysis_volumes(context))),
    ).to_raw_dict()
