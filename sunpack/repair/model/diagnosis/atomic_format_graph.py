"""Compatibility entry point for the former shallow atomic-format graph.

The six formats now have independent, specification-backed semantic graphs.
Callers may keep using ``get_atomic_format_graph_plugin`` while migrating.
"""

from __future__ import annotations

from sunpack.repair.model.diagnosis.bzip2_graph import DEFINITION as BZIP2_DEFINITION
from sunpack.repair.model.diagnosis.gzip_graph import DEFINITION as GZIP_DEFINITION
from sunpack.repair.model.diagnosis.rar_graph import DEFINITION as RAR_DEFINITION
from sunpack.repair.model.diagnosis.semantic_format_graph import (
    SemanticFormatDiagnosisGraphPlugin,
    SemanticFormatGraphDefinition,
)
from sunpack.repair.model.diagnosis.tar_graph import DEFINITION as TAR_DEFINITION
from sunpack.repair.model.diagnosis.xz_graph import DEFINITION as XZ_DEFINITION
from sunpack.repair.model.diagnosis.zstd_graph import DEFINITION as ZSTD_DEFINITION


DEFINITIONS: dict[str, SemanticFormatGraphDefinition] = {
    definition.format_name: definition
    for definition in (
        RAR_DEFINITION,
        TAR_DEFINITION,
        GZIP_DEFINITION,
        BZIP2_DEFINITION,
        XZ_DEFINITION,
        ZSTD_DEFINITION,
    )
}


def get_atomic_format_graph_plugin(format_name: str) -> SemanticFormatDiagnosisGraphPlugin:
    try:
        definition = DEFINITIONS[format_name]
    except KeyError as exc:
        raise ValueError(f"unsupported semantic format graph: {format_name}") from exc
    return SemanticFormatDiagnosisGraphPlugin(definition)
