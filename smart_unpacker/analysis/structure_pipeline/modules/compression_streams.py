from smart_unpacker.analysis.structure_pipeline.module import AnalysisModuleSpec
from smart_unpacker.analysis.structure_pipeline.registry import register_analysis_module
from smart_unpacker.analysis.result import ArchiveFormatEvidence, ArchiveSegment

GZIP_MAGIC = b"\x1f\x8b\x08"
BZIP2_MAGIC = b"BZh"
XZ_MAGIC = b"\xfd7zXZ\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


class _CompressionModule:
    name = ""
    fmt = ""
    magic = b""

    @property
    def spec(self):
        return AnalysisModuleSpec(name=self.name, formats=(self.fmt,), signatures=(self.magic,), io_profile="head_tail")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        result = view.probe_compression_stream(format=self.fmt)
        if not result.get("magic_matched"):
            return ArchiveFormatEvidence(format=self.fmt, confidence=0.0, status="not_found", details=result)
        if result.get("plausible"):
            confidence = float(result.get("confidence") or 0.88)
            return ArchiveFormatEvidence(
                format=self.fmt,
                confidence=confidence,
                status="extractable",
                segments=[ArchiveSegment(start_offset=0, end_offset=view.size, confidence=confidence, evidence=list(result.get("evidence") or []))],
                details=result,
            )
        return ArchiveFormatEvidence(
            format=self.fmt,
            confidence=0.35,
            status="weak",
            segments=[ArchiveSegment(start_offset=0, end_offset=None, confidence=0.35, damage_flags=[str(result.get("error") or "stream_unverified")], evidence=list(result.get("evidence") or []))],
            details=result,
        )


class GzipAnalysisModule(_CompressionModule):
    name = "gzip"
    fmt = "gzip"
    magic = GZIP_MAGIC


class Bzip2AnalysisModule(_CompressionModule):
    name = "bzip2"
    fmt = "bzip2"
    magic = BZIP2_MAGIC


class XzAnalysisModule(_CompressionModule):
    name = "xz"
    fmt = "xz"
    magic = XZ_MAGIC


class ZstdAnalysisModule(_CompressionModule):
    name = "zstd"
    fmt = "zstd"
    magic = ZSTD_MAGIC


class _CompressedTarModule:
    name = ""
    fmt = ""
    stream_fmt = ""

    @property
    def spec(self):
        return AnalysisModuleSpec(name=self.name, formats=(self.fmt,), signatures=(), io_profile="head_heavy")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        result = view.probe_compressed_tar(
            format=self.stream_fmt,
            max_probe_bytes=int(config.get("max_probe_bytes", 4 * 1024 * 1024) or 4 * 1024 * 1024),
        )
        if not result.get("magic_matched"):
            return ArchiveFormatEvidence(format=self.fmt, confidence=0.0, status="not_found", details=result)
        if result.get("tar_plausible"):
            confidence = 0.93 if result.get("plausible") else 0.75
            return ArchiveFormatEvidence(
                format=self.fmt,
                confidence=confidence,
                status="extractable",
                segments=[ArchiveSegment(start_offset=0, end_offset=view.size, confidence=confidence, evidence=list(result.get("evidence") or []) + ["tar:inner_header"])],
                details={**result, "inner_format": "tar"},
            )
        return ArchiveFormatEvidence(format=self.fmt, confidence=0.0, status="not_found", details=result)


class TarGzAnalysisModule(_CompressedTarModule):
    name = "tar_gz"
    fmt = "tar.gz"
    stream_fmt = "gzip"


class TarBz2AnalysisModule(_CompressedTarModule):
    name = "tar_bz2"
    fmt = "tar.bz2"
    stream_fmt = "bzip2"


class TarXzAnalysisModule(_CompressedTarModule):
    name = "tar_xz"
    fmt = "tar.xz"
    stream_fmt = "xz"


class TarZstAnalysisModule(_CompressedTarModule):
    name = "tar_zst"
    fmt = "tar.zst"
    stream_fmt = "zstd"


for module in (
    GzipAnalysisModule(),
    Bzip2AnalysisModule(),
    XzAnalysisModule(),
    ZstdAnalysisModule(),
    TarGzAnalysisModule(),
    TarBz2AnalysisModule(),
    TarXzAnalysisModule(),
    TarZstAnalysisModule(),
):
    register_analysis_module(module)
