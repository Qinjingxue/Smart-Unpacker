from sunpack.repair.pipeline.modules._compression_stream_partial import CompressionStreamPartialRecovery
from sunpack.repair.pipeline.registry import register_repair_module


class ZstdTruncatedPartialRecovery(CompressionStreamPartialRecovery):
    format_name = "zstd"
    aliases = ("zstd", "zst")
    module_name = "zstd_truncated_partial_recovery"


register_repair_module(ZstdTruncatedPartialRecovery())
