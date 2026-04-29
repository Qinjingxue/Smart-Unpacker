from packrelic.repair.pipeline.modules._compression_stream_partial import CompressionStreamPartialRecovery
from packrelic.repair.pipeline.registry import register_repair_module


class GzipTruncatedPartialRecovery(CompressionStreamPartialRecovery):
    format_name = "gzip"
    aliases = ("gzip", "gz")
    module_name = "gzip_truncated_partial_recovery"


register_repair_module(GzipTruncatedPartialRecovery())
