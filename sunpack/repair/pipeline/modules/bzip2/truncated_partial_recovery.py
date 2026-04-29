from sunpack.repair.pipeline.modules._compression_stream_partial import CompressionStreamPartialRecovery
from sunpack.repair.pipeline.registry import register_repair_module


class Bzip2TruncatedPartialRecovery(CompressionStreamPartialRecovery):
    format_name = "bzip2"
    aliases = ("bzip2", "bz2")
    module_name = "bzip2_truncated_partial_recovery"


register_repair_module(Bzip2TruncatedPartialRecovery())
