from packrelic.repair.pipeline.modules._compression_stream_partial import CompressionStreamPartialRecovery
from packrelic.repair.pipeline.registry import register_repair_module


class XzTruncatedPartialRecovery(CompressionStreamPartialRecovery):
    format_name = "xz"
    aliases = ("xz",)
    module_name = "xz_truncated_partial_recovery"


register_repair_module(XzTruncatedPartialRecovery())
