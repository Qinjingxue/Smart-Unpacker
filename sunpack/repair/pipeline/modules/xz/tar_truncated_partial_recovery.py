from sunpack.repair.pipeline.modules._tar_compressed_partial import TarCompressedPartialRecovery
from sunpack.repair.pipeline.registry import register_repair_module


class TarXzTruncatedPartialRecovery(TarCompressedPartialRecovery):
    format_name = "tar.xz"
    aliases = ("tar.xz", "txz", "xz")
    module_name = "tar_xz_truncated_partial_recovery"


register_repair_module(TarXzTruncatedPartialRecovery())
