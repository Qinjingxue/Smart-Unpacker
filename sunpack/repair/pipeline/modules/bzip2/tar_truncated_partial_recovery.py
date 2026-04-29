from sunpack.repair.pipeline.modules._tar_compressed_partial import TarCompressedPartialRecovery
from sunpack.repair.pipeline.registry import register_repair_module


class TarBzip2TruncatedPartialRecovery(TarCompressedPartialRecovery):
    format_name = "tar.bz2"
    aliases = ("tar.bz2", "tbz2", "tbz", "bzip2", "bz2")
    module_name = "tar_bzip2_truncated_partial_recovery"


register_repair_module(TarBzip2TruncatedPartialRecovery())
