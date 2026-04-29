from packrelic.repair.pipeline.modules._tar_compressed_partial import TarCompressedPartialRecovery
from packrelic.repair.pipeline.registry import register_repair_module


class TarZstdTruncatedPartialRecovery(TarCompressedPartialRecovery):
    format_name = "tar.zst"
    aliases = ("tar.zst", "tar.zstd", "tzst", "zstd", "zst")
    module_name = "tar_zstd_truncated_partial_recovery"


register_repair_module(TarZstdTruncatedPartialRecovery())
