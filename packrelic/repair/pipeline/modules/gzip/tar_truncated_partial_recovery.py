from packrelic.repair.pipeline.modules._tar_compressed_partial import TarCompressedPartialRecovery
from packrelic.repair.pipeline.registry import register_repair_module


class TarGzipTruncatedPartialRecovery(TarCompressedPartialRecovery):
    format_name = "tar.gz"
    aliases = ("tar.gz", "tgz", "gzip", "gz")
    module_name = "tar_gzip_truncated_partial_recovery"


register_repair_module(TarGzipTruncatedPartialRecovery())
