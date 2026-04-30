from sunpack.repair.pipeline.modules._compression_stream_block_salvage import CompressionStreamBlockSalvage
from sunpack.repair.pipeline.registry import register_repair_module


class GzipDeflatePrefixSalvage(CompressionStreamBlockSalvage):
    format_name = "gzip"
    aliases = ("gzip", "gz")
    module_name = "gzip_deflate_prefix_salvage"
    strategy = "deflate_prefix_salvage"
    route_flags = ("damaged", "checksum_error", "crc_error", "data_error", "deflate_resync", "payload_damaged")
    action_label = "gzip deflate prefix salvage"


register_repair_module(GzipDeflatePrefixSalvage())
