from sunpack.repair.pipeline.modules._compression_stream_block_salvage import CompressionStreamBlockSalvage
from sunpack.repair.pipeline.registry import register_repair_module


class XzBlockSalvage(CompressionStreamBlockSalvage):
    format_name = "xz"
    aliases = ("xz", "tar.xz", "txz")
    module_name = "xz_block_salvage"
    strategy = "block_salvage"
    route_flags = ("damaged", "checksum_error", "crc_error", "data_error", "block_damaged", "payload_damaged")
    action_label = "xz block salvage"


register_repair_module(XzBlockSalvage())
