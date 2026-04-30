from sunpack.repair.pipeline.modules._compression_stream_block_salvage import CompressionStreamBlockSalvage
from sunpack.repair.pipeline.registry import register_repair_module


class Bzip2BlockSalvage(CompressionStreamBlockSalvage):
    format_name = "bzip2"
    aliases = ("bzip2", "bz2")
    module_name = "bzip2_block_salvage"
    strategy = "block_salvage"
    route_flags = ("damaged", "checksum_error", "crc_error", "data_error", "block_damaged", "payload_damaged")
    action_label = "bzip2 block salvage"


register_repair_module(Bzip2BlockSalvage())
