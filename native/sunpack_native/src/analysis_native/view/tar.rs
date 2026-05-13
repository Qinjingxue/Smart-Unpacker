fn u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn tar_header_plausible(header: &[u8]) -> (bool, &'static str, u64, bool) {
    if header.len() < TAR_BLOCK_SIZE {
        return (false, "short_tar_header", 0, false);
    }
    let Some(stored_checksum) = parse_octal(&header[148..156]) else {
        return (false, "invalid_checksum_field", 0, false);
    };
    let Some(member_size) = parse_octal(&header[124..136]) else {
        return (false, "invalid_size_field", 0, false);
    };
    if stored_checksum != tar_checksum(header) {
        return (false, "checksum_mismatch", 0, false);
    }
    (
        true,
        "",
        member_size,
        matches!(&header[257..263], b"ustar\x00" | b"ustar "),
    )
}

fn parse_octal(field: &[u8]) -> Option<u64> {
    let text = field
        .iter()
        .copied()
        .filter(|byte| *byte != 0 && *byte != b' ')
        .collect::<Vec<_>>();
    if text.is_empty() {
        return Some(0);
    }
    std::str::from_utf8(&text)
        .ok()
        .and_then(|value| u64::from_str_radix(value.trim(), 8).ok())
}

fn tar_checksum(header: &[u8]) -> u64 {
    header[..148].iter().map(|byte| *byte as u64).sum::<u64>()
        + 32 * 8
        + header[156..].iter().map(|byte| *byte as u64).sum::<u64>()
}

fn tar_padding(size: u64) -> u64 {
    let remainder = size % TAR_BLOCK_SIZE as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_SIZE as u64 - remainder
    }
}
