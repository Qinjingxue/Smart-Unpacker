fn rar_walks(data: &[u8], max_candidates: usize) -> Vec<RarWalk> {
    let mut output = Vec::new();
    let mut candidates = find_all(data, RAR4_MAGIC)
        .into_iter()
        .map(|offset| (offset, RarVersion::Rar4))
        .chain(
            find_all(data, RAR5_MAGIC)
                .into_iter()
                .map(|offset| (offset, RarVersion::Rar5)),
        )
        .collect::<Vec<_>>();
    candidates.sort_by_key(|item| item.0);
    for (index, (offset, version)) in candidates.into_iter().enumerate() {
        if index >= max_candidates {
            break;
        }
        let walk = match version {
            RarVersion::Rar4 => walk_rar4_blocks(data, offset),
            RarVersion::Rar5 => walk_rar5_blocks(data, offset),
        };
        if let Some(walk) = walk {
            output.push(walk);
        }
    }
    output
}

fn walk_rar4_blocks(data: &[u8], offset: usize) -> Option<RarWalk> {
    if !data.get(offset..)?.starts_with(RAR4_MAGIC) {
        return None;
    }
    let mut pos = offset.checked_add(RAR4_MAGIC.len())?;
    let mut last_complete_end = pos;
    let mut blocks = 0usize;
    let mut missing_volume = false;
    let mut last_type = 0u8;
    let mut warnings = Vec::new();

    while pos < data.len() {
        if pos.checked_add(7)? > data.len() {
            warnings.push("RAR4 trailing block header is truncated".to_string());
            break;
        }
        let stored_crc = u16_le(data, pos) as u32;
        let header_type = data[pos + 2];
        let flags = u16_le(data, pos + 3);
        let header_size = u16_le(data, pos + 5) as usize;
        if !matches!(header_type, 0x73..=0x7b) {
            warnings.push("RAR4 block chain stopped before an unknown block type".to_string());
            break;
        }
        if header_size < 7 {
            warnings.push("RAR4 block chain stopped before an invalid header size".to_string());
            break;
        }
        let Some(header_end) = pos.checked_add(header_size) else {
            warnings.push("RAR4 block header size overflowed".to_string());
            break;
        };
        if header_end > data.len() {
            warnings.push("RAR4 block header is truncated".to_string());
            break;
        }
        let header = &data[pos..header_end];
        if (crc32(&header[2..]) & 0xffff) != stored_crc {
            warnings.push("RAR4 block chain stopped before a header CRC mismatch".to_string());
            break;
        }
        let add_size = if flags & 0x8000 != 0 {
            if header_size < 11 {
                warnings.push("RAR4 block add_size field is missing".to_string());
                break;
            }
            u32_le(header, 7) as usize
        } else {
            0
        };
        let Some(block_end) = header_end.checked_add(add_size) else {
            warnings.push("RAR4 block payload size overflowed".to_string());
            break;
        };
        if block_end > data.len() {
            warnings.push("RAR4 block payload is truncated".to_string());
            break;
        }
        if blocks == 0 && header_type == 0x73 && flags & 0x0001 != 0 {
            missing_volume = true;
        }
        blocks += 1;
        last_type = header_type;
        last_complete_end = block_end;
        pos = block_end;
        if header_type == 0x7b {
            return Some(RarWalk {
                version: RarVersion::Rar4,
                offset,
                last_complete_end,
                end_block_found: true,
                header_encrypted: false,
                missing_volume,
                last_block_can_precede_end: true,
                warnings,
            });
        }
    }

    (blocks > 0).then_some(RarWalk {
        version: RarVersion::Rar4,
        offset,
        last_complete_end,
        end_block_found: false,
        header_encrypted: false,
        missing_volume,
        last_block_can_precede_end: matches!(last_type, 0x74 | 0x7a),
        warnings,
    })
}

fn walk_rar5_blocks(data: &[u8], offset: usize) -> Option<RarWalk> {
    if !data.get(offset..)?.starts_with(RAR5_MAGIC) {
        return None;
    }
    let mut pos = offset.checked_add(RAR5_MAGIC.len())?;
    let mut last_complete_end = pos;
    let mut blocks = 0usize;
    let mut missing_volume = false;
    let mut last_type = 0u64;
    let mut warnings = Vec::new();

    while pos < data.len() {
        let Some(block) = parse_rar5_block(data, pos) else {
            warnings
                .push("RAR5 block chain stopped before a truncated or invalid block".to_string());
            break;
        };
        if block.end > data.len() {
            warnings.push("RAR5 block payload is truncated".to_string());
            break;
        }
        if !block.crc_ok {
            warnings.push("RAR5 block chain stopped before a header CRC mismatch".to_string());
            break;
        }
        if !matches!(block.block_type, 1..=5) && block.flags & 0x0004 == 0 {
            warnings.push("RAR5 block chain stopped before an unknown non-skippable block".to_string());
            break;
        }
        if blocks == 0 && block.block_type == 1 && block.archive_flags & 0x0001 != 0 {
            missing_volume = true;
        }
        blocks += 1;
        last_type = block.block_type;
        last_complete_end = block.end;
        pos = block.end;
        if block.block_type == 4 {
            warnings.push("RAR5 archive headers after the encryption header require a password".to_string());
            return Some(RarWalk {
                version: RarVersion::Rar5,
                offset,
                last_complete_end,
                end_block_found: false,
                header_encrypted: true,
                missing_volume,
                last_block_can_precede_end: false,
                warnings,
            });
        }
        if block.block_type == 5 {
            return Some(RarWalk {
                version: RarVersion::Rar5,
                offset,
                last_complete_end,
                end_block_found: true,
                header_encrypted: false,
                missing_volume,
                last_block_can_precede_end: true,
                warnings,
            });
        }
    }

    (blocks > 0).then_some(RarWalk {
        version: RarVersion::Rar5,
        offset,
        last_complete_end,
        end_block_found: false,
        header_encrypted: false,
        missing_volume,
        last_block_can_precede_end: matches!(last_type, 2 | 3),
        warnings,
    })
}

struct Rar5Block {
    block_type: u64,
    flags: u64,
    archive_flags: u64,
    end: usize,
    crc_ok: bool,
}

fn parse_rar5_block(data: &[u8], offset: usize) -> Option<Rar5Block> {
    if offset.checked_add(6)? > data.len() {
        return None;
    }
    let stored_crc = u32_le(data, offset);
    let (header_size, fields_start) = read_vint(data, offset + 4)?;
    if fields_start.saturating_sub(offset + 4) > 3 {
        return None;
    }
    let fields_end = fields_start.checked_add(usize::try_from(header_size).ok()?)?;
    if header_size == 0 || fields_end > data.len() {
        return None;
    }
    let (block_type, after_type) = read_vint(data, fields_start)?;
    let (flags, after_flags) = read_vint(data, after_type)?;
    let mut cursor = after_flags;
    if flags & 0x0001 != 0 {
        let (_, after_extra_size) = read_vint(data, cursor)?;
        cursor = after_extra_size;
    }
    let mut data_size = 0usize;
    if flags & 0x0002 != 0 {
        let (value, after_data_size) = read_vint(data, cursor)?;
        data_size = usize::try_from(value).ok()?;
        cursor = after_data_size;
    }
    if cursor > fields_end {
        return None;
    }
    let archive_flags = if block_type == 1 && cursor < fields_end {
        read_vint(data, cursor).map(|item| item.0).unwrap_or(0)
    } else {
        0
    };
    let end = fields_end.checked_add(data_size)?;
    let crc_ok = crc32(&data[offset + 4..fields_end]) == stored_crc;
    Some(Rar5Block {
        block_type,
        flags,
        archive_flags,
        end,
        crc_ok,
    })
}

fn rar4_end_block() -> Vec<u8> {
    rar4_block(0x7b, 0, &[])
}

fn rar5_end_block() -> Vec<u8> {
    rar5_block(5, 0, &[])
}

fn rar4_block(header_type: u8, flags: u16, payload: &[u8]) -> Vec<u8> {
    let add_size = if payload.is_empty() {
        Vec::new()
    } else {
        (payload.len() as u32).to_le_bytes().to_vec()
    };
    let header_size = 7 + add_size.len();
    let mut body = Vec::with_capacity(5 + add_size.len());
    body.push(header_type);
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&(header_size as u16).to_le_bytes());
    body.extend_from_slice(&add_size);
    let header_crc = (crc32(&body) & 0xffff) as u16;
    let mut output = Vec::with_capacity(header_size + payload.len());
    output.extend_from_slice(&header_crc.to_le_bytes());
    output.extend_from_slice(&body);
    output.extend_from_slice(payload);
    output
}

fn rar5_block(block_type: u64, flags: u64, data: &[u8]) -> Vec<u8> {
    rar5_header_block(block_type, flags, &[], data)
}

fn rar5_header_block(block_type: u64, flags: u64, tail_fields: &[u8], data: &[u8]) -> Vec<u8> {
    let mut effective_flags = flags;
    let mut fields = Vec::new();
    fields.extend_from_slice(&write_vint(block_type));
    if !data.is_empty() {
        effective_flags |= 0x0002;
    }
    fields.extend_from_slice(&write_vint(effective_flags));
    if !data.is_empty() {
        fields.extend_from_slice(&write_vint(data.len() as u64));
    }
    fields.extend_from_slice(tail_fields);
    let mut header_data = write_vint(fields.len() as u64);
    header_data.extend_from_slice(&fields);
    let mut output = Vec::with_capacity(4 + header_data.len() + data.len());
    output.extend_from_slice(&crc32(&header_data).to_le_bytes());
    output.extend_from_slice(&header_data);
    output.extend_from_slice(data);
    output
}

#[cfg(test)]
mod rar5_spec_tests {
    use super::*;

    #[test]
    fn unknown_skippable_block_is_walked() {
        let mut data = RAR5_MAGIC.to_vec();
        data.extend_from_slice(&rar5_header_block(9, 0x0004, &[], &[]));
        data.extend_from_slice(&rar5_end_block());
        let walk = walk_rar5_blocks(&data, 0).unwrap();
        assert!(walk.end_block_found);
        assert!(!walk.header_encrypted);
    }

    #[test]
    fn archive_encryption_header_is_valid_but_not_repairable_without_password() {
        let mut data = RAR5_MAGIC.to_vec();
        data.extend_from_slice(&rar5_header_block(4, 0, &[], &[]));
        data.extend_from_slice(&[0u8; 16]);
        let walk = walk_rar5_blocks(&data, 0).unwrap();
        assert!(walk.header_encrypted);
        assert!(!walk.end_block_found);
    }

    #[test]
    fn four_byte_header_size_vint_is_rejected() {
        let mut data = RAR5_MAGIC.to_vec();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&[0x80, 0x80, 0x80, 0x00, 1, 0]);
        assert!(walk_rar5_blocks(&data, 0).is_none());
    }
}

