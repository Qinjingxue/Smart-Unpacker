fn parse_local_header(data: &[u8], offset: usize) -> Option<LocalHeader> {
    if offset + LOCAL_HEADER_LEN > data.len() || &data[offset..offset + 4] != LFH_SIG {
        return None;
    }
    let name_len = u16_le(data, offset + 26);
    let extra_len = u16_le(data, offset + 28);
    let name_start = offset + LOCAL_HEADER_LEN;
    let extra_start = name_start.checked_add(name_len as usize)?;
    let data_start = extra_start.checked_add(extra_len as usize)?;
    if data_start > data.len() {
        return None;
    }
    Some(LocalHeader {
        offset,
        flags: u16_le(data, offset + 6),
        method: u16_le(data, offset + 8),
        crc32: u32_le(data, offset + 14),
        compressed_size: u32_le(data, offset + 18),
        uncompressed_size: u32_le(data, offset + 22),
        name: data[name_start..extra_start].to_vec(),
        extra: data[extra_start..data_start].to_vec(),
        extra_offset: extra_start,
        name_len,
        extra_len,
    })
}

fn parse_zip64_extra_tolerant(extra: &[u8], absolute_extra_offset: usize) -> Option<Zip64Extra> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let header_id = u16_le(extra, pos);
        let size = u16_le(extra, pos + 2) as usize;
        let value_start = pos + 4;
        let value_end = value_start.saturating_add(size).min(extra.len());
        if header_id == 0x0001 {
            let mut values = Vec::new();
            let mut value_offsets = Vec::new();
            let mut cursor = value_start;
            while cursor + 8 <= value_end {
                values.push(u64_le(extra, cursor));
                value_offsets.push(absolute_extra_offset + cursor);
                cursor += 8;
            }
            let (disk_start, disk_start_offset) = if cursor + 4 == value_end {
                (Some(u32_le(extra, cursor)), Some(absolute_extra_offset + cursor))
            } else {
                (None, None)
            };
            return Some(Zip64Extra {
                values,
                value_offsets,
                disk_start,
                disk_start_offset,
                size_offset: absolute_extra_offset + pos + 2,
                stored_size: size,
            });
        }
        let next = value_start.saturating_add(size);
        if next <= pos || next > extra.len() {
            break;
        }
        pos = next;
    }
    None
}

fn central_zip64_local_header_offset(entry: &CentralEntry, zip64: &Zip64Extra) -> Option<u64> {
    let mut index = 0usize;
    if entry.uncompressed_size == u32::MAX {
        index += 1;
    }
    if entry.compressed_size == u32::MAX {
        index += 1;
    }
    if entry.local_header_offset == u32::MAX {
        zip64.values.get(index).copied()
    } else {
        None
    }
}

fn find_zip64_eocd(data: &[u8], before: usize) -> Option<Zip64Eocd> {
    let pos = memmem::rfind(&data[..before.min(data.len())], ZIP64_EOCD_SIG)?;
    if pos + 56 > data.len() {
        return None;
    }
    let record_size = u64_le(data, pos + 4);
    let end = pos
        .checked_add(12)?
        .checked_add(usize::try_from(record_size).ok()?)?;
    if end > data.len() || end < pos + 56 {
        return None;
    }
    Some(Zip64Eocd {
        offset: pos,
        end,
        total_entries: u64_le(data, pos + 32),
        cd_size: u64_le(data, pos + 40),
        cd_offset: u64_le(data, pos + 48),
    })
}

fn find_zip64_locator(data: &[u8], eocd_offset: usize) -> Option<Zip64Locator> {
    let pos = memmem::rfind(&data[..eocd_offset.min(data.len())], ZIP64_LOCATOR_SIG)?;
    if pos + 20 > data.len() {
        return None;
    }
    Some(Zip64Locator {
        offset: pos,
        end: pos + 20,
        zip64_eocd_offset: u64_le(data, pos + 8),
        total_disks: u32_le(data, pos + 16),
    })
}

fn zip64_locator_bytes(zip64_offset: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(20);
    output.extend_from_slice(ZIP64_LOCATOR_SIG);
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&zip64_offset.to_le_bytes());
    output.extend_from_slice(&1u32.to_le_bytes());
    output
}

fn find_local_for_central(data: &[u8], entry: &CentralEntry) -> Option<LocalHeader> {
    let mut candidates = Vec::new();
    if entry.local_header_offset != 0xFFFF_FFFF {
        candidates.push(entry.local_header_offset as usize);
    }
    if let Some(zip64) = parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset) {
        if let Some(offset) = central_zip64_local_header_offset(entry, &zip64) {
            if let Ok(offset) = usize::try_from(offset) {
                candidates.push(offset);
            }
        }
    }
    for offset in candidates {
        if let Some(local) = parse_local_header(data, offset) {
            if local.name == entry.name {
                return Some(local);
            }
        }
    }
    let mut pos = memmem::find(data, LFH_SIG)?;
    loop {
        if let Some(local) = parse_local_header(data, pos) {
            if local.name == entry.name {
                return Some(local);
            }
        }
        let next_start = pos + 4;
        if next_start >= data.len() {
            return None;
        }
        let Some(next) = memmem::find(&data[next_start..], LFH_SIG) else {
            return None;
        };
        pos = next_start + next;
    }
}

fn find_local_for_central_offset_only(data: &[u8], entry: &CentralEntry) -> Option<LocalHeader> {
    if entry.local_header_offset != 0xFFFF_FFFF {
        if let Some(local) = parse_local_header(data, entry.local_header_offset as usize) {
            return Some(local);
        }
    }
    if let Some(zip64) = parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset) {
        if let Some(offset) = central_zip64_local_header_offset(entry, &zip64) {
            return parse_local_header(data, usize::try_from(offset).ok()?);
        }
    }
    None
}

fn cd_local_reconcile_indices(data: &[u8], entries: &[RecoveredEntry]) -> (Vec<usize>, usize) {
    let structurally_available = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.verified || entry.passthrough)
        .collect::<Vec<_>>();
    if structurally_available.is_empty() {
        return (Vec::new(), 0);
    }
    let central_entries = parse_best_central_entries(data);
    if central_entries.is_empty() {
        return (
            structurally_available.into_iter().map(|(index, _)| index).collect::<Vec<_>>(),
            0,
        );
    }
    let mut selected = Vec::new();
    let mut used = std::collections::HashSet::new();
    let mut corrected_offsets = 0usize;
    for central in &central_entries {
        let mut best: Option<(i64, usize, bool)> = None;
        for (index, local) in entries.iter().enumerate() {
            if !(local.verified || local.passthrough) || used.contains(&index) {
                continue;
            }
            let score = reconcile_score(central, local);
            if score <= 0 {
                continue;
            }
            let corrected = central.local_header_offset as usize != local.local_header_offset;
            let key = (score, std::cmp::Reverse(local.local_header_offset));
            let replace = best
                .as_ref()
                .map(|(best_score, best_index, _)| {
                    key > (*best_score, std::cmp::Reverse(entries[*best_index].local_header_offset))
                })
                .unwrap_or(true);
            if replace {
                best = Some((score, index, corrected));
            }
        }
        if let Some((_, index, corrected)) = best {
            used.insert(index);
            selected.push(index);
            if corrected {
                corrected_offsets += 1;
            }
        }
    }
    if selected.is_empty() {
        selected = entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| (entry.verified || entry.passthrough).then_some(index))
            .collect();
    }
    selected.sort_by_key(|index| entries[*index].local_header_offset);
    (selected, corrected_offsets)
}

fn parse_best_central_entries(data: &[u8]) -> Vec<CentralEntry> {
    if let Some(eocd) = find_eocd_record(data, true) {
        let cd_end = (eocd.cd_offset as usize).saturating_add(eocd.cd_size as usize);
        let entries = parse_central_directory_entries(data, eocd.cd_offset as usize, cd_end);
        if !entries.is_empty() {
            return entries;
        }
    }
    if let Some(cd) = find_valid_central_directory(data) {
        return parse_central_directory_entries(data, cd.offset, cd.end);
    }
    Vec::new()
}

fn reconcile_score(central: &CentralEntry, local: &RecoveredEntry) -> i64 {
    let mut score = 0i64;
    if central.name == local.name {
        score += 1000;
    } else if entry_name_key(&central.name) == entry_name_key(&local.name) {
        score += 700;
    } else {
        return 0;
    }
    if central.method == local.method {
        score += 120;
    }
    if central.crc32 == local.crc32 {
        score += 180;
    }
    if central.compressed_size as u64 == local.compressed_size {
        score += 80;
    }
    if central.uncompressed_size as u64 == local.uncompressed_size {
        score += 80;
    }
    if central.local_header_offset as usize == local.local_header_offset {
        score += 40;
    } else {
        score += 20;
    }
    if local.boundary_source == BoundarySource::DeflateConsumed
        || local.boundary_source == BoundarySource::NextRecord
    {
        score += 30;
    }
    score
}

#[cfg(test)]
mod zip64_extra_spec_tests {
    use super::*;

    #[test]
    fn central_zip64_extra_keeps_four_byte_disk_start() {
        let local_offset = 0x1_0000_0020u64;
        let disk_start = 7u32;
        let mut extra = Vec::new();
        extra.extend_from_slice(&0x0001u16.to_le_bytes());
        extra.extend_from_slice(&12u16.to_le_bytes());
        extra.extend_from_slice(&local_offset.to_le_bytes());
        extra.extend_from_slice(&disk_start.to_le_bytes());
        let parsed = parse_zip64_extra_tolerant(&extra, 100).unwrap();
        assert_eq!(parsed.values, vec![local_offset]);
        assert_eq!(parsed.disk_start, Some(disk_start));
        assert_eq!(parsed.disk_start_offset, Some(112));

        let entry = CentralEntry {
            offset: 0,
            flags: 0,
            method: 0,
            crc32: 0,
            compressed_size: 1,
            uncompressed_size: 1,
            name_len: 0,
            extra_len: extra.len() as u16,
            name: Vec::new(),
            extra,
            extra_offset: 100,
            disk_number_start: u16::MAX,
            local_header_offset: u32::MAX,
        };
        assert_eq!(central_zip64_local_header_offset(&entry, &parsed), Some(local_offset));
        assert_eq!(expected_zip64_central_size(&entry), 12);
    }
}

