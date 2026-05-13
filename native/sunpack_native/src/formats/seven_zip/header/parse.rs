fn seven_zip_candidate(data: &[u8], offset: usize) -> Option<ArchiveCandidate> {
    let header = parse_seven_zip_header(data, offset)?;
    if !header.start_crc_ok() {
        return None;
    }
    let mut warnings = Vec::new();
    if !header.next_header_crc_ok() {
        warnings.push(
            "7z NextHeader CRC is invalid; crop candidate requires later CRC repair".to_string(),
        );
    }
    Some(ArchiveCandidate {
        format: TargetFormat::SevenZip,
        offset,
        archive_end: header.archive_end,
        start_crc_ok: header.start_crc_ok(),
        next_header_crc_ok: header.next_header_crc_ok(),
        warnings,
    })
}

fn loose_seven_zip_header_facts(data: &[u8], offset: usize) -> SevenZipLooseHeaderFacts {
    if offset.checked_add(SEVEN_Z_HEADER_SIZE).is_none_or(|end| end > data.len()) {
        return SevenZipLooseHeaderFacts {
            stored_start_crc: 0,
            computed_start_crc: 0,
            start_crc_ok: false,
            next_header_offset: 0,
            next_header_size: 0,
            range_valid: false,
        };
    }
    let stored_start_crc = u32_le(data, offset + 8);
    let mut start_header = [0u8; 20];
    start_header.copy_from_slice(&data[offset + 12..offset + 32]);
    let computed_start_crc = crc32(&start_header);
    let next_header_offset = u64_le(&start_header, 0);
    let next_header_size = u64_le(&start_header, 8);
    let range_valid = (|| {
        let relative_end = (SEVEN_Z_HEADER_SIZE as u64)
            .checked_add(next_header_offset)?
            .checked_add(next_header_size)?;
        let archive_end = offset.checked_add(usize::try_from(relative_end).ok()?)?;
        if next_header_size == 0 || archive_end > data.len() {
            return None;
        }
        let next_header_start = offset
            .checked_add(SEVEN_Z_HEADER_SIZE)?
            .checked_add(usize::try_from(next_header_offset).ok()?)?;
        if next_header_start >= archive_end {
            return None;
        }
        Some(())
    })()
    .is_some();
    SevenZipLooseHeaderFacts {
        stored_start_crc,
        computed_start_crc,
        start_crc_ok: stored_start_crc == computed_start_crc,
        next_header_offset,
        next_header_size,
        range_valid,
    }
}
fn parse_seven_zip_header(data: &[u8], offset: usize) -> Option<SevenZipHeader> {
    if offset.checked_add(SEVEN_Z_HEADER_SIZE)? > data.len()
        || !data[offset..].starts_with(SEVEN_Z_MAGIC)
    {
        return None;
    }
    if data[offset + 6] != 0 {
        return None;
    }
    let stored_start_crc = u32_le(data, offset + 8);
    let mut start_header = [0u8; 20];
    start_header.copy_from_slice(&data[offset + 12..offset + 32]);
    let computed_start_crc = crc32(&start_header);
    let next_header_offset = u64_le(&start_header, 0);
    let next_header_size = u64_le(&start_header, 8);
    let stored_next_header_crc = u32_le(&start_header, 16);
    if next_header_size == 0 {
        return None;
    }
    let relative_end = (SEVEN_Z_HEADER_SIZE as u64)
        .checked_add(next_header_offset)?
        .checked_add(next_header_size)?;
    let archive_end = offset.checked_add(usize::try_from(relative_end).ok()?)?;
    if archive_end > data.len() {
        return None;
    }
    let next_header_start = offset
        .checked_add(SEVEN_Z_HEADER_SIZE)?
        .checked_add(usize::try_from(next_header_offset).ok()?)?;
    if next_header_start >= archive_end {
        return None;
    }
    let next_header = &data[next_header_start..archive_end];
    let computed_next_header_crc = crc32(next_header);
    let nid = next_header.first().copied().unwrap_or(0);
    Some(SevenZipHeader {
        archive_end,
        start_header,
        next_header_start,
        next_header_offset,
        next_header_size,
        next_header_nid: nid,
        stored_start_crc,
        computed_start_crc,
        stored_next_header_crc,
        computed_next_header_crc,
        next_header_nid_valid: nid == SZ_HEADER || nid == SZ_ENCODED_HEADER,
    })
}

impl SevenZipHeader {
    fn start_crc_ok(&self) -> bool {
        self.stored_start_crc == self.computed_start_crc
    }

    fn next_header_crc_ok(&self) -> bool {
        self.stored_next_header_crc == self.computed_next_header_crc
    }
}

fn read_sz_vint(data: &[u8], pos: &mut usize) -> Option<SevenZipVintSpan> {
    let start = *pos;
    let first = *data.get(*pos)?;
    *pos += 1;
    let mut mask = 0x80u8;
    let mut value = 0u64;
    for extra in 0..8 {
        if first & mask == 0 {
            let low_mask = mask.saturating_sub(1);
            value |= ((first & low_mask) as u64) << (8 * extra);
            return Some(SevenZipVintSpan {
                start,
                end: *pos,
                value,
            });
        }
        let byte = *data.get(*pos)? as u64;
        *pos += 1;
        value |= byte << (8 * extra);
        mask >>= 1;
    }
    Some(SevenZipVintSpan {
        start,
        end: *pos,
        value,
    })
}

fn write_sz_vint(mut value: u64) -> Vec<u8> {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut extra = 0usize;
    while extra < 8 {
        if value < (1u64 << (7 * (extra + 1))) {
            first |= (value >> (8 * extra)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        extra += 1;
    }
    let mut output = vec![first];
    while extra > 0 {
        output.push((value & 0xff) as u8);
        value >>= 8;
        extra -= 1;
    }
    output
}

fn replace_header_vint(header: &[u8], span: SevenZipVintSpan, value: u64) -> Vec<u8> {
    let mut output = Vec::with_capacity(header.len() + 4);
    output.extend_from_slice(&header[..span.start]);
    output.extend_from_slice(&write_sz_vint(value));
    output.extend_from_slice(&header[span.end..]);
    output
}

fn replace_header_u32_le(header: &[u8], start: usize, value: u32) -> Vec<u8> {
    let mut output = header.to_vec();
    if start + 4 <= output.len() {
        output[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }
    output
}

fn replace_header_range(header: &[u8], start: usize, end: usize, replacement: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(header.len().saturating_sub(end.saturating_sub(start)) + replacement.len());
    output.extend_from_slice(&header[..start.min(header.len())]);
    output.extend_from_slice(replacement);
    output.extend_from_slice(&header[end.min(header.len())..]);
    output
}

fn parse_seven_zip_header_ast(data: &[u8], header: &SevenZipHeader) -> Result<SevenZipHeaderAst, String> {
    if header.next_header_nid != SZ_HEADER {
        return Err("7z next header is not a plain Header tree".to_string());
    }
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z next header range is invalid".to_string())?;
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_HEADER) {
        return Err("7z Header NID is missing".to_string());
    }
    pos += 1;
    let mut pack_info = None;
    let mut files_info = None;
    loop {
        let Some(nid) = raw.get(pos).copied() else {
            return Err("7z Header tree ended before End NID".to_string());
        };
        pos += 1;
        match nid {
            SZ_END => break,
            SZ_MAIN_STREAMS_INFO => {
                pack_info = parse_seven_zip_streams_info(raw, &mut pos)?;
            }
            SZ_FILES_INFO => {
                files_info = Some(parse_seven_zip_files_info(raw, &mut pos)?);
            }
            _ => {
                return Err(format!("unsupported 7z Header NID 0x{nid:02x}"));
            }
        }
    }
    Ok(SevenZipHeaderAst {
        header: raw.to_vec(),
        pack_info,
        files_info,
    })
}

fn parse_seven_zip_encoded_pack_prefix(raw: &[u8]) -> Result<(SevenZipVintSpan, SevenZipVintSpan, usize), String> {
    if raw.first().copied() != Some(SZ_ENCODED_HEADER) {
        return Err("encoded_header_nid_missing".to_string());
    }
    if raw.get(1).copied() != Some(SZ_PACK_INFO) {
        return Err("encoded_header_pack_info_missing".to_string());
    }
    let mut pos = 2usize;
    let pack_pos = read_sz_vint(raw, &mut pos).ok_or_else(|| "encoded_header_pack_pos_truncated".to_string())?;
    let num_streams = read_sz_vint(raw, &mut pos).ok_or_else(|| "encoded_header_pack_stream_count_truncated".to_string())?;
    Ok((pack_pos, num_streams, pos))
}

fn parse_seven_zip_encoded_header_ast(data: &[u8], header: &SevenZipHeader) -> Result<SevenZipHeaderAst, String> {
    if header.next_header_nid != SZ_ENCODED_HEADER {
        return Err("7z next header is not an EncodedHeader tree".to_string());
    }
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z encoded header range is invalid".to_string())?;
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_ENCODED_HEADER) {
        return Err("7z EncodedHeader NID is missing".to_string());
    }
    pos += 1;
    if raw.get(pos).copied() != Some(SZ_PACK_INFO) {
        return Err("7z EncodedHeader PackInfo is missing".to_string());
    }
    pos += 1;
    let pack_info = Some(parse_seven_zip_pack_info(raw, &mut pos)?);
    Ok(SevenZipHeaderAst {
        header: raw.to_vec(),
        pack_info,
        files_info: None,
    })
}

fn parse_seven_zip_streams_info(
    data: &[u8],
    pos: &mut usize,
) -> Result<Option<SevenZipPackInfoAst>, String> {
    let mut pack_info = None;
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z StreamsInfo ended before End NID".to_string());
        };
        *pos += 1;
        match nid {
            SZ_END => break,
            SZ_PACK_INFO => {
                pack_info = Some(parse_seven_zip_pack_info(data, pos)?);
            }
            SZ_UNPACK_INFO => skip_seven_zip_unhandled_property_tree(data, pos, "UnpackInfo")?,
            SZ_SUB_STREAMS_INFO => skip_seven_zip_unhandled_property_tree(data, pos, "SubStreamsInfo")?,
            _ => return Err(format!("unsupported 7z StreamsInfo NID 0x{nid:02x}")),
        }
    }
    Ok(pack_info)
}

fn parse_seven_zip_pack_info(
    data: &[u8],
    pos: &mut usize,
) -> Result<SevenZipPackInfoAst, String> {
    let pack_pos = read_sz_vint(data, pos).ok_or_else(|| "7z PackInfo PackPos is truncated".to_string())?;
    let num_streams_raw = read_sz_vint(data, pos).ok_or_else(|| "7z PackInfo NumPackStreams is truncated".to_string())?;
    let num_streams = usize::try_from(num_streams_raw.value)
        .map_err(|_| "7z PackInfo stream count is too large".to_string())?;
    if num_streams > SEVEN_Z_MAX_HEADER_STREAMS {
        return Err("7z PackInfo stream count exceeds repair parser limit".to_string());
    }
    let mut sizes = Vec::new();
    let mut crc_values = Vec::new();
    let mut crc_defined_all = false;
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z PackInfo ended before End NID".to_string());
        };
        *pos += 1;
        match nid {
            SZ_END => break,
            SZ_SIZE => {
                sizes.clear();
                for _ in 0..num_streams {
                    let span = read_sz_vint(data, pos)
                        .ok_or_else(|| "7z PackInfo PackSizes is truncated".to_string())?;
                    sizes.push(span);
                }
            }
            SZ_CRC => {
                let defined = parse_seven_zip_bool_vector(data, pos, num_streams)?;
                crc_defined_all = defined.iter().all(|item| *item);
                crc_values.clear();
                for is_defined in defined {
                    if is_defined {
                        if *pos + 4 > data.len() {
                            return Err("7z PackInfo CRC values are truncated".to_string());
                        }
                        let start = *pos;
                        let value = u32_le(data, *pos);
                        *pos += 4;
                        crc_values.push(SevenZipCrcSpan { start, value });
                    }
                }
            }
            _ => return Err(format!("unsupported 7z PackInfo NID 0x{nid:02x}")),
        }
    }
    Ok(SevenZipPackInfoAst {
        pack_pos,
        num_streams,
        sizes,
        crc_values,
        crc_defined_all,
    })
}

fn parse_seven_zip_bool_vector(
    data: &[u8],
    pos: &mut usize,
    count: usize,
) -> Result<Vec<bool>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let all_defined = *data
        .get(*pos)
        .ok_or_else(|| "7z boolean vector is truncated".to_string())?;
    *pos += 1;
    if all_defined != 0 {
        return Ok(vec![true; count]);
    }
    let byte_count = (count + 7) / 8;
    if *pos + byte_count > data.len() {
        return Err("7z boolean bitset is truncated".to_string());
    }
    let mut output = Vec::with_capacity(count);
    for index in 0..count {
        let byte = data[*pos + index / 8];
        output.push((byte & (0x80 >> (index % 8))) != 0);
    }
    *pos += byte_count;
    Ok(output)
}

fn parse_seven_zip_files_info(
    data: &[u8],
    pos: &mut usize,
) -> Result<SevenZipFilesInfoAst, String> {
    let num_files = read_sz_vint(data, pos).ok_or_else(|| "7z FilesInfo file count is truncated".to_string())?;
    if num_files.value > SEVEN_Z_MAX_HEADER_FILES {
        return Err("7z FilesInfo file count exceeds repair parser limit".to_string());
    }
    let mut empty_stream_property = None;
    let mut empty_file_property = None;
    let mut anti_property = None;
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err("7z FilesInfo ended before End NID".to_string());
        };
        *pos += 1;
        if nid == SZ_END {
            break;
        }
        let size = read_sz_vint(data, pos)
            .ok_or_else(|| "7z FilesInfo property size is truncated".to_string())?;
        let prop_start = *pos;
        let prop_size = usize::try_from(size.value)
            .map_err(|_| "7z FilesInfo property size is too large".to_string())?;
        let prop_end = prop_start
            .checked_add(prop_size)
            .ok_or_else(|| "7z FilesInfo property range overflowed".to_string())?;
        if prop_end > data.len() {
            return Err("7z FilesInfo property is truncated".to_string());
        }
        match nid {
            SZ_EMPTY_STREAM => empty_stream_property = Some((prop_start, prop_end)),
            SZ_EMPTY_FILE => empty_file_property = Some((prop_start, prop_end)),
            SZ_ANTI => anti_property = Some((prop_start, prop_end)),
            _ => {}
        }
        *pos = prop_end;
    }
    Ok(SevenZipFilesInfoAst {
        num_files,
        empty_stream_property,
        empty_file_property,
        anti_property,
    })
}

fn skip_seven_zip_unhandled_property_tree(
    data: &[u8],
    pos: &mut usize,
    label: &str,
) -> Result<(), String> {
    loop {
        let Some(nid) = data.get(*pos).copied() else {
            return Err(format!("7z {label} ended before End NID"));
        };
        *pos += 1;
        if nid == SZ_END {
            return Ok(());
        }
        match nid {
            SZ_SIZE | SZ_CRC => {
                return Err(format!("7z {label} requires a full folder graph parser"));
            }
            _ => return Err(format!("unsupported 7z {label} NID 0x{nid:02x}")),
        }
    }
}

fn find_next_header_candidate(data: &[u8], max_scan: usize) -> Option<(u64, u64)> {
    if data.len() < 33 || !data.starts_with(SEVEN_Z_MAGIC) {
        return None;
    }
    let stored_offset = u64_le(data, 12);
    let stored_size = u64_le(data, 20);
    let stored_crc = u32_le(data, 28);
    let scan_end = data.len().min(SEVEN_Z_HEADER_SIZE + max_scan);
    let preferred_start = SEVEN_Z_HEADER_SIZE.checked_add(usize::try_from(stored_offset).ok()?)?;
    let mut starts = Vec::new();
    if preferred_start >= SEVEN_Z_HEADER_SIZE && preferred_start < scan_end {
        starts.push(preferred_start);
    }
    for index in (SEVEN_Z_HEADER_SIZE..scan_end).rev() {
        if matches!(data[index], SZ_HEADER | SZ_ENCODED_HEADER) && !starts.contains(&index) {
            starts.push(index);
            if starts.len() >= 64 {
                break;
            }
        }
    }
    let mut best: Option<(u64, u64)> = None;
    let mut best_score: Option<(u8, u64)> = None;
    for start in starts {
        for end in seven_zip_candidate_header_ends(data, start, scan_end, stored_size, max_scan) {
            if crc32(&data[start..end]) != stored_crc {
                continue;
            }
            let next_offset = (start - SEVEN_Z_HEADER_SIZE) as u64;
            let next_size = (end - start) as u64;
            if !next_header_semantically_plausible(
                &data[start..end],
                stored_offset,
                stored_size,
                next_offset,
                next_size,
            ) {
                continue;
            }
            let score = (
                if next_offset == stored_offset { 0 } else { 1 },
                next_size.abs_diff(stored_size),
            );
            if best_score.is_none_or(|current| score < current) {
                best = Some((next_offset, next_size));
                best_score = Some(score);
            }
        }
    }
    best
}

fn seven_zip_candidate_header_ends(
    data: &[u8],
    start: usize,
    scan_end: usize,
    stored_size: u64,
    max_scan: usize,
) -> Vec<usize> {
    let mut output = Vec::new();
    let max_candidate_bytes = max_scan.min(65_536).max(1);
    let max_end = data.len().min(scan_end).min(start.saturating_add(max_candidate_bytes));
    if start >= max_end {
        return output;
    }
    if stored_size > 0 {
        if let Ok(size) = usize::try_from(stored_size) {
            if let Some(end) = start.checked_add(size) {
                if end > start && end <= max_end {
                    output.push(end);
                }
            }
        }
    }
    let mut zero_ended = 0usize;
    for index in start + 1..=max_end {
        if data[index - 1] != SZ_END {
            continue;
        }
        if !output.contains(&index) {
            output.push(index);
            zero_ended += 1;
        }
        if zero_ended >= 32 {
            break;
        }
    }
    output.sort_unstable();
    output.dedup();
    output
}

fn next_header_semantically_plausible(
    candidate: &[u8],
    stored_offset: u64,
    stored_size: u64,
    next_offset: u64,
    next_size: u64,
) -> bool {
    if candidate.is_empty() || !matches!(candidate[0], 0x01 | 0x17) {
        return false;
    }
    if candidate.len() <= 16 && candidate.iter().all(|item| *item <= 0x19) {
        return true;
    }
    if *candidate.last().unwrap_or(&0xff) != 0 {
        return false;
    }
    if next_offset != stored_offset {
        let max_reasonable_growth = 4096u64.max(stored_size.saturating_mul(16));
        if next_size > max_reasonable_growth {
            return false;
        }
    }
    true
}
