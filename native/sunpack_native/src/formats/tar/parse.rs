fn find_magic_offsets(data: &[u8], magic: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    if magic.is_empty() || data.len() < magic.len() {
        return offsets;
    }
    let mut start = 0usize;
    while start + magic.len() <= data.len() {
        let Some(pos) = data[start..]
            .windows(magic.len())
            .position(|window| window == magic)
        else {
            break;
        };
        let absolute = start + pos;
        offsets.push(absolute);
        start = absolute + 1;
    }
    offsets
}

fn repair_tar_checksums(
    data: &[u8],
    options: &StreamRepairOptions,
    max_entries: usize,
) -> Result<TarRepair, String> {
    let mut offset = 0usize;
    let mut patches = Vec::new();
    let mut entries = 0usize;
    while offset + 512 <= data.len() {
        if max_entries > 0 && entries >= max_entries {
            break;
        }
        let header = &data[offset..offset + 512];
        if is_zero_block(header) {
            break;
        }
        let Some(size) = parse_tar_number(&header[124..136]) else {
            break;
        };
        let computed = tar_checksum(header);
        if parse_tar_number(&header[148..156]) != Some(computed) {
            patches.push(TarBytePatch {
                offset: (offset + 148) as u64,
                data: format_tar_checksum(computed).to_vec(),
            });
        }
        let Some(payload_span) = padded_tar_payload_span(size) else {
            break;
        };
        offset = offset
            .checked_add(512)
            .and_then(|value| value.checked_add(payload_span))
            .ok_or_else(|| "TAR member size overflowed".to_string())?;
        entries += 1;
    }
    if patches.is_empty() {
        return Err("no TAR header checksum mismatch was found".to_string());
    }
    if options
        .max_output_bytes
        .is_some_and(|limit| data.len() as u64 > limit)
    {
        return Err("repaired TAR exceeds repair.deep.max_output_size_mb".to_string());
    }
    Ok(TarRepair {
        patches,
        truncate_at: None,
        append_data: None,
        confidence: 0.88,
        actions: vec!["recompute_tar_header_checksum"],
        message: "TAR header checksums were recomputed by native repair".to_string(),
    })
}

fn repair_tar_trailing_junk(data: &[u8]) -> Result<TarRepair, String> {
    let payload_end = walk_tar_payload_end(data)
        .ok_or_else(|| "TAR entries could not be walked safely".to_string())?;
    let end = canonical_tar_end(data, payload_end);
    if end.saturating_sub(payload_end) < 1024 {
        return Err("TAR does not have two trusted trailing zero blocks".to_string());
    }
    if end == data.len() {
        return Err("no trailing bytes after TAR zero blocks".to_string());
    }
    Ok(TarRepair {
        patches: Vec::new(),
        truncate_at: Some(end as u64),
        append_data: None,
        confidence: 0.86,
        actions: vec!["trim_after_tar_zero_blocks"],
        message: "TAR trailing junk was trimmed by native repair".to_string(),
    })
}

fn repair_tar_trailing_zero_blocks(data: &[u8]) -> Result<TarRepair, String> {
    let payload_end = walk_tar_payload_end(data)
        .ok_or_else(|| "TAR entries could not be walked safely".to_string())?;
    let end = canonical_tar_end(data, payload_end);
    let zero_bytes_present = end.saturating_sub(payload_end);
    let missing_zeros = 1024usize.saturating_sub(zero_bytes_present.min(1024));
    if end == data.len() && missing_zeros == 0 {
        return Err("TAR already has canonical zero block ending".to_string());
    }
    Ok(TarRepair {
        patches: Vec::new(),
        truncate_at: Some(end as u64),
        append_data: (missing_zeros > 0).then(|| vec![0u8; missing_zeros]),
        confidence: 0.84,
        actions: vec!["trim_or_append_tar_zero_blocks"],
        message: "TAR trailing zero blocks were normalized by native repair".to_string(),
    })
}

fn walk_tar_payload_end(data: &[u8]) -> Option<usize> {
    let mut offset = 0usize;
    while offset + 512 <= data.len() {
        let header = &data[offset..offset + 512];
        if is_zero_block(header) {
            return Some(offset);
        }
        let size = parse_tar_number(&header[124..136])?;
        let payload_span = padded_tar_payload_span(size)?;
        offset = offset.checked_add(512)?.checked_add(payload_span)?;
    }
    (offset == data.len()).then_some(offset)
}

fn canonical_tar_end(data: &[u8], payload_end: usize) -> usize {
    let mut end = payload_end;
    while end + 512 <= data.len() && is_zero_block(&data[end..end + 512]) {
        end += 512;
        if end >= payload_end + 1024 {
            break;
        }
    }
    end
}

fn crc32(bytes: &[u8]) -> u32 {
    crc32_hash(bytes)
}

fn write_tar_repair_candidate(
    data: &[u8],
    repair: &TarRepair,
    output: &Path,
) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<u64, String> {
        let mut file = File::create(&temp).map_err(|err| err.to_string())?;
        let end = repair
            .truncate_at
            .map(|value| value as usize)
            .unwrap_or(data.len())
            .min(data.len());
        let mut cursor = 0usize;
        let mut patches = repair.patches.iter().collect::<Vec<_>>();
        patches.sort_by_key(|patch| patch.offset);
        for patch in patches {
            let offset = patch.offset as usize;
            if offset < cursor || offset + patch.data.len() > end {
                return Err("TAR patch is out of range".to_string());
            }
            file.write_all(&data[cursor..offset])
                .map_err(|err| err.to_string())?;
            file.write_all(&patch.data).map_err(|err| err.to_string())?;
            cursor = offset + patch.data.len();
        }
        file.write_all(&data[cursor..end])
            .map_err(|err| err.to_string())?;
        if let Some(append_data) = &repair.append_data {
            file.write_all(append_data).map_err(|err| err.to_string())?;
        }
        file.flush().map_err(|err| err.to_string())?;
        Ok((end + repair.append_data.as_ref().map_or(0, Vec::len)) as u64)
    })();
    match result {
        Ok(written) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(written)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn repair_tar_prefix(
    data: &[u8],
    options: &StreamRepairOptions,
    max_entries: usize,
) -> Result<TarPrefixRepair, String> {
    let mut output = Vec::with_capacity(data.len().saturating_add(1024));
    let mut offset = 0usize;
    let mut members = 0u64;
    let mut checksum_fixes = 0u64;
    let mut truncated_members = 0u64;
    let mut warnings = Vec::new();

    while offset + 512 <= data.len() {
        if max_entries > 0 && members as usize >= max_entries {
            warnings.push("compressed TAR recovery reached repair.deep.max_entries".to_string());
            break;
        }

        let header = &data[offset..offset + 512];
        if is_zero_block(header) {
            break;
        }

        let Some(size) = parse_tar_number(&header[124..136]) else {
            if members == 0 {
                return Err("no plausible TAR header was found in decoded stream".to_string());
            }
            warnings.push("stopped before a TAR header with an invalid size field".to_string());
            break;
        };
        if !plausible_tar_header(header) {
            if members == 0 {
                return Err("decoded stream does not begin with a plausible TAR header".to_string());
            }
            warnings.push("stopped before an implausible TAR header".to_string());
            break;
        }

        let Some(payload_span) = padded_tar_payload_span(size) else {
            warnings.push("stopped before a TAR member with an oversized payload".to_string());
            break;
        };
        let Some(member_end) = offset
            .checked_add(512)
            .and_then(|value| value.checked_add(payload_span))
        else {
            warnings
                .push("stopped before a TAR member with an overflowing payload span".to_string());
            break;
        };
        if member_end > data.len() {
            truncated_members += 1;
            warnings.push("dropped a trailing TAR member whose payload is truncated".to_string());
            break;
        }

        let mut fixed_header = header.to_vec();
        let computed = tar_checksum(&fixed_header);
        let stored = parse_tar_number(&fixed_header[148..156]);
        if stored != Some(computed) {
            fixed_header[148..156].copy_from_slice(&format_tar_checksum(computed));
            checksum_fixes += 1;
        }

        output.extend_from_slice(&fixed_header);
        output.extend_from_slice(&data[offset + 512..member_end]);
        members += 1;
        offset = member_end;
    }

    if members == 0 {
        return Err("decoded stream contains no complete TAR members".to_string());
    }
    output.extend_from_slice(&[0u8; 1024]);
    if options
        .max_output_bytes
        .is_some_and(|limit| output.len() as u64 > limit)
    {
        return Err("repaired TAR stream exceeds repair.deep.max_output_size_mb".to_string());
    }
    let changed = output.as_slice() != data;
    Ok(TarPrefixRepair {
        tar_bytes: output.len() as u64,
        bytes: output,
        members,
        checksum_fixes,
        truncated_members,
        changed,
        warnings,
    })
}

