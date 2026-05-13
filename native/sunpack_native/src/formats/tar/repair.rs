fn downgrade_tar_metadata(
    data: &[u8],
    options: &StreamRepairOptions,
    max_entries: usize,
) -> Result<TarPrefixRepair, String> {
    let mut output = Vec::with_capacity(data.len().saturating_add(1024));
    let mut offset = 0usize;
    let mut members = 0u64;
    let mut skipped_metadata = 0u64;
    let mut checksum_fixes = 0u64;
    let mut warnings = Vec::new();
    while offset + 512 <= data.len() {
        if max_entries > 0 && members as usize >= max_entries {
            warnings.push("TAR metadata downgrade reached repair.deep.max_entries".to_string());
            break;
        }
        let header = &data[offset..offset + 512];
        if is_zero_block(header) {
            break;
        }
        let Some(size) = parse_tar_number(&header[124..136]) else {
            if members == 0 {
                return Err("no plausible TAR header was found".to_string());
            }
            warnings.push("stopped before a TAR header with an invalid size field".to_string());
            break;
        };
        if !plausible_tar_header(header) {
            if members == 0 {
                return Err("input does not begin with a plausible TAR header".to_string());
            }
            warnings.push("stopped before an implausible TAR header".to_string());
            break;
        }
        let Some(payload_span) = padded_tar_payload_span(size) else {
            break;
        };
        let Some(member_end) = offset
            .checked_add(512)
            .and_then(|value| value.checked_add(payload_span))
        else {
            break;
        };
        if member_end > data.len() {
            break;
        }
        let typeflag = header[156];
        if matches!(typeflag, b'x' | b'g' | b'L' | b'K' | b'S') {
            skipped_metadata += 1;
            offset = member_end;
            continue;
        }
        if matches!(typeflag, b'0' | 0) {
            let mut fixed_header = header.to_vec();
            let computed = tar_checksum(&fixed_header);
            if parse_tar_number(&fixed_header[148..156]) != Some(computed) {
                fixed_header[148..156].copy_from_slice(&format_tar_checksum(computed));
                checksum_fixes += 1;
            }
            output.extend_from_slice(&fixed_header);
            output.extend_from_slice(&data[offset + 512..member_end]);
            members += 1;
        }
        offset = member_end;
    }
    if members == 0 || skipped_metadata == 0 {
        return Err(
            "no TAR metadata member could be downgraded while preserving regular payloads"
                .to_string(),
        );
    }
    output.extend_from_slice(&[0u8; 1024]);
    if options
        .max_output_bytes
        .is_some_and(|limit| output.len() as u64 > limit)
    {
        return Err("repaired TAR exceeds repair.deep.max_output_size_mb".to_string());
    }
    warnings.push(format!(
        "downgraded or skipped {skipped_metadata} TAR metadata headers"
    ));
    Ok(TarPrefixRepair {
        tar_bytes: output.len() as u64,
        bytes: output,
        members,
        checksum_fixes,
        truncated_members: 0,
        changed: true,
        warnings,
    })
}

fn repair_tar_sparse_pax_longname(
    data: &[u8],
    options: &StreamRepairOptions,
    max_entries: usize,
) -> Result<TarPrefixRepair, String> {
    let mut output = Vec::with_capacity(data.len().saturating_add(1024));
    let mut offset = 0usize;
    let mut members = 0u64;
    let mut skipped_metadata = 0u64;
    let mut checksum_fixes = 0u64;
    let mut truncated_members = 0u64;
    let mut warnings = Vec::new();
    let mut pending_long_name: Option<String> = None;
    while offset + 512 <= data.len() {
        if members as usize >= max_entries {
            warnings.push("TAR sparse/PAX repair reached repair.deep.max_entries".to_string());
            break;
        }
        let header = &data[offset..offset + 512];
        if is_zero_block(header) {
            break;
        }
        if !plausible_tar_header(header) {
            let Some(next) = find_next_plausible_tar_header(data, offset + 512) else {
                if members == 0 {
                    return Err("input does not contain a recoverable TAR member".to_string());
                }
                warnings.push("stopped before an implausible TAR header".to_string());
                break;
            };
            warnings.push(format!(
                "resynchronized TAR scan from offset {offset} to {next}"
            ));
            offset = next;
            continue;
        }
        let Some(size) = parse_tar_number(&header[124..136]) else {
            break;
        };
        let Some(payload_span) = padded_tar_payload_span(size) else {
            break;
        };
        let Some(member_end) = offset
            .checked_add(512)
            .and_then(|value| value.checked_add(payload_span))
        else {
            break;
        };
        if member_end > data.len() {
            truncated_members += 1;
            break;
        }
        let typeflag = header[156];
        match typeflag {
            b'L' => {
                pending_long_name = tar_payload_text(data, offset + 512, size as usize);
                skipped_metadata += 1;
            }
            b'x' | b'g' | b'K' | b'S' => {
                skipped_metadata += 1;
            }
            b'0' | 0 => {
                let payload = &data[offset + 512..member_end];
                let mut fixed = header.to_vec();
                if let Some(name) = pending_long_name.take() {
                    write_tar_name(&mut fixed, &name);
                }
                fixed[156] = b'0';
                let computed = tar_checksum(&fixed);
                if parse_tar_number(&fixed[148..156]) != Some(computed) {
                    fixed[148..156].copy_from_slice(&format_tar_checksum(computed));
                    checksum_fixes += 1;
                }
                output.extend_from_slice(&fixed);
                output.extend_from_slice(payload);
                members += 1;
            }
            b'5' => {
                let mut fixed = header.to_vec();
                if let Some(name) = pending_long_name.take() {
                    write_tar_name(&mut fixed, &name);
                }
                fixed[124..136].copy_from_slice(b"00000000000\0");
                let computed = tar_checksum(&fixed);
                fixed[148..156].copy_from_slice(&format_tar_checksum(computed));
                output.extend_from_slice(&fixed);
                members += 1;
                checksum_fixes += 1;
            }
            _ => {
                skipped_metadata += 1;
            }
        }
        offset = member_end;
    }
    if members == 0 {
        return Err("no TAR regular file or directory could be preserved".to_string());
    }
    if skipped_metadata == 0 && checksum_fixes == 0 && truncated_members == 0 {
        return Err("TAR sparse/PAX/GNU longname repair found nothing to normalize".to_string());
    }
    output.extend_from_slice(&[0u8; 1024]);
    if options
        .max_output_bytes
        .is_some_and(|limit| output.len() as u64 > limit)
    {
        return Err("repaired TAR exceeds repair.deep.max_output_size_mb".to_string());
    }
    warnings.push(format!(
        "dropped or downgraded {skipped_metadata} TAR metadata/sparse headers"
    ));
    Ok(TarPrefixRepair {
        bytes: output,
        tar_bytes: 0,
        members,
        checksum_fixes,
        truncated_members,
        changed: true,
        warnings,
    })
}

fn find_next_plausible_tar_header(data: &[u8], start: usize) -> Option<usize> {
    let mut offset = align_up_512(start);
    while offset + 512 <= data.len() {
        if plausible_tar_header(&data[offset..offset + 512]) {
            return Some(offset);
        }
        offset += 512;
    }
    None
}

fn align_up_512(value: usize) -> usize {
    value.saturating_add(511) / 512 * 512
}

fn tar_payload_text(data: &[u8], start: usize, size: usize) -> Option<String> {
    let end = start.checked_add(size)?.min(data.len());
    let raw = &data[start..end];
    let nul = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    let text = String::from_utf8_lossy(&raw[..nul]).replace('\\', "/");
    let safe = text
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/");
    (!safe.is_empty()).then_some(safe)
}

fn write_tar_name(header: &mut [u8], name: &str) {
    header[0..100].fill(0);
    header[345..500].fill(0);
    let bytes = name.as_bytes();
    if bytes.len() <= 100 {
        header[0..bytes.len()].copy_from_slice(bytes);
        return;
    }
    let split = name
        .as_bytes()
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'/')
        .map(|(index, _)| index)
        .filter(|index| *index <= 155 && bytes.len().saturating_sub(*index + 1) <= 100)
        .next_back();
    if let Some(index) = split {
        header[345..345 + index].copy_from_slice(&bytes[..index]);
        let suffix = &bytes[index + 1..];
        header[0..suffix.len()].copy_from_slice(suffix);
    } else {
        let suffix = &bytes[bytes.len().saturating_sub(100)..];
        header[0..suffix.len()].copy_from_slice(suffix);
    }
}

