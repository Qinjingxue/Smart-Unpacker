fn repair_zip_comment_length(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd = find_eocd_record(data, true)
        .ok_or_else(|| "EOCD fixed header was not found".to_string())?;
    let cd = walk_central_directory_range(
        data,
        eocd.cd_offset as usize,
        Some(eocd.cd_offset as usize + eocd.cd_size as usize),
    );
    if !cd.valid {
        return Err("central directory range is not trusted".to_string());
    }
    let actual_comment_len = data.len().saturating_sub(eocd.offset + 22);
    if actual_comment_len > u16::MAX as usize {
        return Err("actual ZIP comment length is out of range".to_string());
    }
    let stored_comment_len = u16_le(data, eocd.offset + 20) as usize;
    if stored_comment_len == actual_comment_len {
        return Err("ZIP comment length already matches file length".to_string());
    }
    let patch = BytePatch {
        offset: (eocd.offset + 20) as u64,
        data: (actual_comment_len as u16).to_le_bytes().to_vec(),
    };
    let mut bytes = data.to_vec();
    bytes[eocd.offset + 20..eocd.offset + 22].copy_from_slice(&patch.data);
    Ok(DirectoryFieldRepair {
        bytes,
        patches: vec![patch],
        truncate_at: None,
        confidence: 0.86,
        actions: vec!["patch_zip_eocd_comment_length".to_string()],
        message: "ZIP EOCD comment length was patched by native repair".to_string(),
    })
}

fn repair_zip_cd_count(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd =
        find_eocd_record(data, false).ok_or_else(|| "trusted EOCD was not found".to_string())?;
    let cd = walk_central_directory_range(
        data,
        eocd.cd_offset as usize,
        Some(eocd.cd_offset as usize + eocd.cd_size as usize),
    );
    if !cd.valid {
        return Err("central directory range is not trusted".to_string());
    }
    if eocd.disk_entries as usize == cd.count && eocd.total_entries as usize == cd.count {
        return Err("central directory count already matches walked entries".to_string());
    }
    if cd.count > u16::MAX as usize {
        return Err("ZIP64 central directory count patch is not supported here".to_string());
    }
    let value = (cd.count as u16).to_le_bytes().to_vec();
    let patches = vec![
        BytePatch {
            offset: (eocd.offset + 8) as u64,
            data: value.clone(),
        },
        BytePatch {
            offset: (eocd.offset + 10) as u64,
            data: value,
        },
    ];
    let mut bytes = data.to_vec();
    for patch in &patches {
        let offset = patch.offset as usize;
        bytes[offset..offset + patch.data.len()].copy_from_slice(&patch.data);
    }
    Ok(DirectoryFieldRepair {
        bytes,
        patches,
        truncate_at: None,
        confidence: 0.88,
        actions: vec!["patch_zip_eocd_entry_counts".to_string()],
        message: "ZIP EOCD central directory counts were patched by native repair".to_string(),
    })
}

fn repair_zip_cd_offset(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd = find_eocd_record(data, true)
        .ok_or_else(|| "EOCD or central directory is missing".to_string())?;
    let cd = find_valid_central_directory(data)
        .ok_or_else(|| "EOCD or central directory is missing".to_string())?;
    if eocd.cd_offset as usize == cd.offset
        && eocd.cd_size as usize == cd.end - cd.offset
        && eocd.total_entries as usize == cd.count
    {
        return Err(
            "central directory offset already matches parsed central directory".to_string(),
        );
    }
    if cd.count > u16::MAX as usize
        || cd.end - cd.offset > u32::MAX as usize
        || cd.offset > u32::MAX as usize
    {
        return Err("ZIP64 central directory rewrite is not supported here".to_string());
    }
    let mut tail = Vec::new();
    tail.extend_from_slice(EOCD_SIG);
    tail.extend_from_slice(&0u16.to_le_bytes());
    tail.extend_from_slice(&0u16.to_le_bytes());
    tail.extend_from_slice(&(cd.count as u16).to_le_bytes());
    tail.extend_from_slice(&(cd.count as u16).to_le_bytes());
    tail.extend_from_slice(&((cd.end - cd.offset) as u32).to_le_bytes());
    tail.extend_from_slice(&(cd.offset as u32).to_le_bytes());
    let comment_len = eocd.end.saturating_sub(eocd.offset + 22);
    tail.extend_from_slice(&(comment_len as u16).to_le_bytes());
    if comment_len > 0 && eocd.offset + 22 + comment_len <= data.len() {
        tail.extend_from_slice(&data[eocd.offset + 22..eocd.offset + 22 + comment_len]);
    }
    let mut bytes = data[..cd.end].to_vec();
    bytes.extend_from_slice(&tail);
    Ok(DirectoryFieldRepair {
        bytes,
        patches: vec![BytePatch {
            offset: cd.end as u64,
            data: tail,
        }],
        truncate_at: Some(cd.end as u64),
        confidence: 0.9,
        actions: vec![
            "scan_central_directory".to_string(),
            "rewrite_eocd_cd_offset_size_count".to_string(),
        ],
        message: "ZIP EOCD central directory offset/size/count were rewritten by native repair"
            .to_string(),
    })
}

fn repair_zip_trailing_junk(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd = find_eocd_record(data, true).ok_or_else(|| "EOCD was not found".to_string())?;
    if eocd.end == data.len() {
        return Err("no trailing bytes after EOCD".to_string());
    }
    Ok(DirectoryFieldRepair {
        bytes: data[..eocd.end].to_vec(),
        patches: Vec::new(),
        truncate_at: Some(eocd.end as u64),
        confidence: 0.88,
        actions: vec!["trim_after_eocd".to_string()],
        message: "ZIP trailing junk was trimmed by native repair".to_string(),
    })
}

fn repair_zip_eocd(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    if let Some(eocd) = find_eocd_record(data, true) {
        let cd = walk_central_directory_range(
            data,
            eocd.cd_offset as usize,
            Some(eocd.cd_offset as usize + eocd.cd_size as usize),
        );
        if cd.valid && eocd.end < data.len() {
            return Ok(DirectoryFieldRepair {
                bytes: data[..eocd.end].to_vec(),
                patches: Vec::new(),
                truncate_at: Some(eocd.end as u64),
                confidence: 0.9,
                actions: vec!["trim_after_eocd".to_string()],
                message: "ZIP EOCD boundary was repaired by native trim".to_string(),
            });
        }
    }
    let cd = find_valid_central_directory(data)
        .ok_or_else(|| "no valid central directory was found for EOCD rebuild".to_string())?;
    let tail = eocd_tail_for_cd(data, &cd, None)?;
    let mut bytes = data[..cd.end].to_vec();
    bytes.extend_from_slice(&tail);
    Ok(DirectoryFieldRepair {
        bytes,
        patches: vec![BytePatch {
            offset: cd.end as u64,
            data: tail,
        }],
        truncate_at: Some(cd.end as u64),
        confidence: 0.94,
        actions: vec![
            "scan_central_directory".to_string(),
            "rebuild_eocd".to_string(),
        ],
        message: "ZIP EOCD was rebuilt by native repair".to_string(),
    })
}

fn repair_zip_local_header_fields(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd =
        find_eocd_record(data, false).ok_or_else(|| "trusted EOCD was not found".to_string())?;
    let entries = parse_central_directory_entries(
        data,
        eocd.cd_offset as usize,
        eocd.cd_offset as usize + eocd.cd_size as usize,
    );
    if entries.is_empty() {
        return Err("no central directory entries were parseable".to_string());
    }
    let mut bytes = data.to_vec();
    let mut patches = Vec::new();
    for entry in entries {
        if entry.local_header_offset == 0xFFFF_FFFF {
            continue;
        }
        let Some(mut local) = parse_local_header(&bytes, entry.local_header_offset as usize) else {
            continue;
        };
        if local.name_len != entry.name_len {
            let local_name_start = local.offset + LOCAL_HEADER_LEN;
            let local_entry_name =
                bytes.get(local_name_start..local_name_start + entry.name_len as usize);
            if local_entry_name == Some(entry.name.as_slice()) {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 26,
                    &(entry.name_len).to_le_bytes(),
                );
                if let Some(updated) =
                    parse_local_header(&bytes, entry.local_header_offset as usize)
                {
                    local = updated;
                }
            }
        }
        if local.extra_len != entry.extra_len {
            let expected_start = local.offset + LOCAL_HEADER_LEN + entry.name_len as usize;
            let expected = bytes.get(expected_start..expected_start + entry.extra_len as usize);
            if expected == Some(entry.extra.as_slice()) {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 28,
                    &(entry.extra_len).to_le_bytes(),
                );
                if let Some(updated) =
                    parse_local_header(&bytes, entry.local_header_offset as usize)
                {
                    local = updated;
                }
            }
        }
        if local.flags != entry.flags {
            add_zip_patch(
                &mut bytes,
                &mut patches,
                local.offset + 6,
                &entry.flags.to_le_bytes(),
            );
        }
        if local.method != entry.method {
            add_zip_patch(
                &mut bytes,
                &mut patches,
                local.offset + 8,
                &entry.method.to_le_bytes(),
            );
        }
        if entry.flags & 0x08 == 0 {
            if local.crc32 != entry.crc32 {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 14,
                    &entry.crc32.to_le_bytes(),
                );
            }
            if entry.compressed_size != 0xFFFF_FFFF
                && local.compressed_size != entry.compressed_size
            {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 18,
                    &entry.compressed_size.to_le_bytes(),
                );
            }
            if entry.uncompressed_size != 0xFFFF_FFFF
                && local.uncompressed_size != entry.uncompressed_size
            {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 22,
                    &entry.uncompressed_size.to_le_bytes(),
                );
            }
        }
    }
    if patches.is_empty() {
        return Err("no ZIP local header field mismatch was safely repairable".to_string());
    }
    Ok(DirectoryFieldRepair {
        bytes,
        patches,
        truncate_at: None,
        confidence: 0.9,
        actions: vec!["reconcile_zip_local_header_fields_with_central_directory".to_string()],
        message: "ZIP local header fields were reconciled by native repair".to_string(),
    })
}

fn repair_zip_extra_field_length(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd =
        find_eocd_record(data, true).ok_or_else(|| "trusted EOCD was not found".to_string())?;
    let cd_offset = eocd.cd_offset as usize;
    let cd_end = cd_offset.saturating_add(eocd.cd_size as usize).min(data.len());
    let mut entries = parse_central_directory_entries(data, cd_offset, cd_end);
    let tolerant_entries = parse_tolerant_central_directory_entries(data, cd_offset, cd_end);
    for entry in tolerant_entries {
        if !entries.iter().any(|existing| existing.offset == entry.offset) {
            entries.push(entry);
        }
    }
    entries.sort_by_key(|entry| entry.offset);
    if entries.is_empty() {
        return Err("no central directory entries were parseable for extra field length repair".to_string());
    }

    let mut bytes = data.to_vec();
    let mut patches = Vec::new();
    let central_entries = entries;
    for (index, entry) in central_entries.iter().enumerate() {
        let Some(local) = find_local_for_central_offset_only(data, &entry)
            .or_else(|| find_local_for_central(data, &entry))
        else {
            continue;
        };
        if let Some(target_extra_len) = infer_central_extra_length_from_next_header(data, entry, cd_end) {
            if entry.extra_len != target_extra_len {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    entry.offset + 30,
                    &target_extra_len.to_le_bytes(),
                );
            }
        }
        if let Some(target_extra_len) = infer_local_extra_length_from_layout(
            &local,
            entry,
            central_entries.get(index + 1),
            cd_offset,
        ) {
            if local.extra_len != target_extra_len {
                add_zip_patch(
                    &mut bytes,
                    &mut patches,
                    local.offset + 28,
                    &target_extra_len.to_le_bytes(),
                );
            }
        }
    }
    if patches.is_empty() {
        return Err("no ZIP extra field length mismatch was safely repairable".to_string());
    }
    Ok(DirectoryFieldRepair {
        bytes,
        patches,
        truncate_at: None,
        confidence: 0.91,
        actions: vec!["reconcile_zip_extra_field_lengths".to_string()],
        message: "ZIP extra field length fields were reconciled by native repair".to_string(),
    })
}

fn infer_central_extra_length_from_next_header(
    data: &[u8],
    entry: &CentralEntry,
    cd_end: usize,
) -> Option<u16> {
    let name_start = entry.offset.checked_add(46)?;
    let extra_start = name_start.checked_add(entry.name_len as usize)?;
    let comment_len = find_next_central_offset(data, entry.offset, cd_end)?
        .checked_sub(extra_start)?
        .checked_sub(u16_le(data, entry.offset + 32) as usize)?;
    if comment_len > u16::MAX as usize {
        return None;
    }
    let target = comment_len as u16;
    if target == entry.extra_len {
        None
    } else {
        Some(target)
    }
}

fn find_next_central_offset(data: &[u8], current_offset: usize, cd_end: usize) -> Option<usize> {
    let start = current_offset.checked_add(46)?;
    if start >= cd_end.min(data.len()) {
        return Some(cd_end.min(data.len()));
    }
    memmem::find(&data[start..cd_end.min(data.len())], CD_SIG).map(|delta| start + delta).or(Some(cd_end.min(data.len())))
}

fn infer_local_extra_length_from_layout(
    local: &LocalHeader,
    entry: &CentralEntry,
    next_entry: Option<&CentralEntry>,
    cd_offset: usize,
) -> Option<u16> {
    if entry.compressed_size == 0xFFFF_FFFF || entry.flags & 0x08 != 0 {
        return None;
    }
    let next_offset = next_entry
        .map(|item| item.local_header_offset as usize)
        .filter(|offset| *offset > local.offset)
        .unwrap_or(cd_offset);
    let fixed = local
        .offset
        .checked_add(LOCAL_HEADER_LEN)?
        .checked_add(local.name_len as usize)?
        .checked_add(entry.compressed_size as usize)?;
    let target = next_offset.checked_sub(fixed)?;
    if target > u16::MAX as usize {
        return None;
    }
    let target = target as u16;
    if target == local.extra_len {
        None
    } else {
        Some(target)
    }
}

fn repair_zip_data_descriptor_flags(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let cd = find_valid_central_directory(data)
        .ok_or_else(|| "central directory was not parseable".to_string())?;
    let entries = parse_central_directory_entries(data, cd.offset, cd.end);
    if entries.is_empty() {
        return Err("no central directory entries were parseable".to_string());
    }
    let mut bytes = data.to_vec();
    let mut patches = Vec::new();
    for entry in entries {
        let Some(local) = find_local_for_central_offset_only(data, &entry) else {
            continue;
        };
        let local_bit = local.flags & 0x08;
        let central_bit = entry.flags & 0x08;
        if local_bit == central_bit {
            continue;
        }
        let data_start = local
            .offset
            .checked_add(LOCAL_HEADER_LEN)
            .and_then(|value| value.checked_add(local.name_len as usize))
            .and_then(|value| value.checked_add(local.extra_len as usize));
        let Some(data_start) = data_start else {
            continue;
        };
        let Some(payload_end) = data_start.checked_add(entry.compressed_size as usize) else {
            continue;
        };
        let descriptor_present = descriptor_at(
            data,
            payload_end,
            entry.crc32,
            entry.compressed_size as u64,
            entry.uncompressed_size as u64,
        );
        let bit = if descriptor_present { 0x08 } else { 0x00 };
        let local_target = (local.flags & !0x08) | bit;
        let central_target = (entry.flags & !0x08) | bit;
        if local_target != local.flags {
            add_zip_patch(
                &mut bytes,
                &mut patches,
                local.offset + 6,
                &local_target.to_le_bytes(),
            );
        }
        if central_target != entry.flags {
            let Some(central_offset) = find_central_entry_offset(data, cd.offset, cd.end, &entry) else {
                continue;
            };
            add_zip_patch(
                &mut bytes,
                &mut patches,
                central_offset + 8,
                &central_target.to_le_bytes(),
            );
        }
    }
    if patches.is_empty() {
        return Err("ZIP data descriptor bit flags already match or are not safely repairable".to_string());
    }
    Ok(DirectoryFieldRepair {
        bytes,
        patches,
        truncate_at: None,
        confidence: 0.93,
        actions: vec!["normalize_zip_data_descriptor_bit_flags".to_string()],
        message: "ZIP data descriptor bit flags were normalized by native repair".to_string(),
    })
}

fn repair_zip_cd_entry_names_from_local_headers(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let cd = find_valid_central_directory(data)
        .ok_or_else(|| "central directory was not parseable".to_string())?;
    let entries = parse_central_directory_entries(data, cd.offset, cd.end);
    if entries.is_empty() {
        return Err("no central directory entries were parseable".to_string());
    }
    let mut bytes = data.to_vec();
    let mut patches = Vec::new();
    for entry in entries {
        let Some(local) = find_local_for_central_offset_only(data, &entry) else {
            continue;
        };
        if local.name == entry.name {
            continue;
        }
        if local.name_len != entry.name_len {
            continue;
        }
        if local.name.iter().any(|byte| *byte == 0) {
            continue;
        }
        let Some(central_offset) = find_central_entry_offset(data, cd.offset, cd.end, &entry) else {
            continue;
        };
        let name_offset = central_offset + 46;
        if name_offset + local.name.len() > data.len() {
            continue;
        }
        add_zip_patch(
            &mut bytes,
            &mut patches,
            name_offset,
            &local.name,
        );
    }
    if patches.is_empty() {
        return Err("no central directory entry name mismatch was safely repairable".to_string());
    }
    Ok(DirectoryFieldRepair {
        bytes,
        patches,
        truncate_at: None,
        confidence: 0.94,
        actions: vec!["reconcile_central_directory_names_from_local_headers".to_string()],
        message: "ZIP central directory entry names were reconciled from local headers".to_string(),
    })
}

fn find_central_entry_offset(
    data: &[u8],
    cd_offset: usize,
    cd_end: usize,
    target: &CentralEntry,
) -> Option<usize> {
    let mut pos = cd_offset;
    while pos + 46 <= data.len() && pos < cd_end && &data[pos..pos + 4] == CD_SIG {
        let name_len = u16_le(data, pos + 28);
        let extra_len = u16_le(data, pos + 30);
        let comment_len = u16_le(data, pos + 32) as usize;
        let name_start = pos + 46;
        let extra_start = name_start + name_len as usize;
        let comment_start = extra_start + extra_len as usize;
        let record_end = comment_start + comment_len;
        if record_end > data.len() || record_end > cd_end {
            return None;
        }
        if u32_le(data, pos + 42) == target.local_header_offset
            && data[name_start..extra_start] == target.name
        {
            return Some(pos);
        }
        pos = record_end;
    }
    None
}

#[derive(Clone, Copy)]
enum Zip64TailTarget {
    Locator,
    Eocd,
}

fn repair_zip64_tail_target(
    data: &[u8],
    target: Zip64TailTarget,
) -> Result<DirectoryFieldRepair, String> {
    let Some(repair) = repair_zip64_tail(data)? else {
        return Err("no ZIP64 tail mismatch was safely repairable".to_string());
    };
    let allowed = match target {
        Zip64TailTarget::Locator => ["normalize_zip64_eocd_locator", "rewrite_zip64_eocd_locator"],
        Zip64TailTarget::Eocd => ["rewrite_zip64_eocd_fields", ""],
    };
    let matched = repair.actions.iter().any(|action| allowed.contains(&action.as_str()));
    let only_allowed = repair
        .actions
        .iter()
        .all(|action| allowed.contains(&action.as_str()));
    if !matched || !only_allowed {
        return Err("ZIP64 native target did not match requested atomic repair".to_string());
    }
    Ok(repair)
}

fn repair_zip64_tail(data: &[u8]) -> Result<Option<DirectoryFieldRepair>, String> {
    let Some(eocd) = find_eocd_record(data, true) else {
        return Ok(None);
    };
    let Some(zip64) = find_zip64_eocd(data, eocd.offset) else {
        return Ok(None);
    };
    let mut cd = walk_central_directory_range(
        data,
        zip64.cd_offset as usize,
        Some(zip64.cd_offset as usize + zip64.cd_size as usize),
    );
    if !cd.valid {
        cd = match find_valid_central_directory(data) {
            Some(value) => value,
            None => return Ok(None),
        };
    }
    if !cd.valid {
        return Ok(None);
    }
    let mut record = data[zip64.offset..zip64.end].to_vec();
    let expected_record_size = (zip64.end - zip64.offset - 12) as u64;
    let mut actions = Vec::new();
    for (offset, value) in [
        (4usize, expected_record_size),
        (24, cd.count as u64),
        (32, cd.count as u64),
        (40, (cd.end - cd.offset) as u64),
        (48, cd.offset as u64),
    ] {
        let encoded = value.to_le_bytes();
        if record.get(offset..offset + 8) != Some(encoded.as_slice()) {
            record[offset..offset + 8].copy_from_slice(&encoded);
            actions.push("rewrite_zip64_eocd_fields".to_string());
        }
    }
    let expected_locator = zip64_locator_bytes(zip64.offset as u64);
    let locator = find_zip64_locator(data, eocd.offset);
    let locator_bytes = if locator
        .is_some_and(|item| item.zip64_eocd_offset == zip64.offset as u64 && item.total_disks >= 1)
    {
        if data[locator.unwrap().offset..locator.unwrap().end] != expected_locator {
            actions.push("normalize_zip64_eocd_locator".to_string());
            expected_locator
        } else {
            data[locator.unwrap().offset..locator.unwrap().end].to_vec()
        }
    } else {
        actions.push("rewrite_zip64_eocd_locator".to_string());
        expected_locator
    };
    dedupe(&mut actions);
    if actions.is_empty() {
        return Ok(None);
    }
    let tail_start = zip64.offset;
    let mut tail = record;
    tail.extend_from_slice(&locator_bytes);
    tail.extend_from_slice(&data[eocd.offset..eocd.end]);
    let mut bytes = data[..tail_start].to_vec();
    bytes.extend_from_slice(&tail);
    Ok(Some(DirectoryFieldRepair {
        bytes,
        patches: vec![BytePatch {
            offset: tail_start as u64,
            data: tail,
        }],
        truncate_at: Some(tail_start as u64),
        confidence: 0.98,
        actions,
        message: "ZIP64 tail fields were rewritten by native repair".to_string(),
    }))
}

fn repair_zip64_central_extra(data: &[u8]) -> Result<DirectoryFieldRepair, String> {
    let eocd =
        find_eocd_record(data, true).ok_or_else(|| "trusted EOCD was not found".to_string())?;
    let (cd_offset, cd_end) = if let Some(zip64) = find_zip64_eocd(data, eocd.offset) {
        (
            zip64.cd_offset as usize,
            (zip64.cd_offset + zip64.cd_size) as usize,
        )
    } else {
        (
            eocd.cd_offset as usize,
            eocd.cd_offset as usize + eocd.cd_size as usize,
        )
    };
    let entries = parse_central_directory_entries(data, cd_offset, cd_end);
    if entries.is_empty() {
        return Err("no ZIP64 central directory entries were parseable".to_string());
    }
    let mut bytes = data.to_vec();
    let mut patches = Vec::new();
    for entry in entries {
        let Some(local) = find_local_for_central(data, &entry) else {
            continue;
        };
        let Some(central_zip64) = parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset) else {
            continue;
        };
        let expected = if let Some(local_zip64) = parse_zip64_extra_tolerant(&local.extra, local.extra_offset) {
            expected_zip64_values(&entry, &local, &local_zip64)
        } else if !central_zip64.values.is_empty() {
            Some(central_zip64.values.clone())
        } else {
            None
        };
        let Some(expected) = expected else {
            continue;
        };
        let expected_size = expected.len() * 8;
        if central_zip64.stored_size != expected_size {
            add_zip_patch(
                &mut bytes,
                &mut patches,
                central_zip64.size_offset,
                &(expected_size as u16).to_le_bytes(),
            );
        }
        if central_zip64.values.len() < expected.len() {
            continue;
        }
        for (index, value) in expected.into_iter().enumerate() {
            if central_zip64.values[index] == value {
                continue;
            }
            let offset = central_zip64.values_offset + index * 8;
            add_zip_patch(&mut bytes, &mut patches, offset, &value.to_le_bytes());
        }
    }
    if patches.is_empty() {
        return Err("no ZIP64 tail or extra field mismatch was safely repairable".to_string());
    }
    Ok(DirectoryFieldRepair {
        bytes,
        patches,
        truncate_at: None,
        confidence: 0.96,
        actions: vec!["reconcile_zip64_central_extra_fields".to_string()],
        message: "ZIP64 central extra fields were reconciled by native repair".to_string(),
    })
}

