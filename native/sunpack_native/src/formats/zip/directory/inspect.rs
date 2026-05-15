pub(crate) fn inspect_zip_directory_consistency(
    py: Python<'_>,
    path: &str,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let result = zip_directory_consistency_empty(py)?;
    let Ok(data) = fs::read(path) else {
        result.set_item("error", "os_error")?;
        return Ok(result.unbind());
    };
    result.set_item("file_size", data.len())?;
    let Some(eocd) = find_eocd_record(&data, true) else {
        result.set_item("error", "eocd_not_found")?;
        return Ok(result.unbind());
    };
    let physical_cd_offset = eocd.offset.saturating_sub(eocd.cd_size as usize);
    let archive_offset = physical_cd_offset.saturating_sub(eocd.cd_offset as usize);
    let cd_end = physical_cd_offset
        .saturating_add(eocd.cd_size as usize)
        .min(data.len());
    result.set_item("eocd_offset", eocd.offset)?;
    result.set_item("declared_central_directory_offset", eocd.cd_offset as usize)?;
    result.set_item("declared_central_directory_size", eocd.cd_size as usize)?;
    result.set_item("declared_total_entries", eocd.total_entries as usize)?;
    result.set_item("physical_central_directory_offset", physical_cd_offset)?;
    result.set_item("archive_offset", archive_offset)?;
    result.set_item(
        "central_directory_offset_delta",
        physical_cd_offset as i64 - eocd.cd_offset as i64,
    )?;
    result.set_item(
        "central_directory_size_delta",
        cd_end.saturating_sub(physical_cd_offset) as i64 - eocd.cd_size as i64,
    )?;
    if physical_cd_offset + 4 > data.len() || data.get(physical_cd_offset..physical_cd_offset + 4) != Some(CD_SIG) {
        result.set_item("error", "bad_central_directory_signature")?;
        result.set_item("bad_central_directory_signature_offset", physical_cd_offset)?;
        return Ok(result.unbind());
    }

    let all_entries = parse_central_directory_entries(&data, physical_cd_offset, cd_end);
    let checked_entries = all_entries.iter().take(max_entries).collect::<Vec<_>>();
    result.set_item("cd_parseable", !all_entries.is_empty())?;
    result.set_item("cd_entries_checked", checked_entries.len())?;
    result.set_item("cd_entries_parseable", all_entries.len())?;
    result.set_item("cd_entries_truncated_by_limit", all_entries.len() > checked_entries.len())?;
    result.set_item("entry_count_delta", all_entries.len() as i64 - eocd.total_entries as i64)?;
    if all_entries.is_empty() {
        result.set_item("error", "no_central_directory_entries_parseable")?;
        return Ok(result.unbind());
    }

    let mut local_missing = 0usize;
    let mut local_bad_sig = 0usize;
    let mut name_mismatch = 0usize;
    let mut flags_mismatch = 0usize;
    let mut method_mismatch = 0usize;
    let mut crc_mismatch = 0usize;
    let mut compressed_mismatch = 0usize;
    let mut uncompressed_mismatch = 0usize;
    let mut local_extra_len_mismatch = 0usize;
    let mut offset_suspicious = 0usize;
    let mut descriptor_checked = 0usize;
    let mut descriptor_present = 0usize;
    let mut descriptor_missing = 0usize;
    let mut descriptor_flag_mismatch = 0usize;
    let mut spurious_descriptor_candidates = 0usize;
    let mut zip64_extra_present = 0usize;
    let mut zip64_extra_size_mismatch = 0usize;
    let mut zip64_extra_value_mismatch = 0usize;

    for (index, entry) in checked_entries.iter().enumerate() {
        let Some(local_offset) = archive_offset.checked_add(entry.local_header_offset as usize) else {
            local_missing += 1;
            offset_suspicious += 1;
            continue;
        };
        if local_offset + 4 > data.len() {
            local_missing += 1;
            offset_suspicious += 1;
            continue;
        }
        if data.get(local_offset..local_offset + 4) != Some(LFH_SIG) {
            local_bad_sig += 1;
            offset_suspicious += 1;
            continue;
        }
        let Some(local) = parse_local_header(&data, local_offset) else {
            local_missing += 1;
            continue;
        };
        if local.name != entry.name {
            name_mismatch += 1;
        }
        if local.flags != entry.flags {
            flags_mismatch += 1;
        }
        if local.method != entry.method {
            method_mismatch += 1;
        }
        if local.extra_len != entry.extra_len {
            local_extra_len_mismatch += 1;
        }
        if entry.flags & 0x08 == 0 {
            if local.crc32 != entry.crc32 {
                crc_mismatch += 1;
            }
            if entry.compressed_size != u32::MAX && local.compressed_size != entry.compressed_size {
                compressed_mismatch += 1;
            }
            if entry.uncompressed_size != u32::MAX && local.uncompressed_size != entry.uncompressed_size {
                uncompressed_mismatch += 1;
            }
        }

        let local_zip64 = parse_zip64_extra_tolerant(&local.extra, local.extra_offset);
        let central_zip64 = parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset);
        if central_zip64.is_some() || local_zip64.is_some() {
            zip64_extra_present += 1;
        }
        if let Some(central) = central_zip64.as_ref() {
            if central.stored_size != central.values.len() * 8 {
                zip64_extra_size_mismatch += 1;
            }
            if let Some(local_zip64) = local_zip64.as_ref() {
                let expected = expected_zip64_values(entry, &local, local_zip64)
                    .unwrap_or_else(|| local_zip64.values.clone());
                if central.values != expected {
                    zip64_extra_value_mismatch += 1;
                }
            }
        }

        let Some(payload_end) = local
            .offset
            .checked_add(LOCAL_HEADER_LEN)
            .and_then(|value| value.checked_add(local.name_len as usize))
            .and_then(|value| value.checked_add(local.extra_len as usize))
            .and_then(|value| value.checked_add(entry.compressed_size as usize))
        else {
            continue;
        };
        if entry.compressed_size != u32::MAX && payload_end <= data.len() {
            descriptor_checked += 1;
            let has_descriptor = descriptor_at(
                &data,
                payload_end,
                entry.crc32,
                entry.compressed_size as u64,
                entry.uncompressed_size as u64,
            );
            if has_descriptor {
                descriptor_present += 1;
            } else if (entry.flags | local.flags) & 0x08 != 0 {
                descriptor_missing += 1;
            }
            if (entry.flags & 0x08) != (local.flags & 0x08) {
                descriptor_flag_mismatch += 1;
            }
            if zip_inspect_spurious_descriptor_candidate(&data, &all_entries, index, entry, &local, physical_cd_offset) {
                spurious_descriptor_candidates += 1;
            }
        }
    }

    result.set_item("local_header_missing_count", local_missing)?;
    result.set_item("local_header_bad_signature_count", local_bad_sig)?;
    result.set_item("central_local_name_mismatch_count", name_mismatch)?;
    result.set_item("central_local_flags_mismatch_count", flags_mismatch)?;
    result.set_item("central_local_method_mismatch_count", method_mismatch)?;
    result.set_item("central_local_crc_mismatch_count", crc_mismatch)?;
    result.set_item("central_local_compressed_size_mismatch_count", compressed_mismatch)?;
    result.set_item("central_local_uncompressed_size_mismatch_count", uncompressed_mismatch)?;
    result.set_item("local_extra_len_mismatch_count", local_extra_len_mismatch)?;
    result.set_item("central_local_offset_suspicious_count", offset_suspicious)?;

    let descriptor = PyDict::new(py);
    descriptor.set_item("descriptor_checked_count", descriptor_checked)?;
    descriptor.set_item("descriptor_present_count", descriptor_present)?;
    descriptor.set_item("descriptor_missing_count", descriptor_missing)?;
    descriptor.set_item("descriptor_flag_mismatch_count", descriptor_flag_mismatch)?;
    descriptor.set_item("spurious_descriptor_candidate_count", spurious_descriptor_candidates)?;
    result.set_item("descriptor", descriptor)?;

    let zip64 = PyDict::new(py);
    let zip64_eocd = find_zip64_eocd(&data, eocd.offset);
    let zip64_locator = find_zip64_locator(&data, eocd.offset);
    zip64.set_item("zip64_eocd_present", zip64_eocd.is_some())?;
    zip64.set_item("zip64_locator_present", zip64_locator.is_some())?;
    zip64.set_item(
        "zip64_locator_target_valid",
        zip64_locator.is_some_and(|locator| {
            zip64_eocd.is_some_and(|tail| locator.zip64_eocd_offset == tail.offset as u64 && locator.total_disks >= 1)
        }),
    )?;
    zip64.set_item(
        "zip64_eocd_field_mismatch_count",
        zip_inspect_zip64_eocd_mismatch_count(zip64_eocd, physical_cd_offset, cd_end, all_entries.len()),
    )?;
    zip64.set_item("zip64_extra_present_count", zip64_extra_present)?;
    zip64.set_item("zip64_extra_size_mismatch_count", zip64_extra_size_mismatch)?;
    zip64.set_item("zip64_extra_value_mismatch_count", zip64_extra_value_mismatch)?;
    result.set_item("zip64_consistency", zip64)?;
    Ok(result.unbind())
}

fn zip_directory_consistency_empty<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
    let result = PyDict::new(py);
    result.set_item("schema_version", 1)?;
    result.set_item("error", "")?;
    result.set_item("cd_parseable", false)?;
    result.set_item("cd_entries_checked", 0)?;
    result.set_item("cd_entries_parseable", 0)?;
    result.set_item("cd_entries_truncated_by_limit", false)?;
    result.set_item("local_header_missing_count", 0)?;
    result.set_item("local_header_bad_signature_count", 0)?;
    result.set_item("central_local_name_mismatch_count", 0)?;
    result.set_item("central_local_flags_mismatch_count", 0)?;
    result.set_item("central_local_method_mismatch_count", 0)?;
    result.set_item("central_local_crc_mismatch_count", 0)?;
    result.set_item("central_local_compressed_size_mismatch_count", 0)?;
    result.set_item("central_local_uncompressed_size_mismatch_count", 0)?;
    result.set_item("local_extra_len_mismatch_count", 0)?;
    result.set_item("central_local_offset_suspicious_count", 0)?;
    Ok(result)
}

fn zip_inspect_spurious_descriptor_candidate(
    data: &[u8],
    entries: &[CentralEntry],
    index: usize,
    entry: &CentralEntry,
    local: &LocalHeader,
    cd_offset: usize,
) -> bool {
    spurious_descriptor_delete_for_entry(data, entries, index, entry, local, cd_offset).is_some()
}

fn zip_inspect_zip64_eocd_mismatch_count(
    zip64: Option<Zip64Eocd>,
    cd_offset: usize,
    cd_end: usize,
    entry_count: usize,
) -> usize {
    let Some(zip64) = zip64 else {
        return 0;
    };
    let expected_record_size = (zip64.end - zip64.offset - 12) as u64;
    let mut mismatches = 0usize;
    if expected_record_size != 44 {
        mismatches += 1;
    }
    if zip64.cd_size != cd_end.saturating_sub(cd_offset) as u64 {
        mismatches += 1;
    }
    if zip64.cd_offset != cd_offset as u64 {
        mismatches += 1;
    }
    if entry_count == 0 {
        mismatches += 1;
    }
    mismatches
}
