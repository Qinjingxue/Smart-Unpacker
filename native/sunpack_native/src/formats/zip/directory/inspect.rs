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
    let local_candidates = scan_zip_local_headers(&data, physical_cd_offset, max_entries.saturating_mul(4).max(32));
    let local_spans = local_record_spans(&local_candidates, physical_cd_offset);
    let (known_payload_spans, known_descriptor_spans) =
        local_payload_descriptor_spans(&data, &local_candidates, physical_cd_offset);
    let first_local_offset = local_candidates.first().map(|local| local.offset).unwrap_or(0);
    let prefix_len = first_local_offset;

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
    let mut descriptor_candidate_span_overlap = 0usize;
    let mut descriptor_payload_end_to_next_local_delta_min: Option<usize> = None;
    let mut cd_compressed_size_points_into_descriptor = 0usize;
    let mut compressed_size_ends_before_descriptor = 0usize;
    let mut compressed_size_ends_inside_descriptor = 0usize;
    let mut compressed_size_ends_after_descriptor = 0usize;
    let mut compressed_size_ends_after_next_local = 0usize;
    let mut compressed_size_ends_before_next_local_gap = 0usize;
    let mut descriptor_span_between_payload_and_next_local = 0usize;
    let mut cd_entry_span_conflict = 0usize;
    let mut wrong_local_header_target = 0usize;
    let mut local_header_offset_points_to_other_entry = 0usize;
    let mut local_header_offset_points_to_descriptor_or_payload = 0usize;
    let mut local_header_offset_points_inside_payload = 0usize;
    let mut local_header_offset_points_inside_descriptor = 0usize;
    let mut local_header_offset_points_outside_archive = 0usize;
    let mut local_header_offset_bad_signature = 0usize;
    let mut descriptor_span_present = 0usize;
    let mut descriptor_span_missing = 0usize;
    let mut descriptor_between_payload_and_next_local = 0usize;
    let mut descriptor_flag_set_but_span_missing = 0usize;
    let mut descriptor_span_present_without_flag = 0usize;
    let mut descriptor_span_conflicts_with_cd_size = 0usize;
    let mut cd_size_points_to_descriptor_start = 0usize;
    let mut cd_size_points_inside_descriptor = 0usize;
    let mut cd_offset_size_joint_conflict = 0usize;
    let mut cd_offset_valid_but_size_conflict = 0usize;
    let mut cd_size_valid_but_offset_conflict = 0usize;
    let mut local_offset_valid_without_prefix = 0usize;
    let mut local_offset_valid_with_prefix = 0usize;
    let mut local_offset_only_valid_with_prefix = 0usize;
    let mut local_offset_invalid_after_prefix_adjustment = 0usize;
    let mut zip64_extra_present = 0usize;
    let mut zip64_extra_size_mismatch = 0usize;
    let mut zip64_extra_value_mismatch = 0usize;
    let mut parsed_payload_spans: Vec<(usize, usize)> = Vec::new();

    for (index, entry) in checked_entries.iter().enumerate() {
        let raw_local_offset = entry.local_header_offset as usize;
        let Some(archive_adjusted_offset) = archive_offset.checked_add(entry.local_header_offset as usize) else {
            local_missing += 1;
            offset_suspicious += 1;
            continue;
        };
        let prefix_adjusted_offset = raw_local_offset.saturating_add(prefix_len);
        let local_offset = if prefix_len > 0 {
            prefix_adjusted_offset
        } else {
            archive_adjusted_offset
        };
        let local_offset_outside_archive = local_offset + 4 > data.len();
        let local_offset_has_signature =
            !local_offset_outside_archive && data.get(local_offset..local_offset + 4) == Some(LFH_SIG);
        if local_offset_outside_archive {
            local_header_offset_points_outside_archive += 1;
        } else if !local_offset_has_signature {
            local_header_offset_bad_signature += 1;
            if offset_inside_local_or_data_span(local_offset, &known_descriptor_spans) {
                local_header_offset_points_inside_descriptor += 1;
            } else if offset_inside_local_or_data_span(local_offset, &known_payload_spans) {
                local_header_offset_points_inside_payload += 1;
            }
        }
        let raw_local = parse_local_header(&data, raw_local_offset);
        let archive_adjusted_local = parse_local_header(&data, archive_adjusted_offset);
        let prefix_adjusted_local = if prefix_len > 0 {
            parse_local_header(&data, prefix_adjusted_offset)
        } else {
            None
        };
        if raw_local.is_some() {
            local_offset_valid_without_prefix += 1;
        }
        if prefix_len > 0 {
            if prefix_adjusted_local.is_some() {
                local_offset_valid_with_prefix += 1;
                if raw_local.is_none() {
                    local_offset_only_valid_with_prefix += 1;
                }
            } else {
                local_offset_invalid_after_prefix_adjustment += 1;
            }
        }
        let matched_local = prefix_adjusted_local
            .clone()
            .or_else(|| archive_adjusted_local.clone())
            .or_else(|| raw_local.clone())
            .or_else(|| local_candidates.iter().find(|candidate| candidate.name == entry.name).cloned());
        if raw_local_offset != archive_adjusted_offset
            && archive_adjusted_local.is_none()
            && raw_local.is_some()
        {
            offset_suspicious += 1;
        }
        for candidate_offset in [raw_local_offset, archive_adjusted_offset, prefix_adjusted_offset] {
            if candidate_offset < data.len()
                && data.get(candidate_offset..candidate_offset.saturating_add(4)) != Some(LFH_SIG)
                && offset_inside_local_or_data_span(candidate_offset, &local_spans)
            {
                local_header_offset_points_to_descriptor_or_payload += 1;
            }
        }
        if let Some(local) = matched_local.as_ref() {
            if local.offset != local_offset || local.name != entry.name {
                wrong_local_header_target += 1;
            }
            if local.name != entry.name {
                local_header_offset_points_to_other_entry += 1;
            }
        }
        if local_offset + 4 > data.len() {
            local_missing += 1;
            offset_suspicious += 1;
            continue;
        }
        if data.get(local_offset..local_offset + 4) != Some(LFH_SIG) {
            local_bad_sig += 1;
            offset_suspicious += 1;
            if parsed_payload_spans
                .iter()
                .any(|(start, end)| local_offset >= *start && local_offset < end.saturating_add(32))
                || offset_inside_local_or_data_span(local_offset, &local_spans)
            {
                local_header_offset_points_to_descriptor_or_payload += 1;
            }
        }
        let Some(ref local) = matched_local else {
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
        let payload_start = local
            .offset
            .checked_add(LOCAL_HEADER_LEN)
            .and_then(|value| value.checked_add(local.name_len as usize))
            .and_then(|value| value.checked_add(local.extra_len as usize))
            .unwrap_or(local.offset);
        parsed_payload_spans.push((payload_start, payload_end));
        let next_boundary = checked_entries
            .get(index + 1)
            .map(|next| next.local_header_offset as usize + prefix_len)
            .or_else(|| checked_entries.get(index + 1).map(|next| next.local_header_offset as usize))
            .unwrap_or(physical_cd_offset)
            .min(data.len());
        let mut entry_descriptor_span: Option<(usize, usize)> = None;
        let mut entry_size_conflict = false;
        if payload_end > next_boundary {
            compressed_size_ends_after_next_local += 1;
            cd_entry_span_conflict += 1;
            entry_size_conflict = true;
        }
        if payload_end < next_boundary {
            if next_boundary.saturating_sub(payload_end) > 32 {
                compressed_size_ends_before_next_local_gap += 1;
            }
            if let Some(descriptor_offset) = find_signature_between(&data, payload_end, next_boundary, DD_SIG) {
                descriptor_span_between_payload_and_next_local += 1;
                descriptor_between_payload_and_next_local += 1;
                let descriptor_end = descriptor_at_impl(
                    &data,
                    descriptor_offset,
                    entry.crc32,
                    entry.compressed_size as u64,
                    entry.uncompressed_size as u64,
                )
                .unwrap_or_else(|| descriptor_offset.saturating_add(16).min(next_boundary));
                entry_descriptor_span = Some((descriptor_offset, descriptor_end));
                if payload_end == descriptor_offset {
                    cd_size_points_to_descriptor_start += 1;
                } else if payload_end < descriptor_offset {
                    compressed_size_ends_before_descriptor += 1;
                    entry_size_conflict = true;
                    cd_entry_span_conflict += 1;
                } else if payload_end < descriptor_end {
                    compressed_size_ends_inside_descriptor += 1;
                    cd_size_points_inside_descriptor += 1;
                    entry_size_conflict = true;
                    cd_entry_span_conflict += 1;
                } else if payload_end > descriptor_end && payload_end <= next_boundary {
                    compressed_size_ends_after_descriptor += 1;
                    entry_size_conflict = true;
                    cd_entry_span_conflict += 1;
                }
                let delta = descriptor_offset.saturating_sub(payload_end);
                descriptor_payload_end_to_next_local_delta_min =
                    Some(descriptor_payload_end_to_next_local_delta_min.map_or(delta, |current| current.min(delta)));
            }
        }
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
                descriptor_span_present += 1;
                let descriptor_end = descriptor_at_impl(
                    &data,
                    payload_end,
                    entry.crc32,
                    entry.compressed_size as u64,
                    entry.uncompressed_size as u64,
                )
                .unwrap_or(payload_end);
                entry_descriptor_span = Some((payload_end, descriptor_end));
            } else if (entry.flags | local.flags) & 0x08 != 0 {
                descriptor_missing += 1;
                descriptor_span_missing += 1;
            }
            if (entry.flags & 0x08) != (local.flags & 0x08) {
                descriptor_flag_mismatch += 1;
            }
            if ((entry.flags | local.flags) & 0x08) != 0 && !has_descriptor {
                descriptor_flag_set_but_span_missing += 1;
            }
            if has_descriptor && ((entry.flags | local.flags) & 0x08) == 0 {
                descriptor_span_present_without_flag += 1;
            }
            if zip_inspect_spurious_descriptor_candidate(&data, &all_entries, index, entry, local, physical_cd_offset) {
                spurious_descriptor_candidates += 1;
            }
            if let Some(next_entry) = checked_entries.get(index + 1) {
                if let Some(next_local_offset) = (next_entry.local_header_offset as usize).checked_add(prefix_len) {
                    if next_local_offset > payload_end {
                        let delta = next_local_offset - payload_end;
                        descriptor_payload_end_to_next_local_delta_min =
                            Some(descriptor_payload_end_to_next_local_delta_min.map_or(delta, |current| current.min(delta)));
                        if delta <= 32 {
                            descriptor_candidate_span_overlap += 1;
                            if has_descriptor || delta >= 12 {
                                cd_compressed_size_points_into_descriptor += 1;
                            }
                        }
                    } else if next_local_offset > payload_start {
                        local_header_offset_points_to_descriptor_or_payload += 1;
                    }
                }
            }
        }
        let entry_offset_conflict =
            local_offset_outside_archive || !local_offset_has_signature || matched_local.as_ref().is_some_and(|candidate| {
                candidate.offset != local_offset || candidate.name != entry.name
            });
        if let Some((descriptor_start, descriptor_end)) = entry_descriptor_span {
            if payload_end != descriptor_start {
                descriptor_span_conflicts_with_cd_size += 1;
                entry_size_conflict = true;
            }
            if local_offset > descriptor_start && local_offset < descriptor_end {
                local_header_offset_points_inside_descriptor += 1;
            }
        }
        if entry_offset_conflict && entry_size_conflict {
            cd_offset_size_joint_conflict += 1;
        } else if !entry_offset_conflict && entry_size_conflict {
            cd_offset_valid_but_size_conflict += 1;
        } else if entry_offset_conflict && !entry_size_conflict {
            cd_size_valid_but_offset_conflict += 1;
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
    descriptor.set_item("descriptor_candidate_span_overlap_count", descriptor_candidate_span_overlap)?;
    descriptor.set_item(
        "descriptor_payload_end_to_next_local_delta_min",
        descriptor_payload_end_to_next_local_delta_min.unwrap_or(0),
    )?;
    descriptor.set_item("cd_compressed_size_points_into_descriptor_count", cd_compressed_size_points_into_descriptor)?;
    descriptor.set_item("compressed_size_ends_before_descriptor_count", compressed_size_ends_before_descriptor)?;
    descriptor.set_item("compressed_size_ends_inside_descriptor_count", compressed_size_ends_inside_descriptor)?;
    descriptor.set_item("compressed_size_ends_after_descriptor_count", compressed_size_ends_after_descriptor)?;
    descriptor.set_item("compressed_size_ends_after_next_local_count", compressed_size_ends_after_next_local)?;
    descriptor.set_item(
        "compressed_size_ends_before_next_local_gap_count",
        compressed_size_ends_before_next_local_gap,
    )?;
    descriptor.set_item("descriptor_span_between_payload_and_next_local_count", descriptor_span_between_payload_and_next_local)?;
    descriptor.set_item("cd_entry_span_conflict_count", cd_entry_span_conflict)?;
    descriptor.set_item("wrong_local_header_target_count", wrong_local_header_target)?;
    descriptor.set_item("local_header_offset_points_to_other_entry_count", local_header_offset_points_to_other_entry)?;
    descriptor.set_item(
        "local_header_offset_points_to_descriptor_or_payload_count",
        local_header_offset_points_to_descriptor_or_payload,
    )?;
    descriptor.set_item("local_header_offset_points_inside_payload_count", local_header_offset_points_inside_payload)?;
    descriptor.set_item(
        "local_header_offset_points_inside_descriptor_count",
        local_header_offset_points_inside_descriptor,
    )?;
    descriptor.set_item("local_header_offset_points_outside_archive_count", local_header_offset_points_outside_archive)?;
    descriptor.set_item("local_header_offset_bad_signature_count", local_header_offset_bad_signature)?;
    descriptor.set_item(
        "local_header_offset_target_conflict_ratio",
        wrong_local_header_target as f64 / checked_entries.len().max(1) as f64,
    )?;
    descriptor.set_item("descriptor_span_present_count", descriptor_span_present)?;
    descriptor.set_item("descriptor_span_missing_count", descriptor_span_missing)?;
    descriptor.set_item(
        "descriptor_between_payload_and_next_local_count",
        descriptor_between_payload_and_next_local,
    )?;
    descriptor.set_item(
        "descriptor_flag_set_but_span_missing_count",
        descriptor_flag_set_but_span_missing,
    )?;
    descriptor.set_item(
        "descriptor_span_present_without_flag_count",
        descriptor_span_present_without_flag,
    )?;
    descriptor.set_item(
        "descriptor_span_conflicts_with_cd_size_count",
        descriptor_span_conflicts_with_cd_size,
    )?;
    descriptor.set_item("cd_size_points_to_descriptor_start_count", cd_size_points_to_descriptor_start)?;
    descriptor.set_item("cd_size_points_inside_descriptor_count", cd_size_points_inside_descriptor)?;
    descriptor.set_item("cd_offset_size_joint_conflict_count", cd_offset_size_joint_conflict)?;
    descriptor.set_item("cd_offset_valid_but_size_conflict_count", cd_offset_valid_but_size_conflict)?;
    descriptor.set_item("cd_size_valid_but_offset_conflict_count", cd_size_valid_but_offset_conflict)?;
    result.set_item("descriptor", descriptor)?;

    let prefix = PyDict::new(py);
    prefix.set_item("first_local_header_found", !local_candidates.is_empty())?;
    prefix.set_item("first_local_header_offset", first_local_offset)?;
    prefix.set_item("prefix_bytes_before_first_local", prefix_len)?;
    prefix.set_item("prefix_has_non_zip_bytes", prefix_len > 0 && data.get(0..4) != Some(LFH_SIG))?;
    prefix.set_item(
        "prefix_has_executable_signature",
        prefix_len >= 2 && (data.get(0..2) == Some(b"MZ") || data.get(0..2) == Some(b"#!")),
    )?;
    prefix.set_item("local_offset_valid_without_prefix_count", local_offset_valid_without_prefix)?;
    prefix.set_item("local_offset_valid_with_prefix_count", local_offset_valid_with_prefix)?;
    prefix.set_item("local_offset_only_valid_with_prefix_count", local_offset_only_valid_with_prefix)?;
    prefix.set_item(
        "local_offset_invalid_after_prefix_adjustment_count",
        local_offset_invalid_after_prefix_adjustment,
    )?;
    prefix.set_item(
        "local_offset_prefix_adjustment_success_ratio",
        local_offset_valid_with_prefix as f64 / checked_entries.len().max(1) as f64,
    )?;
    result.set_item("prefix", prefix)?;

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

pub(crate) fn inspect_zip_structure_graph(
    py: Python<'_>,
    path: &str,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("schema_version", 1)?;
    result.set_item("format", "zip")?;
    result.set_item("error", "")?;
    result.set_item("truncated", false)?;
    let nodes = PyList::empty(py);
    let edges = PyList::empty(py);
    let violations = PyList::empty(py);
    let explanations = PyList::empty(py);
    let summary = PyDict::new(py);
    result.set_item("nodes", &nodes)?;
    result.set_item("edges", &edges)?;
    result.set_item("violations", &violations)?;
    result.set_item("explanations", &explanations)?;
    result.set_item("summary", &summary)?;

    let Ok(data) = fs::read(path) else {
        result.set_item("error", "os_error")?;
        summary.set_item("archive_readable", false)?;
        return Ok(result.unbind());
    };
    let file_size = data.len();
    summary.set_item("archive_readable", true)?;
    summary.set_item("file_size", file_size)?;
    zip_graph_node(py, &nodes, "archive:0", "archive", 0, file_size, "parsed")?;
    zip_graph_node(py, &nodes, "physical_span:archive", "physical_span", 0, file_size, "observed")?;
    zip_graph_edge(py, &edges, "archive:0", "physical_span:archive", "owns_span", "", true, 1.0)?;

    let Some(eocd) = find_eocd_record(&data, true) else {
        result.set_item("error", "eocd_not_found")?;
        summary.set_item("eocd_present", false)?;
        zip_graph_violation(py, &violations, "missing_node", "archive:0", "", "eocd", "", "", 0, "high")?;
        return Ok(result.unbind());
    };
    summary.set_item("eocd_present", true)?;
    let eocd_id = "eocd:0";
    zip_graph_node(py, &nodes, eocd_id, "eocd", eocd.offset, eocd.end, "parsed")?;
    zip_graph_edge(py, &edges, "archive:0", eocd_id, "contains", "", true, 1.0)?;
    let trailing = file_size.saturating_sub(eocd.end);
    summary.set_item("trailing_bytes_after_eocd", trailing)?;
    if trailing > 0 {
        zip_graph_node(py, &nodes, "physical_span:tail", "physical_span", eocd.end, file_size, "observed")?;
        zip_graph_violation(
            py,
            &violations,
            "unexpected_tail",
            eocd_id,
            "physical_span:tail",
            "tail.trailing_bytes",
            "0",
            &trailing.to_string(),
            trailing as i64,
            "medium",
        )?;
        zip_graph_explanation(py, &explanations, "tail_truncation", false, "tail.trailing_bytes", 0, "tail bytes exist after EOCD")?;
    }

    let physical_cd_offset = eocd.offset.saturating_sub(eocd.cd_size as usize);
    let archive_offset = physical_cd_offset.saturating_sub(eocd.cd_offset as usize);
    let cd_end = physical_cd_offset
        .saturating_add(eocd.cd_size as usize)
        .min(file_size);
    let cd_id = "central_directory:0";
    summary.set_item("declared_central_directory_offset", eocd.cd_offset as usize)?;
    summary.set_item("physical_central_directory_offset", physical_cd_offset)?;
    summary.set_item("central_directory_offset_delta", physical_cd_offset as i64 - eocd.cd_offset as i64)?;
    summary.set_item("central_directory_size_delta", cd_end.saturating_sub(physical_cd_offset) as i64 - eocd.cd_size as i64)?;
    zip_graph_node(py, &nodes, cd_id, "central_directory", physical_cd_offset, cd_end, "candidate")?;
    zip_graph_edge(py, &edges, eocd_id, cd_id, "points_to", "central_directory", physical_cd_offset + 4 <= file_size && data.get(physical_cd_offset..physical_cd_offset + 4) == Some(CD_SIG), 1.0)?;
    if physical_cd_offset + 4 > file_size || data.get(physical_cd_offset..physical_cd_offset + 4) != Some(CD_SIG) {
        result.set_item("error", "bad_central_directory_signature")?;
        zip_graph_violation(
            py,
            &violations,
            "bad_signature",
            eocd_id,
            cd_id,
            "eocd.cd_offset",
            "central_directory_signature",
            "missing",
            physical_cd_offset as i64 - eocd.cd_offset as i64,
            "high",
        )?;
    }
    if archive_offset > 0 {
        zip_graph_node(py, &nodes, "physical_span:sfx_prefix", "physical_span", 0, archive_offset, "observed")?;
        zip_graph_explanation(
            py,
            &explanations,
            "sfx_prefix_adjustment",
            physical_cd_offset == archive_offset.saturating_add(eocd.cd_offset as usize),
            "eocd.cd_offset",
            archive_offset as i64,
            "archive offset explains central directory pointer",
        )?;
    }

    let all_entries = parse_central_directory_entries(&data, physical_cd_offset, cd_end);
    let checked_entries = all_entries.iter().take(max_entries).collect::<Vec<_>>();
    result.set_item("truncated", all_entries.len() > checked_entries.len())?;
    summary.set_item("cd_entry_count", all_entries.len())?;
    summary.set_item("cd_entries_checked", checked_entries.len())?;
    summary.set_item("entry_count_delta", all_entries.len() as i64 - eocd.total_entries as i64)?;
    if all_entries.len() as u16 != eocd.total_entries {
        zip_graph_violation(
            py,
            &violations,
            "count_mismatch",
            eocd_id,
            cd_id,
            "eocd.entry_count",
            &eocd.total_entries.to_string(),
            &all_entries.len().to_string(),
            all_entries.len() as i64 - eocd.total_entries as i64,
            "medium",
        )?;
    }

    let local_candidates = scan_zip_local_headers(&data, physical_cd_offset, max_entries.saturating_mul(4).max(32));
    let local_spans = local_record_spans(&local_candidates, physical_cd_offset);
    let (known_payload_spans, known_descriptor_spans) =
        local_payload_descriptor_spans(&data, &local_candidates, physical_cd_offset);
    summary.set_item("local_header_candidate_count", local_candidates.len())?;
    let first_local_offset = local_candidates.first().map(|local| local.offset).unwrap_or(0);
    let prefix_len = first_local_offset;
    summary.set_item("first_local_header_offset", first_local_offset)?;
    summary.set_item("sfx_prefix_len", prefix_len)?;
    for (index, local) in local_candidates.iter().take(max_entries).enumerate() {
        let local_id = format!("local_header:{index}");
        let end = local_data_start(local).unwrap_or(local.offset).min(file_size);
        zip_graph_node(py, &nodes, &local_id, "local_header_candidate", local.offset, end, "parsed")?;
        zip_graph_edge(py, &edges, "archive:0", &local_id, "contains", "", true, 0.8)?;
    }
    for (index, (start, end)) in known_payload_spans.iter().take(max_entries).enumerate() {
        zip_graph_node(py, &nodes, &format!("payload_span:{index}"), "payload_span", *start, *end, "candidate")?;
    }
    for (index, (start, end)) in known_descriptor_spans.iter().take(max_entries).enumerate() {
        zip_graph_node(py, &nodes, &format!("descriptor_candidate:{index}"), "descriptor_candidate", *start, *end, "candidate")?;
    }

    let mut name_mismatch = 0usize;
    let mut flags_mismatch = 0usize;
    let mut method_mismatch = 0usize;
    let mut crc_mismatch = 0usize;
    let mut compressed_mismatch = 0usize;
    let mut uncompressed_mismatch = 0usize;
    let mut local_offset_violations = 0usize;
    let mut span_conflicts = 0usize;
    let mut descriptor_conflicts = 0usize;
    let mut zip64_extra_present = 0usize;
    let mut zip64_extra_mismatch = 0usize;

    for (index, entry) in checked_entries.iter().enumerate() {
        let cd_entry_id = format!("cd_entry:{index}");
        let cd_entry_end = entry.offset
            .saturating_add(46)
            .saturating_add(entry.name_len as usize)
            .saturating_add(entry.extra_len as usize);
        zip_graph_node(py, &nodes, &cd_entry_id, "cd_entry", entry.offset, cd_entry_end, "parsed")?;
        zip_graph_edge(py, &edges, cd_id, &cd_entry_id, "owns_span", "", true, 1.0)?;
        let raw_local_offset = entry.local_header_offset as usize;
        let archive_adjusted_offset = archive_offset.saturating_add(raw_local_offset);
        let prefix_adjusted_offset = raw_local_offset.saturating_add(prefix_len);
        let raw_local = parse_local_header(&data, raw_local_offset);
        let archive_adjusted_local = parse_local_header(&data, archive_adjusted_offset);
        let prefix_adjusted_local = if prefix_len > 0 { parse_local_header(&data, prefix_adjusted_offset) } else { None };
        let matched_local = prefix_adjusted_local
            .clone()
            .or_else(|| archive_adjusted_local.clone())
            .or_else(|| raw_local.clone())
            .or_else(|| local_candidates.iter().find(|candidate| candidate.name == entry.name).cloned());
        let local_target_id = format!("local_header_target:{index}");
        let local_ok = matched_local.as_ref().is_some_and(|local| local.name == entry.name);
        zip_graph_edge(py, &edges, &cd_entry_id, &local_target_id, "points_to", "local_header_offset", local_ok, if local_ok { 1.0 } else { 0.0 })?;
        if !local_ok {
            local_offset_violations += 1;
            let observed = if raw_local_offset >= file_size {
                "outside_archive"
            } else if offset_inside_local_or_data_span(raw_local_offset, &known_descriptor_spans) {
                "inside_descriptor"
            } else if offset_inside_local_or_data_span(raw_local_offset, &known_payload_spans) || offset_inside_local_or_data_span(raw_local_offset, &local_spans) {
                "inside_payload_or_entry"
            } else {
                "bad_signature"
            };
            zip_graph_violation(
                py,
                &violations,
                "bad_reference",
                &cd_entry_id,
                &local_target_id,
                "central_directory.local_header_offset",
                "local_header",
                observed,
                raw_local_offset as i64 - archive_adjusted_offset as i64,
                "high",
            )?;
        }
        let Some(local) = matched_local else {
            continue;
        };
        zip_graph_node(py, &nodes, &local_target_id, "local_header_candidate", local.offset, local_data_start(&local).unwrap_or(local.offset), "matched")?;
        if local.name != entry.name {
            name_mismatch += 1;
            zip_graph_violation(py, &violations, "field_mismatch", &cd_entry_id, &local_target_id, "central_directory.filename", "cd_name", "local_name", 0, "medium")?;
        }
        if local.flags != entry.flags {
            flags_mismatch += 1;
            zip_graph_violation(py, &violations, "field_mismatch", &cd_entry_id, &local_target_id, "local_header.flags", &entry.flags.to_string(), &local.flags.to_string(), local.flags as i64 - entry.flags as i64, "medium")?;
        }
        if local.method != entry.method {
            method_mismatch += 1;
            zip_graph_violation(py, &violations, "field_mismatch", &cd_entry_id, &local_target_id, "local_header.method", &entry.method.to_string(), &local.method.to_string(), local.method as i64 - entry.method as i64, "medium")?;
        }
        if entry.flags & 0x08 == 0 {
            if local.crc32 != entry.crc32 {
                crc_mismatch += 1;
                zip_graph_violation(py, &violations, "field_mismatch", &cd_entry_id, &local_target_id, "local_header.crc", &entry.crc32.to_string(), &local.crc32.to_string(), local.crc32 as i64 - entry.crc32 as i64, "medium")?;
            }
            if entry.compressed_size != u32::MAX && local.compressed_size != entry.compressed_size {
                compressed_mismatch += 1;
                zip_graph_violation(py, &violations, "field_mismatch", &cd_entry_id, &local_target_id, "local_header.compressed_size", &entry.compressed_size.to_string(), &local.compressed_size.to_string(), local.compressed_size as i64 - entry.compressed_size as i64, "medium")?;
            }
            if entry.uncompressed_size != u32::MAX && local.uncompressed_size != entry.uncompressed_size {
                uncompressed_mismatch += 1;
                zip_graph_violation(py, &violations, "field_mismatch", &cd_entry_id, &local_target_id, "local_header.uncompressed_size", &entry.uncompressed_size.to_string(), &local.uncompressed_size.to_string(), local.uncompressed_size as i64 - entry.uncompressed_size as i64, "medium")?;
            }
        }
        let data_start = local_data_start(&local).unwrap_or(local.offset);
        let payload_end = data_start.saturating_add(entry.compressed_size as usize);
        zip_graph_node(py, &nodes, &format!("payload_span:cd:{index}"), "payload_span", data_start, payload_end.min(file_size), "declared")?;
        zip_graph_edge(py, &edges, &local_target_id, &format!("payload_span:cd:{index}"), "owns_span", "payload", payload_end <= file_size, 0.9)?;
        let next_boundary = checked_entries
            .get(index + 1)
            .map(|next| next.local_header_offset as usize + prefix_len)
            .or_else(|| checked_entries.get(index + 1).map(|next| next.local_header_offset as usize))
            .unwrap_or(physical_cd_offset)
            .min(file_size);
        if payload_end > next_boundary {
            span_conflicts += 1;
            zip_graph_violation(py, &violations, "span_overlap", &format!("payload_span:cd:{index}"), "next_record", "central_directory.compressed_size", &next_boundary.to_string(), &payload_end.to_string(), payload_end as i64 - next_boundary as i64, "high")?;
        }
        if payload_end < next_boundary {
            if let Some(descriptor_offset) = find_signature_between(&data, payload_end, next_boundary, DD_SIG) {
                let descriptor_end = descriptor_at_impl(
                    &data,
                    descriptor_offset,
                    entry.crc32,
                    entry.compressed_size as u64,
                    entry.uncompressed_size as u64,
                )
                .unwrap_or_else(|| descriptor_offset.saturating_add(16).min(next_boundary));
                zip_graph_node(py, &nodes, &format!("descriptor_candidate:cd:{index}"), "descriptor_candidate", descriptor_offset, descriptor_end, "candidate")?;
                zip_graph_edge(py, &edges, &format!("payload_span:cd:{index}"), &format!("descriptor_candidate:cd:{index}"), "adjacent_to", "data_descriptor", payload_end == descriptor_offset, 0.8)?;
                if payload_end != descriptor_offset {
                    descriptor_conflicts += 1;
                    zip_graph_violation(py, &violations, "descriptor_span_gap", &format!("payload_span:cd:{index}"), &format!("descriptor_candidate:cd:{index}"), "data_descriptor.record", &payload_end.to_string(), &descriptor_offset.to_string(), descriptor_offset as i64 - payload_end as i64, "medium")?;
                    zip_graph_explanation(py, &explanations, "descriptor_span_adjustment", true, "central_directory.compressed_size", descriptor_offset as i64 - payload_end as i64, "descriptor candidate explains payload boundary drift")?;
                }
            }
        }
        if parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset).is_some()
            || parse_zip64_extra_tolerant(&local.extra, local.extra_offset).is_some()
        {
            zip64_extra_present += 1;
            zip_graph_explanation(py, &explanations, "zip64_extra_resolution", true, "zip64.extra", 0, "ZIP64 extra fields are present")?;
        }
        if let Some(central_zip64) = parse_zip64_extra_tolerant(&entry.extra, entry.extra_offset) {
            if central_zip64.stored_size != central_zip64.values.len() * 8 {
                zip64_extra_mismatch += 1;
                zip_graph_violation(py, &violations, "zip64_extra_mismatch", &cd_entry_id, "zip64_extra", "zip64.extra_length", &(central_zip64.values.len() * 8).to_string(), &central_zip64.stored_size.to_string(), central_zip64.stored_size as i64 - (central_zip64.values.len() * 8) as i64, "medium")?;
            }
        }
    }
    summary.set_item("violation_count", violations.len())?;
    summary.set_item("edge_count", edges.len())?;
    summary.set_item("node_count", nodes.len())?;
    summary.set_item("central_local_name_mismatch_count", name_mismatch)?;
    summary.set_item("central_local_flags_mismatch_count", flags_mismatch)?;
    summary.set_item("central_local_method_mismatch_count", method_mismatch)?;
    summary.set_item("central_local_crc_mismatch_count", crc_mismatch)?;
    summary.set_item("central_local_compressed_size_mismatch_count", compressed_mismatch)?;
    summary.set_item("central_local_uncompressed_size_mismatch_count", uncompressed_mismatch)?;
    summary.set_item("local_header_offset_violation_count", local_offset_violations)?;
    summary.set_item("span_conflict_count", span_conflicts)?;
    summary.set_item("descriptor_conflict_count", descriptor_conflicts)?;
    summary.set_item("zip64_extra_present_count", zip64_extra_present)?;
    summary.set_item("zip64_extra_mismatch_count", zip64_extra_mismatch)?;
    let zip64_eocd = find_zip64_eocd(&data, eocd.offset);
    let zip64_locator = find_zip64_locator(&data, eocd.offset);
    summary.set_item("zip64_eocd_present", zip64_eocd.is_some())?;
    summary.set_item("zip64_locator_present", zip64_locator.is_some())?;
    if let Some(tail) = zip64_eocd {
        zip_graph_node(py, &nodes, "zip64_eocd:0", "zip64_eocd", tail.offset, tail.end, "parsed")?;
    }
    if let Some(locator) = zip64_locator {
        zip_graph_node(py, &nodes, "zip64_locator:0", "zip64_locator", locator.offset, locator.end, "parsed")?;
        zip_graph_edge(py, &edges, "zip64_locator:0", "zip64_eocd:0", "points_to", "zip64_locator", zip64_eocd.is_some_and(|tail| locator.zip64_eocd_offset == tail.offset as u64), 0.9)?;
    }
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
    let descriptor = PyDict::new(py);
    for key in [
        "descriptor_checked_count",
        "descriptor_present_count",
        "descriptor_missing_count",
        "descriptor_flag_mismatch_count",
        "spurious_descriptor_candidate_count",
        "descriptor_candidate_span_overlap_count",
        "descriptor_payload_end_to_next_local_delta_min",
        "cd_compressed_size_points_into_descriptor_count",
        "compressed_size_ends_before_descriptor_count",
        "compressed_size_ends_inside_descriptor_count",
        "compressed_size_ends_after_descriptor_count",
        "compressed_size_ends_after_next_local_count",
        "compressed_size_ends_before_next_local_gap_count",
        "descriptor_span_between_payload_and_next_local_count",
        "cd_entry_span_conflict_count",
        "wrong_local_header_target_count",
        "local_header_offset_points_to_other_entry_count",
        "local_header_offset_points_to_descriptor_or_payload_count",
        "local_header_offset_points_inside_payload_count",
        "local_header_offset_points_inside_descriptor_count",
        "local_header_offset_points_outside_archive_count",
        "local_header_offset_bad_signature_count",
        "descriptor_span_present_count",
        "descriptor_span_missing_count",
        "descriptor_between_payload_and_next_local_count",
        "descriptor_flag_set_but_span_missing_count",
        "descriptor_span_present_without_flag_count",
        "descriptor_span_conflicts_with_cd_size_count",
        "cd_size_points_to_descriptor_start_count",
        "cd_size_points_inside_descriptor_count",
        "cd_offset_size_joint_conflict_count",
        "cd_offset_valid_but_size_conflict_count",
        "cd_size_valid_but_offset_conflict_count",
    ] {
        descriptor.set_item(key, 0)?;
    }
    descriptor.set_item("local_header_offset_target_conflict_ratio", 0.0)?;
    result.set_item("descriptor", descriptor)?;
    Ok(result)
}

fn zip_graph_node<'py>(
    py: Python<'py>,
    nodes: &Bound<'py, PyList>,
    id: &str,
    kind: &str,
    start: usize,
    end: usize,
    status: &str,
) -> PyResult<()> {
    let node = PyDict::new(py);
    node.set_item("id", id)?;
    node.set_item("kind", kind)?;
    node.set_item("start", start)?;
    node.set_item("end", end)?;
    node.set_item("size", end.saturating_sub(start))?;
    node.set_item("status", status)?;
    nodes.append(node)
}

fn zip_graph_edge<'py>(
    py: Python<'py>,
    edges: &Bound<'py, PyList>,
    source: &str,
    target: &str,
    kind: &str,
    field: &str,
    valid: bool,
    confidence: f64,
) -> PyResult<()> {
    let edge = PyDict::new(py);
    edge.set_item("source_node", source)?;
    edge.set_item("target_node", target)?;
    edge.set_item("kind", kind)?;
    edge.set_item("field", field)?;
    edge.set_item("valid", valid)?;
    edge.set_item("confidence", confidence)?;
    edges.append(edge)
}

fn zip_graph_violation<'py>(
    py: Python<'py>,
    violations: &Bound<'py, PyList>,
    kind: &str,
    source: &str,
    target: &str,
    field: &str,
    expected: &str,
    observed: &str,
    delta: i64,
    severity: &str,
) -> PyResult<()> {
    let violation = PyDict::new(py);
    violation.set_item("kind", kind)?;
    violation.set_item("source_node", source)?;
    violation.set_item("target_node", target)?;
    violation.set_item("field", field)?;
    violation.set_item("expected", expected)?;
    violation.set_item("observed", observed)?;
    violation.set_item("delta", delta)?;
    violation.set_item("severity", severity)?;
    violations.append(violation)
}

fn zip_graph_explanation<'py>(
    py: Python<'py>,
    explanations: &Bound<'py, PyList>,
    kind: &str,
    applies: bool,
    field: &str,
    delta: i64,
    reason: &str,
) -> PyResult<()> {
    let explanation = PyDict::new(py);
    explanation.set_item("kind", kind)?;
    explanation.set_item("applies", applies)?;
    explanation.set_item("field", field)?;
    explanation.set_item("delta", delta)?;
    explanation.set_item("reason", reason)?;
    explanations.append(explanation)
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

fn scan_zip_local_headers(data: &[u8], before: usize, limit: usize) -> Vec<LocalHeader> {
    let mut output = Vec::new();
    let mut cursor = 0usize;
    let end = before.min(data.len());
    while cursor + LOCAL_HEADER_LEN <= end && output.len() < limit {
        let Some(delta) = memmem::find(&data[cursor..end], LFH_SIG) else {
            break;
        };
        let offset = cursor + delta;
        if let Some(local) = parse_local_header(data, offset) {
            output.push(local);
        }
        cursor = offset.saturating_add(1);
    }
    output
}

fn local_record_spans(locals: &[LocalHeader], cd_offset: usize) -> Vec<(usize, usize)> {
    let mut offsets = locals.iter().map(|local| local.offset).collect::<Vec<_>>();
    offsets.sort_unstable();
    let mut output = Vec::new();
    for local in locals {
        let data_start = local
            .offset
            .checked_add(LOCAL_HEADER_LEN)
            .and_then(|value| value.checked_add(local.name_len as usize))
            .and_then(|value| value.checked_add(local.extra_len as usize))
            .unwrap_or(local.offset);
        let next_local = offsets
            .iter()
            .copied()
            .find(|offset| *offset > local.offset)
            .unwrap_or(cd_offset);
        output.push((local.offset, next_local.max(data_start).max(local.offset + LOCAL_HEADER_LEN)));
    }
    output
}

fn local_payload_descriptor_spans(
    data: &[u8],
    locals: &[LocalHeader],
    cd_offset: usize,
) -> (Vec<(usize, usize)>, Vec<(usize, usize)>) {
    let mut offsets = locals.iter().map(|local| local.offset).collect::<Vec<_>>();
    offsets.sort_unstable();
    let mut payload_spans = Vec::new();
    let mut descriptor_spans = Vec::new();
    for local in locals {
        let Some(data_start) = local_data_start(local) else {
            continue;
        };
        let next_local = offsets
            .iter()
            .copied()
            .find(|offset| *offset > local.offset)
            .unwrap_or(cd_offset)
            .min(data.len());
        if data_start >= next_local {
            continue;
        }
        if let Some(descriptor_offset) = find_signature_between(data, data_start, next_local, DD_SIG) {
            payload_spans.push((data_start, descriptor_offset));
            descriptor_spans.push((descriptor_offset, descriptor_offset.saturating_add(24).min(next_local)));
        } else {
            payload_spans.push((data_start, next_local));
        }
    }
    (payload_spans, descriptor_spans)
}

fn local_data_start(local: &LocalHeader) -> Option<usize> {
    local
        .offset
        .checked_add(LOCAL_HEADER_LEN)?
        .checked_add(local.name_len as usize)?
        .checked_add(local.extra_len as usize)
}

fn offset_inside_local_or_data_span(offset: usize, spans: &[(usize, usize)]) -> bool {
    spans.iter().any(|(start, end)| offset > *start && offset < *end)
}

fn find_signature_between(data: &[u8], start: usize, end: usize, signature: &[u8]) -> Option<usize> {
    if start >= end || start >= data.len() {
        return None;
    }
    let bounded_end = end.min(data.len());
    memmem::find(&data[start..bounded_end], signature).map(|delta| start + delta)
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
