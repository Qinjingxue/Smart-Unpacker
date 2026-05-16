fn scan_entries(data: &[u8], options: &DeepZipOptions, started: Instant) -> ScanResult {
    let mut result = ScanResult::default();
    for offset in memmem::find_iter(data, LFH_SIG).take(options.max_entries) {
        result.lfh_scanned += 1;
        if timed_out(started, options.max_duration) {
            result.timed_out = true;
            result
                .warnings
                .push("ZIP deep recovery time budget reached".to_string());
            break;
        }
        let parse_started = Instant::now();
        let outcome = parse_entry(data, offset, options, &mut result.timing);
        result.timing.parse_entry_seconds += parse_started.elapsed().as_secs_f64();
        match outcome {
            EntryOutcome::Recovered(entry) => {
                if entry.descriptor {
                    result.descriptor_entries += 1;
                }
                if entry.passthrough {
                    result.unsupported_entries += 1;
                }
                if entry.boundary_source == BoundarySource::NextRecord {
                    result.next_lfh_boundary_entries += 1;
                }
                if entry.boundary_source == BoundarySource::DeflateConsumed {
                    result.deflate_consumed_boundary_entries += 1;
                }
                if entry.boundary_source == BoundarySource::Descriptor {
                    if descriptor_at(data, entry.data_end, entry.crc32, entry.compressed_size, entry.uncompressed_size) {
                        result.descriptor_signature_entries += 1;
                    } else {
                        result.descriptor_no_signature_entries += 1;
                    }
                }
                if entry.experimental_deflate_resync {
                    result.deflate_resync_partial_entries += 1;
                }
                result.entries.push(entry);
            }
            EntryOutcome::Encrypted => result.encrypted_entries += 1,
            EntryOutcome::Skipped(message) => {
                result.skipped_offsets.push(offset);
                if result.warnings.len() < 32 {
                    result.warnings.push(format!("offset {offset}: {message}"));
                }
            }
        }
    }
    dedupe(&mut result.warnings);
    result
}

enum EntryOutcome {
    Recovered(RecoveredEntry),
    Encrypted,
    Skipped(String),
}

fn parse_entry(data: &[u8], offset: usize, options: &DeepZipOptions, timing: &mut ScanTiming) -> EntryOutcome {
    if offset + LOCAL_HEADER_LEN > data.len() {
        return EntryOutcome::Skipped("short local header".to_string());
    }
    let version_needed = u16_le(data, offset + 4);
    let flags = u16_le(data, offset + 6);
    let method = u16_le(data, offset + 8);
    let mod_time = u16_le(data, offset + 10);
    let mod_date = u16_le(data, offset + 12);
    let header_crc32 = u32_le(data, offset + 14);
    let header_compressed = u32_le(data, offset + 18);
    let header_uncompressed = u32_le(data, offset + 22);
    let name_len = u16_le(data, offset + 26) as usize;
    let extra_len = u16_le(data, offset + 28) as usize;
    if version_needed > 63 {
        return EntryOutcome::Skipped("unsupported ZIP version".to_string());
    }
    let is_encrypted = flags & 0x01 != 0;
    if is_encrypted && options.password.is_none() {
        return EntryOutcome::Encrypted;
    }
    if name_len == 0 || name_len > MAX_NAME_LEN {
        return EntryOutcome::Skipped("invalid filename length".to_string());
    }
    let name_start = offset + LOCAL_HEADER_LEN;
    let extra_start = name_start + name_len;
    let data_start = extra_start + extra_len;
    if data_start > data.len() {
        return EntryOutcome::Skipped("local header exceeds input size".to_string());
    }
    let name = data[name_start..extra_start].to_vec();
    if name.iter().any(|byte| *byte == 0) {
        return EntryOutcome::Skipped("filename contains NUL".to_string());
    }
    let extra = &data[extra_start..data_start];
    if flags & 0x08 != 0 {
        return parse_descriptor_entry(
            data,
            offset,
            data_start,
            name,
            extra.to_vec(),
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            options,
            timing,
        );
    }

    let (compressed_size, uncompressed_size) =
        match zip64_sizes(extra, header_compressed, header_uncompressed) {
            Some(sizes) => sizes,
            None => return EntryOutcome::Skipped("ZIP64 local sizes are incomplete".to_string()),
        };
    if compressed_size > u32::MAX as u64 || uncompressed_size > u32::MAX as u64 {
        return EntryOutcome::Skipped(
            "ZIP64-sized entries are not rewritten by deep recovery yet".to_string(),
        );
    }
    let mut boundary_source = BoundarySource::HeaderSize;
    let data_end = match data_start.checked_add(compressed_size as usize) {
        Some(end) if end <= data.len() => end,
        Some(_) if method == 8 && options.verify_candidates => {
            let verify_started = Instant::now();
            match verified_deflate_payload_end(
                data,
                data_start,
                None,
                header_crc32,
                uncompressed_size,
                options,
            ) {
                Some((end, source)) => {
                    timing.verify_deflate_seconds += verify_started.elapsed().as_secs_f64();
                    boundary_source = source;
                    end
                }
                None => {
                    timing.verify_deflate_seconds += verify_started.elapsed().as_secs_f64();
                    return EntryOutcome::Skipped("entry payload is truncated".to_string());
                }
            }
        }
        Some(_) if method == 0 && options.verify_candidates => {
            let verify_started = Instant::now();
            match verified_store_payload_end(data, data_start, header_crc32, uncompressed_size) {
                Some((end, source)) => {
                    timing.verify_store_seconds += verify_started.elapsed().as_secs_f64();
                    boundary_source = source;
                    end
                }
                None => {
                    timing.verify_store_seconds += verify_started.elapsed().as_secs_f64();
                    return EntryOutcome::Skipped("stored entry payload is truncated".to_string());
                }
            }
        }
        Some(_) => return EntryOutcome::Skipped("entry payload is truncated".to_string()),
        None => {
            return EntryOutcome::Skipped("compressed size overflows input range".to_string());
        }
    };
    let entry_is_encrypted = flags & 0x01 != 0;
    let data_end = if entry_is_encrypted {
        data_end
    } else if method == 8 && options.verify_candidates {
        let verify_started = Instant::now();
        match verified_deflate_payload_end(
            data,
            data_start,
            Some(data_end),
            header_crc32,
            uncompressed_size,
            options,
        ) {
            Some((end, source)) => {
                timing.verify_deflate_seconds += verify_started.elapsed().as_secs_f64();
                boundary_source = source;
                end
            }
            None => {
                timing.verify_deflate_seconds += verify_started.elapsed().as_secs_f64();
                data_end
            }
        }
    } else if method == 0 && options.verify_candidates {
        let verify_started = Instant::now();
        match verified_store_payload_end(data, data_start, header_crc32, uncompressed_size) {
            Some((end, source)) => {
                timing.verify_store_seconds += verify_started.elapsed().as_secs_f64();
                boundary_source = source;
                end
            }
            None => {
                timing.verify_store_seconds += verify_started.elapsed().as_secs_f64();
                data_end
            }
        }
    } else {
        data_end
    };
    classify_entry(
        data,
        offset,
        data_start,
        data_end,
        name,
        extra.to_vec(),
        version_needed,
        flags,
        method,
        mod_time,
        mod_date,
        header_crc32,
        compressed_size,
        uncompressed_size,
        false,
        boundary_source,
        options,
        timing,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_descriptor_entry(
    data: &[u8],
    local_header_offset: usize,
    data_start: usize,
    name: Vec<u8>,
    extra: Vec<u8>,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    options: &DeepZipOptions,
    timing: &mut ScanTiming,
) -> EntryOutcome {
    if method == 8 && options.verify_candidates {
        let verify_started = Instant::now();
        match verify_deflate(
            &data[data_start..],
            None,
            None,
            options.max_entry_uncompressed_bytes,
            false,
        ) {
            Ok(info) => {
                timing.verify_deflate_seconds += verify_started.elapsed().as_secs_f64();
                let data_end = data_start + info.consumed;
                let _descriptor = descriptor_at(
                    data,
                    data_end,
                    info.crc32,
                    info.consumed as u64,
                    info.uncompressed_size,
                );
                return EntryOutcome::Recovered(RecoveredEntry {
                    name,
                    extra: extra.clone(),
                    local_header_offset,
                    version_needed,
                    flags,
                    method,
                    mod_time,
                    mod_date,
                    crc32: info.crc32,
                    compressed_size: info.consumed as u64,
                    uncompressed_size: info.uncompressed_size,
                    data_start,
                    data_end,
                    payload_override: None,
                    verified: true,
                    descriptor: true,
                    passthrough: false,
                    boundary_source: BoundarySource::DeflateConsumed,
                    experimental_deflate_resync: false,
                });
            }
            Err(_) => {
                timing.verify_deflate_seconds += verify_started.elapsed().as_secs_f64();
                let resync_started = Instant::now();
                if let Some(entry) = deflate_resync_partial_entry(
                    data,
                    local_header_offset,
                    data_start,
                    name.clone(),
                    extra.clone(),
                    version_needed,
                    flags,
                    mod_time,
                    mod_date,
                    options,
                ) {
                    timing.deflate_resync_seconds += resync_started.elapsed().as_secs_f64();
                    return EntryOutcome::Recovered(entry);
                }
                timing.deflate_resync_seconds += resync_started.elapsed().as_secs_f64();
            }
        }
    }

    let descriptor_started = Instant::now();
    let Some((descriptor_start, crc32, compressed_size, uncompressed_size)) =
        descriptor_before_next_record(data, data_start, Some(&mut *timing))
    else {
        timing.descriptor_probe_seconds += descriptor_started.elapsed().as_secs_f64();
        return EntryOutcome::Skipped("data descriptor could not be recovered".to_string());
    };
    timing.descriptor_probe_seconds += descriptor_started.elapsed().as_secs_f64();
    let data_end = descriptor_start;
    if method == 0 {
        return classify_entry(
            data,
            local_header_offset,
            data_start,
            data_end,
            name,
            extra,
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            true,
            BoundarySource::Descriptor,
            options,
            timing,
        );
    }
    if compressed_size > u32::MAX as u64 || uncompressed_size > u32::MAX as u64 {
        return EntryOutcome::Skipped("ZIP64-sized descriptor entry is too large".to_string());
    }
    EntryOutcome::Recovered(RecoveredEntry {
        name,
        extra,
        local_header_offset,
        version_needed,
        flags,
        method,
        mod_time,
        mod_date,
        crc32,
        compressed_size,
        uncompressed_size,
        data_start,
        data_end,
        payload_override: None,
        verified: false,
        descriptor: true,
        passthrough: true,
        boundary_source: BoundarySource::Descriptor,
        experimental_deflate_resync: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn classify_entry(
    data: &[u8],
    local_header_offset: usize,
    data_start: usize,
    data_end: usize,
    name: Vec<u8>,
    extra: Vec<u8>,
    version_needed: u16,
    flags: u16,
    method: u16,
    mod_time: u16,
    mod_date: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    descriptor: bool,
    boundary_source: BoundarySource,
    options: &DeepZipOptions,
    timing: &mut ScanTiming,
) -> EntryOutcome {
    let payload = &data[data_start..data_end];
    let verified = match method {
        0 if options.verify_candidates => {
            let verify_started = Instant::now();
            let ok =
            payload.len() as u64 == uncompressed_size
                && compressed_size == uncompressed_size
                && crc32_bytes(payload) == crc32;
            timing.verify_store_seconds += verify_started.elapsed().as_secs_f64();
            ok
        }
        0 => false,
        8 if options.verify_candidates => {
            let verify_started = Instant::now();
            match verify_deflate(
                payload,
                Some(crc32),
                Some(uncompressed_size),
                options.max_entry_uncompressed_bytes,
                true,
            ) {
                Ok(info) => {
                    timing.verify_deflate_seconds += verify_started.elapsed().as_secs_f64();
                    info.consumed == payload.len()
                }
                Err(_) => {
                    timing.verify_deflate_seconds += verify_started.elapsed().as_secs_f64();
                    false
                }
            }
        }
        8 => false,
        _ => false,
    };
    let is_encrypted_entry = flags & 0x01 != 0;
    if !verified
        && matches!(method, 0 | 8)
        && options.verify_candidates
        && !is_encrypted_entry
        && !options.allow_unverified_entries
    {
        return EntryOutcome::Skipped("entry failed payload verification".to_string());
    }
    if !verified && !known_zip_method(method) {
        return EntryOutcome::Recovered(RecoveredEntry {
            name: name.clone(),
            extra: extra.clone(),
            local_header_offset,
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            data_start,
            data_end,
            payload_override: None,
            verified: false,
            descriptor,
            passthrough: true,
            boundary_source,
            experimental_deflate_resync: false,
        });
    }
    if !verified && !options.verify_candidates {
        return EntryOutcome::Recovered(RecoveredEntry {
            name: name.clone(),
            extra: extra.clone(),
            local_header_offset,
            version_needed,
            flags,
            method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            data_start,
            data_end,
            payload_override: None,
            verified: false,
            descriptor,
            passthrough: true,
            boundary_source,
            experimental_deflate_resync: false,
        });
    }
    EntryOutcome::Recovered(RecoveredEntry {
        name,
        extra,
        local_header_offset,
        version_needed,
        flags,
        method,
        mod_time,
        mod_date,
        crc32,
        compressed_size,
        uncompressed_size,
        data_start,
        data_end,
        payload_override: None,
        verified,
        descriptor,
        passthrough: !verified,
        boundary_source,
        experimental_deflate_resync: false,
    })
}

fn candidate_plans(scan: &ScanResult, options: &DeepZipOptions) -> Vec<CandidatePlan> {
    let strict = scan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| (entry.verified && !entry.descriptor).then_some(index))
        .collect::<Vec<_>>();
    let descriptor = scan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| entry.verified.then_some(index))
        .collect::<Vec<_>>();
    let passthrough = scan
        .entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| (entry.verified || entry.passthrough).then_some(index))
        .collect::<Vec<_>>();
    let mut plans = Vec::new();
    if !strict.is_empty() {
        plans.push(make_plan(
            "zip_deep_strict_verified",
            strict,
            &scan.entries,
            0.78,
            vec![
                "deep_scan_local_headers",
                "verify_entry_payloads",
                "write_strict_verified_zip",
            ],
        ));
    }
    if descriptor.len() > plans.first().map(|plan| plan.indices.len()).unwrap_or(0) {
        plans.push(make_plan(
            "zip_deep_descriptor_recovered",
            descriptor,
            &scan.entries,
            0.84,
            vec![
                "deep_scan_local_headers",
                "recover_data_descriptors",
                "verify_entry_payloads",
                "write_descriptor_recovered_zip",
            ],
        ));
    }
    if passthrough.len()
        > plans
            .iter()
            .map(|plan| plan.indices.len())
            .max()
            .unwrap_or(0)
    {
        plans.push(make_plan(
            "zip_deep_passthrough_rebuilt",
            passthrough,
            &scan.entries,
            if options.verify_candidates {
                0.70
            } else {
                0.62
            },
            vec![
                "deep_scan_local_headers",
                "recover_data_descriptors",
                "preserve_trusted_compressed_payloads",
                "write_passthrough_rebuilt_zip",
            ],
        ));
    }
    plans.sort_by_key(|plan| std::cmp::Reverse(plan.rank_score));
    plans
}

fn make_plan(
    name: &'static str,
    mut indices: Vec<usize>,
    entries: &[RecoveredEntry],
    confidence: f64,
    actions: Vec<&'static str>,
) -> CandidatePlan {
    indices.sort_by_key(|index| entries[*index].data_start);
    let verified = indices
        .iter()
        .filter(|index| entries[**index].verified)
        .count() as i64;
    let descriptor = indices
        .iter()
        .filter(|index| entries[**index].descriptor)
        .count() as i64;
    let passthrough = indices
        .iter()
        .filter(|index| entries[**index].passthrough)
        .count() as i64;
    CandidatePlan {
        name,
        indices,
        confidence,
        actions,
        rank_score: verified * 100
            + descriptor * 15
            + passthrough * 45
            + (confidence * 10.0) as i64,
    }
}

fn policy_name(policy: &str) -> &'static str {
    match policy {
        "latest" => "latest",
        "first" => "first",
        "largest_verified" => "largest_verified",
        _ => "crc_match",
    }
}

fn select_conflict_free_zip_entries_by_policy(entries: &[RecoveredEntry], policy: &str) -> Vec<usize> {
    let mut order = (0..entries.len()).collect::<Vec<_>>();
    match policy {
        "latest" => order.sort_by_key(|index| std::cmp::Reverse(entries[*index].data_start)),
        "first" => order.sort_by_key(|index| entries[*index].data_start),
        "largest_verified" => order.sort_by(|left, right| {
            let l = &entries[*left];
            let r = &entries[*right];
            (r.verified, r.uncompressed_size, std::cmp::Reverse(r.data_start))
                .cmp(&(l.verified, l.uncompressed_size, std::cmp::Reverse(l.data_start)))
        }),
        _ => order.sort_by(|left, right| {
            zip_entry_score(&entries[*right])
                .cmp(&zip_entry_score(&entries[*left]))
                .then_with(|| entries[*left].data_start.cmp(&entries[*right].data_start))
        }),
    }
    let mut selected = Vec::new();
    let mut used_names = std::collections::HashSet::new();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for index in order {
        let entry = &entries[index];
        let Some(name_key) = conflict_safe_name_key(&entry.name) else {
            continue;
        };
        if !used_names.insert(name_key) {
            continue;
        }
        if ranges
            .iter()
            .any(|(start, end)| entry.data_start < *end && entry.data_end > *start)
        {
            continue;
        }
        ranges.push((entry.data_start, entry.data_end));
        selected.push(index);
    }
    selected.sort_by_key(|index| entries[*index].data_start);
    selected
}

fn conflict_safe_name_key(name: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(name).replace('\\', "/");
    if raw.is_empty()
        || raw.contains('\0')
        || raw.starts_with('/')
        || has_windows_drive_prefix(&raw)
    {
        return None;
    }
    let mut key_parts = Vec::new();
    for part in raw.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
        if part.ends_with(' ') || part.ends_with('.') {
            return None;
        }
        if is_windows_reserved_name(part) {
            return None;
        }
        let folded = fold_conflict_component(part);
        if folded.is_empty() {
            return None;
        }
        key_parts.push(folded);
    }
    if key_parts.is_empty() {
        None
    } else {
        Some(key_parts.join("/"))
    }
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

fn is_windows_reserved_name(part: &str) -> bool {
    let base = part
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && base.as_bytes()[3].is_ascii_digit()
            && base.as_bytes()[3] != b'0')
}

fn fold_conflict_component(part: &str) -> String {
    let mut out = String::new();
    for ch in part.chars() {
        if ('\u{0300}'..='\u{036f}').contains(&ch) {
            continue;
        }
        for lower in ch.to_lowercase() {
            match lower {
                'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => out.push('a'),
                'ç' | 'ć' | 'ĉ' | 'ċ' | 'č' => out.push('c'),
                'ď' | 'đ' => out.push('d'),
                'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => out.push('e'),
                'ì' | 'í' | 'î' | 'ï' | 'ĩ' | 'ī' | 'ĭ' | 'į' | 'ı' => out.push('i'),
                'ñ' | 'ń' | 'ņ' | 'ň' => out.push('n'),
                'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ŏ' | 'ő' => out.push('o'),
                'ŕ' | 'ŗ' | 'ř' => out.push('r'),
                'ś' | 'ŝ' | 'ş' | 'š' => out.push('s'),
                'ť' | 'ţ' | 'ŧ' => out.push('t'),
                'ù' | 'ú' | 'û' | 'ü' | 'ũ' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' => {
                    out.push('u')
                }
                'ý' | 'ÿ' | 'ŷ' => out.push('y'),
                'ź' | 'ż' | 'ž' => out.push('z'),
                _ => out.push(lower),
            }
        }
    }
    out
}

fn zip_entry_score(entry: &RecoveredEntry) -> i64 {
    let mut score = 0i64;
    if entry.verified {
        score += 1000;
    }
    if entry.method == 0 || entry.method == 8 {
        score += 100;
    } else if entry.passthrough {
        score += 20;
    }
    if entry.descriptor {
        score += 40;
    }
    score += (entry.uncompressed_size.min(16 * 1024 * 1024) / 4096) as i64;
    score
}

