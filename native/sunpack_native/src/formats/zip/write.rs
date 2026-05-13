fn write_candidate_zip(
    source: &[u8],
    entries: &[RecoveredEntry],
    plan: &CandidatePlan,
    output: &Path,
    max_output_bytes: Option<u64>,
) -> Result<WriteStats, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<WriteStats, String> {
        let mut file = File::create(&temp).map_err(|err| err.to_string())?;
        let mut central_directory = Vec::new();
        let mut verified_entries = 0usize;
        let mut descriptor_entries = 0usize;
        let mut passthrough_entries = 0usize;
        for index in &plan.indices {
            let entry = &entries[*index];
            if entry.compressed_size > u32::MAX as u64 || entry.uncompressed_size > u32::MAX as u64
            {
                return Err("entry exceeds ZIP32 size limits".to_string());
            }
            let local_offset = file.stream_position().map_err(|err| err.to_string())?;
            if local_offset > u32::MAX as u64 {
                return Err("candidate exceeds ZIP32 offset limits".to_string());
            }
            let payload = entry
                .payload_override
                .as_deref()
                .unwrap_or(&source[entry.data_start..entry.data_end]);
            write_local_header(&mut file, entry).map_err(|err| err.to_string())?;
            file.write_all(payload).map_err(|err| err.to_string())?;
            append_central_directory(&mut central_directory, entry, local_offset as u32);
            if entry.verified {
                verified_entries += 1;
            }
            if entry.descriptor {
                descriptor_entries += 1;
            }
            if entry.passthrough {
                passthrough_entries += 1;
            }
            enforce_output_limit(&file, max_output_bytes)?;
        }
        let cd_offset = file.stream_position().map_err(|err| err.to_string())?;
        file.write_all(&central_directory)
            .map_err(|err| err.to_string())?;
        write_eocd(
            &mut file,
            plan.indices.len(),
            central_directory.len(),
            cd_offset,
        )
        .map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        enforce_output_limit(&file, max_output_bytes)?;
        let size = file.stream_position().map_err(|err| err.to_string())?;
        Ok(WriteStats {
            entries: plan.indices.len(),
            verified_entries,
            descriptor_entries,
            passthrough_entries,
            size,
        })
    })();
    match result {
        Ok(stats) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(stats)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn write_local_header(file: &mut File, entry: &RecoveredEntry) -> std::io::Result<()> {
    let flags = entry.flags & !0x08;
    file.write_all(&0x0403_4B50u32.to_le_bytes())?;
    file.write_all(&entry.version_needed.to_le_bytes())?;
    file.write_all(&flags.to_le_bytes())?;
    file.write_all(&entry.method.to_le_bytes())?;
    file.write_all(&entry.mod_time.to_le_bytes())?;
    file.write_all(&entry.mod_date.to_le_bytes())?;
    file.write_all(&entry.crc32.to_le_bytes())?;
    file.write_all(&(entry.compressed_size as u32).to_le_bytes())?;
    file.write_all(&(entry.uncompressed_size as u32).to_le_bytes())?;
    file.write_all(&(entry.name.len() as u16).to_le_bytes())?;
    file.write_all(&(entry.extra.len() as u16).to_le_bytes())?;
    file.write_all(&entry.name)?;
    file.write_all(&entry.extra)?;
    Ok(())
}

fn append_central_directory(output: &mut Vec<u8>, entry: &RecoveredEntry, local_offset: u32) {
    let flags = entry.flags & !0x08;
    output.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
    output.extend_from_slice(&20u16.to_le_bytes());
    output.extend_from_slice(&entry.version_needed.to_le_bytes());
    output.extend_from_slice(&flags.to_le_bytes());
    output.extend_from_slice(&entry.method.to_le_bytes());
    output.extend_from_slice(&entry.mod_time.to_le_bytes());
    output.extend_from_slice(&entry.mod_date.to_le_bytes());
    output.extend_from_slice(&entry.crc32.to_le_bytes());
    output.extend_from_slice(&(entry.compressed_size as u32).to_le_bytes());
    output.extend_from_slice(&(entry.uncompressed_size as u32).to_le_bytes());
    output.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
    output.extend_from_slice(&(entry.extra.len() as u16).to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u16.to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&local_offset.to_le_bytes());
    output.extend_from_slice(&entry.name);
    output.extend_from_slice(&entry.extra);
}

fn write_eocd(
    file: &mut File,
    entries: usize,
    cd_size: usize,
    cd_offset: u64,
) -> std::io::Result<()> {
    file.write_all(&0x0605_4B50u32.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    file.write_all(&(entries as u16).to_le_bytes())?;
    file.write_all(&(entries as u16).to_le_bytes())?;
    file.write_all(&(cd_size as u32).to_le_bytes())?;
    file.write_all(&(cd_offset as u32).to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    Ok(())
}

fn verify_deflate(
    input: &[u8],
    expected_crc32: Option<u32>,
    expected_size: Option<u64>,
    max_output_bytes: Option<u64>,
    require_exact_input: bool,
) -> Result<DeflateInfo, String> {
    let mut decompressor = Decompress::new(false);
    let mut output = Vec::with_capacity(64 * 1024);
    let mut crc = Crc32::new();
    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let before_len = output.len();
        let input_offset = before_in as usize;
        if input_offset > input.len() {
            return Err("deflate input offset exceeded payload".to_string());
        }
        let status = decompressor
            .decompress_vec(&input[input_offset..], &mut output, FlushDecompress::None)
            .map_err(|err| format!("deflate decode failed: {err}"))?;
        if output.len() > before_len {
            crc.update(&output[before_len..]);
        }
        if let Some(limit) = max_output_bytes {
            if decompressor.total_out() > limit {
                return Err("deflate output exceeds deep repair entry budget".to_string());
            }
        }
        if status == Status::StreamEnd {
            let consumed = decompressor.total_in() as usize;
            if require_exact_input && consumed != input.len() {
                return Err("deflate stream ended before compressed payload boundary".to_string());
            }
            let computed_crc = crc.finish();
            if expected_crc32.is_some_and(|value| value != computed_crc) {
                return Err("deflate CRC mismatch".to_string());
            }
            if expected_size.is_some_and(|value| value != decompressor.total_out()) {
                return Err("deflate uncompressed size mismatch".to_string());
            }
            return Ok(DeflateInfo {
                consumed,
                uncompressed_size: decompressor.total_out(),
                crc32: computed_crc,
            });
        }
        if decompressor.total_in() as usize >= input.len() {
            return Err("deflate stream did not reach end marker".to_string());
        }
        if before_in == decompressor.total_in() && before_out == decompressor.total_out() {
            return Err("deflate decoder made no progress".to_string());
        }
        if output.len() > COPY_CHUNK_SIZE {
            output.clear();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn deflate_resync_partial_entry(
    data: &[u8],
    local_header_offset: usize,
    data_start: usize,
    name: Vec<u8>,
    _extra: Vec<u8>,
    version_needed: u16,
    flags: u16,
    mod_time: u16,
    mod_date: u16,
    options: &DeepZipOptions,
) -> Option<RecoveredEntry> {
    let decoded = decode_deflate_prefix_for_partial(
        data.get(data_start..)?,
        options.max_entry_uncompressed_bytes,
        options.max_duration,
    )?;
    if decoded.len() < 4096 {
        return None;
    }
    let mut output_name = b"__sunpack_partial/".to_vec();
    output_name.extend_from_slice(&safe_partial_name(&name));
    output_name.extend_from_slice(b".partial");
    if output_name.len() > MAX_NAME_LEN {
        output_name.truncate(MAX_NAME_LEN);
    }
    let crc32 = crc32_bytes(&decoded);
    Some(RecoveredEntry {
        name: output_name,
        extra: Vec::new(),
        local_header_offset,
        version_needed: version_needed.max(20),
        flags: flags & !0x08,
        method: 0,
        mod_time,
        mod_date,
        crc32,
        compressed_size: decoded.len() as u64,
        uncompressed_size: decoded.len() as u64,
        data_start,
        data_end: data_start,
        payload_override: Some(decoded),
        verified: true,
        descriptor: false,
        passthrough: false,
        boundary_source: BoundarySource::DeflateResync,
        experimental_deflate_resync: true,
    })
}

fn decode_deflate_prefix_for_partial(
    input: &[u8],
    max_output_bytes: Option<u64>,
    max_duration: Option<Duration>,
) -> Option<Vec<u8>> {
    let started = Instant::now();
    let mut decompressor = Decompress::new(false);
    let mut output = Vec::with_capacity(64 * 1024);
    loop {
        if max_duration.is_some_and(|duration| started.elapsed() >= duration) {
            break;
        }
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let before_len = output.len();
        let input_offset = before_in as usize;
        if input_offset >= input.len() {
            break;
        }
        match decompressor.decompress_vec(&input[input_offset..], &mut output, FlushDecompress::None) {
            Ok(Status::StreamEnd) => break,
            Ok(_) => {
                if output.len() > before_len {
                    if let Some(limit) = max_output_bytes {
                        if output.len() as u64 > limit {
                            output.truncate(limit as usize);
                            break;
                        }
                    }
                }
                if decompressor.total_in() == before_in && decompressor.total_out() == before_out {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (!output.is_empty()).then_some(output)
}

fn safe_partial_name(name: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(name.len());
    for byte in name {
        match *byte {
            b'/' | b'\\' => output.push(b'_'),
            0 | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|' => output.push(b'_'),
            value if value < 0x20 => output.push(b'_'),
            value => output.push(value),
        }
    }
    if output.is_empty() {
        b"entry".to_vec()
    } else {
        output
    }
}

fn descriptor_at(
    data: &[u8],
    offset: usize,
    expected_crc32: u32,
    expected_compressed: u64,
    expected_uncompressed: u64,
) -> bool {
    descriptor_at_impl(
        data,
        offset,
        expected_crc32,
        expected_compressed,
        expected_uncompressed,
    )
    .is_some()
}

fn descriptor_at_impl(
    data: &[u8],
    offset: usize,
    expected_crc32: u32,
    expected_compressed: u64,
    expected_uncompressed: u64,
) -> Option<usize> {
    for (len, has_sig, zip64) in [
        (16usize, true, false),
        (24, true, true),
        (12, false, false),
        (20, false, true),
    ] {
        if offset + len > data.len() {
            continue;
        }
        let base = if has_sig {
            if &data[offset..offset + 4] != DD_SIG {
                continue;
            }
            offset + 4
        } else {
            offset
        };
        let crc32 = u32_le(data, base);
        let (compressed, uncompressed) = if zip64 {
            (u64_le(data, base + 4), u64_le(data, base + 12))
        } else {
            (u32_le(data, base + 4) as u64, u32_le(data, base + 8) as u64)
        };
        if crc32 == expected_crc32
            && compressed == expected_compressed
            && uncompressed == expected_uncompressed
        {
            return Some(offset + len);
        }
    }
    None
}

fn descriptor_before_next_record(data: &[u8], data_start: usize) -> Option<(usize, u32, u64, u64)> {
    let next = find_next_zip_record(data, data_start)?;
    for (len, has_sig, zip64) in [
        (24usize, true, true),
        (20, false, true),
        (16, true, false),
        (12, false, false),
    ] {
        let descriptor_start = next.checked_sub(len)?;
        if descriptor_start < data_start {
            continue;
        }
        let base = if has_sig {
            if &data[descriptor_start..descriptor_start + 4] != DD_SIG {
                continue;
            }
            descriptor_start + 4
        } else {
            descriptor_start
        };
        let crc32 = u32_le(data, base);
        let (compressed, uncompressed) = if zip64 {
            (u64_le(data, base + 4), u64_le(data, base + 12))
        } else {
            (u32_le(data, base + 4) as u64, u32_le(data, base + 8) as u64)
        };
        if compressed == (descriptor_start - data_start) as u64 {
            return Some((descriptor_start, crc32, compressed, uncompressed));
        }
    }
    None
}

fn verified_deflate_payload_end(
    data: &[u8],
    data_start: usize,
    header_end: Option<usize>,
    expected_crc32: u32,
    expected_size: u64,
    options: &DeepZipOptions,
) -> Option<(usize, BoundarySource)> {
    let mut ends = Vec::new();
    if let Some(end) = header_end.filter(|end| *end <= data.len() && *end > data_start) {
        ends.push((end, BoundarySource::HeaderSize));
    }
    if let Some(next) = find_next_zip_record(data, data_start) {
        if next > data_start && !ends.iter().any(|(end, _)| *end == next) {
            ends.push((next, BoundarySource::NextRecord));
        }
    }
    if data_start < data.len() && ends.is_empty() {
        ends.push((data.len(), BoundarySource::NextRecord));
    }
    for (end, source) in ends {
        let candidate = &data[data_start..end];
        if let Ok(info) = verify_deflate(
            candidate,
            Some(expected_crc32),
            Some(expected_size),
            options.max_entry_uncompressed_bytes,
            false,
        ) {
            if info.consumed > 0 && data_start + info.consumed <= end {
                let actual_end = data_start + info.consumed;
                let actual_source = if actual_end == end {
                    source
                } else {
                    BoundarySource::DeflateConsumed
                };
                return Some((actual_end, actual_source));
            }
        }
    }
    None
}

fn verified_store_payload_end(
    data: &[u8],
    data_start: usize,
    expected_crc32: u32,
    expected_size: u64,
) -> Option<(usize, BoundarySource)> {
    let expected_len = usize::try_from(expected_size).ok()?;
    if let Some(end) = data_start.checked_add(expected_len) {
        if end <= data.len() {
            let payload = &data[data_start..end];
            if crc32_bytes(payload) == expected_crc32 {
                return Some((end, BoundarySource::HeaderSize));
            }
        }
    }
    let next = find_next_zip_record(data, data_start)?;
    if next <= data_start {
        return None;
    }
    let payload = &data[data_start..next];
    if payload.len() as u64 == expected_size && crc32_bytes(payload) == expected_crc32 {
        Some((next, BoundarySource::NextRecord))
    } else {
        None
    }
}

fn find_next_zip_record(data: &[u8], start: usize) -> Option<usize> {
    [LFH_SIG, CD_SIG, EOCD_SIG, ZIP64_EOCD_SIG, ZIP64_LOCATOR_SIG]
        .iter()
        .filter_map(|sig| memmem::find(&data[start..], sig).map(|index| start + index))
        .min()
}

fn zip64_sizes(extra: &[u8], compressed: u32, uncompressed: u32) -> Option<(u64, u64)> {
    let need_uncompressed = uncompressed == u32::MAX;
    let need_compressed = compressed == u32::MAX;
    if !need_uncompressed && !need_compressed {
        return Some((compressed as u64, uncompressed as u64));
    }
    let mut cursor = 0usize;
    while cursor + 4 <= extra.len() {
        let header_id = u16_le(extra, cursor);
        let size = u16_le(extra, cursor + 2) as usize;
        cursor += 4;
        if cursor + size > extra.len() {
            return None;
        }
        if header_id == 0x0001 {
            let mut field = cursor;
            let zip64_uncompressed = if need_uncompressed {
                if field + 8 > cursor + size {
                    return None;
                }
                let value = u64_le(extra, field);
                field += 8;
                value
            } else {
                uncompressed as u64
            };
            let zip64_compressed = if need_compressed {
                if field + 8 > cursor + size {
                    return None;
                }
                u64_le(extra, field)
            } else {
                compressed as u64
            };
            return Some((zip64_compressed, zip64_uncompressed));
        }
        cursor += size;
    }
    None
}

