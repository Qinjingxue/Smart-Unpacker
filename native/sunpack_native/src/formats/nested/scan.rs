fn nested_archive_candidates(
    data: &[u8],
    workspace: &str,
    max_candidates: usize,
) -> Vec<WrittenArchiveCandidate> {
    let mut ranges = Vec::new();
    collect_nested_archive_ranges(data, &mut ranges, max_candidates);
    ranges.sort_by_key(|item| item.0);
    let mut output = Vec::new();
    for (offset, end, format, confidence) in ranges.into_iter().take(max_candidates) {
        if offset == 0 && end == data.len() {
            continue;
        }
        let ext = match format {
            "zip" => ".zip",
            "7z" => ".7z",
            "rar" => ".rar",
            "tar" => ".tar",
            "gzip" => ".gz",
            _ => ".bin",
        };
        let output_path =
            Path::new(workspace).join(format!("archive_nested_payload_{offset:08x}{ext}"));
        let output_bytes = match write_slice_candidate(&data[offset..end], &output_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        output.push(WrittenArchiveCandidate {
            name: format!("nested_payload_{offset:08x}"),
            path: output_path.to_string_lossy().to_string(),
            format: format.to_string(),
            status: "partial".to_string(),
            offset: offset as u64,
            end_offset: end as u64,
            output_bytes,
            confidence,
            actions: vec!["scan_nested_archive_signatures".to_string(), "extract_nested_archive_payload".to_string()],
            warnings: vec!["candidate was carved from inside a damaged outer container".to_string()],
        });
    }
    output
}

fn collect_nested_archive_ranges<'a>(
    data: &'a [u8],
    output: &mut Vec<(usize, usize, &'a str, f64)>,
    max_candidates: usize,
) {
    for offset in find_all(data, b"PK\x03\x04") {
        if output.len() >= max_candidates {
            return;
        }
        if let Some(end) = nested_zip_end(data, offset) {
            output.push((offset, end, "zip", 0.86));
        }
    }
    for candidate in crate::formats::seven_zip::carrier_scan_candidates(data, false, max_candidates.saturating_sub(output.len())) {
        if output.len() >= max_candidates {
            return;
        }
        output.push((candidate.offset, candidate.archive_end, "7z", 0.84));
    }
    for offset in find_all(data, RAR4_MAGIC) {
        if output.len() >= max_candidates {
            return;
        }
        if let Some(walk) = walk_rar4_blocks(data, offset) {
            output.push((
                offset,
                walk.last_complete_end,
                "rar",
                if walk.end_block_found { 0.86 } else { 0.72 },
            ));
        }
    }
    for offset in find_all(data, RAR5_MAGIC) {
        if output.len() >= max_candidates {
            return;
        }
        if let Some(walk) = walk_rar5_blocks(data, offset) {
            output.push((
                offset,
                walk.last_complete_end,
                "rar",
                if walk.end_block_found { 0.86 } else { 0.72 },
            ));
        }
    }
    for offset in find_all(data, b"\x1f\x8b\x08") {
        if output.len() >= max_candidates {
            return;
        }
        if let Some(end) = nested_gzip_end(data, offset) {
            output.push((offset, end, "gzip", 0.78));
        }
    }
    for offset in (0..data.len().saturating_sub(512)).step_by(512) {
        if output.len() >= max_candidates {
            return;
        }
        if offset == 0 {
            continue;
        }
        if plausible_tar_header(&data[offset..offset + 512]) {
            if let Some(end) = nested_tar_end(data, offset) {
                output.push((offset, end, "tar", 0.74));
            }
        }
    }
}

fn nested_zip_end(data: &[u8], offset: usize) -> Option<usize> {
    let mut pos =
        memchr::memmem::find(&data[offset..], b"PK\x05\x06").map(|value| offset + value)?;
    loop {
        if pos + 22 <= data.len() {
            let comment_len = u16_le(data, pos + 20) as usize;
            let end = pos + 22 + comment_len;
            if end <= data.len() {
                return Some(end);
            }
        }
        let next = memchr::memmem::find(&data[pos + 4..], b"PK\x05\x06")?;
        pos = pos + 4 + next;
    }
}

fn nested_gzip_end(data: &[u8], offset: usize) -> Option<usize> {
    for end in offset + 18..=data.len().min(offset + 128 * 1024 * 1024) {
        let mut decoder = GzDecoder::new(Cursor::new(data[offset..end].to_vec()));
        let mut sink = Vec::new();
        if decoder.read_to_end(&mut sink).is_ok() {
            return Some(end);
        }
    }
    None
}

fn nested_tar_end(data: &[u8], offset: usize) -> Option<usize> {
    let mut pos = offset;
    while pos + 512 <= data.len() {
        let header = &data[pos..pos + 512];
        if header.iter().all(|byte| *byte == 0) {
            let end = (pos + 1024).min(data.len());
            return Some(end);
        }
        let size = parse_tar_number(&header[124..136])? as usize;
        let padded = size.checked_add(511)? / 512 * 512;
        pos = pos.checked_add(512)?.checked_add(padded)?;
    }
    None
}

fn plausible_tar_header(header: &[u8]) -> bool {
    if header.len() != 512 {
        return false;
    }
    let name_end = header[0..100]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(100);
    if name_end == 0
        || !header[..name_end]
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte))
    {
        return false;
    }
    parse_tar_number(&header[124..136]).is_some()
}

fn parse_tar_number(field: &[u8]) -> Option<u64> {
    let mut value = 0u64;
    let mut seen = false;
    for byte in field {
        match *byte {
            b'0'..=b'7' => {
                seen = true;
                value = value.checked_mul(8)?.checked_add((byte - b'0') as u64)?;
            }
            b'\0' | b' ' => {}
            _ => return None,
        }
    }
    Some(if seen { value } else { 0 })
}

