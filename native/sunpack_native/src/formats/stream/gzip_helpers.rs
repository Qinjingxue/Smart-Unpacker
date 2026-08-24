enum StreamPrefixSearch {
    Found(usize),
    NotFound,
    TimedOut,
}

fn find_complete_stream_prefix(
    data: &[u8],
    format: StreamFormat,
    max_probe_junk_bytes: usize,
    started: Instant,
    max_duration: Option<Duration>,
    max_probe_attempts: usize,
    max_decode_bytes: usize,
) -> StreamPrefixSearch {
    if data.is_empty() {
        return StreamPrefixSearch::NotFound;
    }
    if data.len() > max_decode_bytes {
        return StreamPrefixSearch::TimedOut;
    }
    if decode_stream_exact(data, format).is_ok() {
        return StreamPrefixSearch::Found(data.len());
    }
    if timed_out_at(started, max_duration) {
        return StreamPrefixSearch::TimedOut;
    }
    let probe_window = max_probe_junk_bytes.max(1).min(4096);
    let min_end = data.len().saturating_sub(probe_window);
    let attempts = max_probe_attempts.max(1).min(probe_window);
    let sequential_attempts = attempts.min(16);
    let mut checked = 0usize;
    let mut previous_end = data.len();
    for attempt in 0..attempts {
        if timed_out_at(started, max_duration) {
            return StreamPrefixSearch::TimedOut;
        }
        let offset = if attempt < sequential_attempts {
            attempt + 1
        } else {
            1 + (attempt * probe_window / attempts)
        };
        let end = data.len().saturating_sub(offset).max(min_end);
        if end == previous_end {
            continue;
        }
        previous_end = end;
        checked += 1;
        if decode_stream_exact(&data[..end], format).is_ok() {
            return StreamPrefixSearch::Found(end);
        }
    }
    if checked == 0 {
        let end = data.len().saturating_sub(1).max(min_end);
        if decode_stream_exact(&data[..end], format).is_ok() {
            return StreamPrefixSearch::Found(end);
        }
    }
    StreamPrefixSearch::NotFound
}

fn decode_stream_exact(data: &[u8], format: StreamFormat) -> Result<u64, String> {
    let cursor = Cursor::new(data.to_vec());
    match format {
        StreamFormat::Gzip => {
            let header_end = gzip_header_end(data).ok_or_else(|| "invalid gzip header".to_string())?;
            let (decoded, consumed) = find_gzip_deflate_payload(data, header_end)?;
            if header_end + consumed + 8 != data.len() {
                return Err("trailing bytes after gzip stream".to_string());
            }
            Ok(decoded.len() as u64)
        }
        StreamFormat::Bzip2 => {
            let mut decoder = BzDecoder::new(cursor);
            let decoded = drain_decoder(&mut decoder)?;
            if decoder.get_ref().position() != data.len() as u64 {
                return Err("trailing bytes after bzip2 stream".to_string());
            }
            Ok(decoded)
        }
        StreamFormat::Xz => {
            let mut decoder = XzDecoder::new(cursor);
            let decoded = drain_decoder(&mut decoder)?;
            if decoder.get_ref().position() != data.len() as u64 {
                return Err("trailing bytes after xz stream".to_string());
            }
            Ok(decoded)
        }
        StreamFormat::Zstd => {
            let mut decoder = ZstdDecoder::new(cursor).map_err(|err| err.to_string())?;
            let decoded = drain_decoder(&mut decoder)?;
            if decoder.get_ref().get_ref().position() != data.len() as u64 {
                return Err("trailing bytes after zstd stream".to_string());
            }
            Ok(decoded)
        }
    }
}

fn drain_decoder<D>(decoder: &mut D) -> Result<u64, String>
where
    D: Read,
{
    let mut buffer = vec![0u8; DECODE_CHUNK_SIZE];
    let mut decoded = 0u64;
    loop {
        match decoder.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => decoded += read as u64,
            Err(err) => return Err(err.to_string()),
        }
    }
    Ok(decoded)
}

fn write_prefix_atomic(data: &[u8], end: usize, output: &Path) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<(), String> {
        let mut file = crate::io::resource_lifecycle::TrackedFile::create(
            &temp,
            "gzip_repair_output",
        )
        .map_err(|err| err.to_string())?;
        file.write_all(&data[..end])
            .map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(end as u64)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn write_prefix_and_suffix_atomic(
    data: &[u8],
    end: usize,
    suffix: &[u8],
    output: &Path,
) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<u64, String> {
        let mut file = crate::io::resource_lifecycle::TrackedFile::create(
            &temp,
            "gzip_repair_output",
        )
        .map_err(|err| err.to_string())?;
        file.write_all(&data[..end])
            .map_err(|err| err.to_string())?;
        file.write_all(suffix).map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        Ok((end + suffix.len()) as u64)
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

struct GzipFooterRepair {
    stream_end: usize,
    footer: [u8; 8],
    decoded_bytes: u64,
}

struct StreamSalvage {
    payload: Vec<u8>,
    recovered_offsets: Vec<u64>,
    skipped_offsets: Vec<u64>,
}

struct TarBytePatch {
    offset: u64,
    data: Vec<u8>,
}

struct TarRepair {
    patches: Vec<TarBytePatch>,
    truncate_at: Option<u64>,
    append_data: Option<Vec<u8>>,
    confidence: f64,
    actions: Vec<&'static str>,
    message: String,
}

fn repair_gzip_footer(
    data: &[u8],
    started: Instant,
    max_duration: Option<Duration>,
    max_decode_bytes: usize,
) -> Result<GzipFooterRepair, String> {
    if data.len() > max_decode_bytes {
        return Err("gzip footer fix skipped because input exceeds decode budget".to_string());
    }
    if timed_out_at(started, max_duration) {
        return Err("gzip footer fix exceeded time budget".to_string());
    }
    let header_end = gzip_header_end(data).ok_or_else(|| "invalid gzip header".to_string())?;
    if data.len() < header_end + 8 {
        return Err("invalid gzip header".to_string());
    }
    let (payload, consumed) = find_gzip_deflate_payload(data, header_end)?;
    if timed_out_at(started, max_duration) {
        return Err("gzip footer fix exceeded time budget".to_string());
    }
    let stream_end = header_end + consumed;
    let mut footer = [0u8; 8];
    footer[0..4].copy_from_slice(&crc32(&payload).to_le_bytes());
    footer[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    if stream_end + 8 == data.len() && data[stream_end..].starts_with(&footer) {
        return Err("gzip footer already matches decoded payload".to_string());
    }
    Ok(GzipFooterRepair {
        stream_end,
        footer,
        decoded_bytes: payload.len() as u64,
    })
}

fn gzip_header_end(data: &[u8]) -> Option<usize> {
    if data.len() < 10 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return None;
    }
    let flags = data[3];
    if flags & 0xe0 != 0 {
        return None;
    }
    let mut offset = 10usize;
    if flags & 0x04 != 0 {
        if offset + 2 > data.len() {
            return None;
        }
        let extra_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        offset = offset.checked_add(2)?.checked_add(extra_len)?;
    }
    if flags & 0x08 != 0 {
        offset = skip_c_string(data, offset)?;
    }
    if flags & 0x10 != 0 {
        offset = skip_c_string(data, offset)?;
    }
    if flags & 0x02 != 0 {
        let crc_end = offset.checked_add(2)?;
        if crc_end > data.len() {
            return None;
        }
        let expected = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let actual = (crc32_hash(&data[..offset]) & 0xffff) as u16;
        if expected != actual {
            return None;
        }
        offset = crc_end;
    }
    (offset <= data.len()).then_some(offset)
}

fn skip_c_string(data: &[u8], offset: usize) -> Option<usize> {
    data.get(offset..)?
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| offset + index + 1)
}

fn decode_raw_deflate_prefix(
    data: &[u8],
    accept_exact_eof: bool,
) -> Result<(Vec<u8>, usize), String> {
    let mut decompressor = Decompress::new(false);
    let mut output = Vec::new();
    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let consumed = usize::try_from(before_in)
            .map_err(|_| "deflate input offset overflowed".to_string())?;
        let flush = if consumed >= data.len() {
            FlushDecompress::Finish
        } else {
            FlushDecompress::None
        };
        let status = decompressor
            .decompress_vec(&data[consumed..], &mut output, flush)
            .map_err(|err| err.to_string())?;
        if status == Status::StreamEnd {
            return Ok((output, decompressor.total_in() as usize));
        }
        if decompressor.total_in() == before_in && decompressor.total_out() == before_out {
            if accept_exact_eof
                && decompressor.total_in() as usize >= data.len()
                && !output.is_empty()
            {
                return Ok((output, data.len()));
            }
            return Err("deflate stream could not be decoded".to_string());
        }
        if decompressor.total_in() as usize >= data.len() {
            if accept_exact_eof && !output.is_empty() {
                return Ok((output, data.len()));
            }
            return Err("deflate stream ended before a complete payload".to_string());
        }
    }
}

fn find_gzip_deflate_payload(data: &[u8], header_end: usize) -> Result<(Vec<u8>, usize), String> {
    if data.len() < header_end + 8 {
        return Err("invalid gzip header".to_string());
    }
    if let Ok((decoded, consumed)) = decode_raw_deflate_prefix(&data[header_end..], false) {
        if gzip_candidate_valid(data, header_end + consumed, &decoded) {
            return Ok((decoded, consumed));
        }
    }
    if let Ok(decoded) = decode_raw_deflate_exact(&data[header_end..data.len() - 8]) {
        let consumed = data.len() - header_end - 8;
        if gzip_candidate_valid(data, header_end + consumed, &decoded) {
            return Ok((decoded, consumed));
        }
    }
    let scan_limit = data.len().saturating_sub(8);
    for end in (header_end + 1..=scan_limit).rev() {
        if let Ok(decoded) = decode_raw_deflate_exact(&data[header_end..end]) {
            if gzip_candidate_valid(data, end, &decoded) {
                return Ok((decoded, end - header_end));
            }
        }
    }
    Err("deflate stream could not be decoded".to_string())
}

fn gzip_candidate_valid(data: &[u8], stream_end: usize, payload: &[u8]) -> bool {
    if stream_end > data.len() {
        return false;
    }
    let mut footer = [0u8; 8];
    footer[0..4].copy_from_slice(&crc32(payload).to_le_bytes());
    footer[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let mut candidate = Vec::with_capacity(stream_end + 8);
    candidate.extend_from_slice(&data[..stream_end]);
    candidate.extend_from_slice(&footer);
    let mut decoder = GzDecoder::new(Cursor::new(candidate));
    let mut decoded = Vec::new();
    if decoder.read_to_end(&mut decoded).is_err() {
        return false;
    }
    decoded == payload
}

fn decode_raw_deflate_exact(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = DeflateDecoder::new(Cursor::new(data.to_vec()));
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|err| err.to_string())?;
    if output.is_empty() {
        return Err("deflate stream decoded no bytes".to_string());
    }
    Ok(output)
}

fn salvage_gzip_members(data: &[u8]) -> Result<StreamSalvage, String> {
    let offsets = find_magic_offsets(data, b"\x1f\x8b\x08");
    if offsets.len() < 2 {
        return Err("gzip deflate resync requires multiple member headers".to_string());
    }
    let mut payload = Vec::new();
    let mut recovered_offsets = Vec::new();
    let mut skipped_offsets = Vec::new();
    for (index, start) in offsets.iter().copied().enumerate() {
        let end = offsets.get(index + 1).copied().unwrap_or(data.len());
        let mut decoder = GzDecoder::new(Cursor::new(data[start..end].to_vec()));
        let before = payload.len();
        match decoder.read_to_end(&mut payload) {
            Ok(_) => recovered_offsets.push(start as u64),
            Err(_) => {
                payload.truncate(before);
                skipped_offsets.push(start as u64);
            }
        }
    }
    if payload.is_empty() || skipped_offsets.is_empty() {
        return Err(
            "no damaged gzip member could be skipped while preserving a later member".to_string(),
        );
    }
    Ok(StreamSalvage {
        payload,
        recovered_offsets,
        skipped_offsets,
    })
}

fn salvage_zstd_frames(data: &[u8]) -> Result<StreamSalvage, String> {
    let offsets = find_magic_offsets(data, b"\x28\xb5\x2f\xfd");
    if offsets.len() < 2 {
        return Err("zstd frame salvage requires multiple frame candidates".to_string());
    }
    let mut payload = Vec::new();
    let mut recovered_offsets = Vec::new();
    let mut skipped_offsets = Vec::new();
    for (index, start) in offsets.iter().copied().enumerate() {
        let end = offsets.get(index + 1).copied().unwrap_or(data.len());
        match zstd::stream::decode_all(Cursor::new(data[start..end].to_vec())) {
            Ok(decoded) => {
                payload.extend_from_slice(&decoded);
                recovered_offsets.push(start as u64);
            }
            Err(_) => skipped_offsets.push(start as u64),
        }
    }
    if payload.is_empty() || skipped_offsets.is_empty() {
        return Err(
            "no damaged zstd frame could be skipped while preserving a good frame".to_string(),
        );
    }
    Ok(StreamSalvage {
        payload,
        recovered_offsets,
        skipped_offsets,
    })
}

