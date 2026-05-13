fn get_required_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(format!("missing {key}")))?
        .extract::<String>()
}

fn get_optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<String>()?)),
        _ => Ok(None),
    }
}

fn get_optional_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) if !value.is_none() => Ok(Some(value.extract::<u64>()?)),
        _ => Ok(None),
    }
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("candidate");
    path.with_file_name(format!(".{name}.tmp"))
}

fn timed_out_at(started: Instant, max_duration: Option<Duration>) -> bool {
    max_duration.is_some_and(|duration| started.elapsed() >= duration)
}

fn duration_from_seconds(value: f64) -> Option<Duration> {
    (value > 0.0).then(|| Duration::from_secs_f64(value))
}

fn mb_to_bytes(value: f64) -> Option<u64> {
    if value <= 0.0 {
        None
    } else {
        Some((value * 1024.0 * 1024.0) as u64)
    }
}

fn confidence_for_size(decoded_bytes: u64) -> f64 {
    if decoded_bytes >= 1024 * 1024 {
        0.78
    } else if decoded_bytes >= 64 * 1024 {
        0.72
    } else {
        0.62
    }
}

fn is_trusted_prefix_salvage(stats: &RecoveryStats) -> bool {
    if stats
        .warnings
        .iter()
        .any(|warning| warning.contains("time budget reached"))
    {
        return true;
    }
    let Some(error) = stats.error.as_deref() else {
        return false;
    };
    let lower = error.to_ascii_lowercase();
    lower.contains("eof")
        || lower.contains("end of file")
        || lower.contains("unexpected end")
        || lower.contains("truncated")
        || lower.contains("decompression not finished")
}

fn sanitize_strategy_name(value: &str) -> String {
    let text = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let trimmed = text.trim_matches('_');
    if trimmed.is_empty() {
        "block_salvage".to_string()
    } else {
        trimmed.to_string()
    }
}

fn tar_confidence(members: u64, decoded_bytes: u64) -> f64 {
    if members >= 8 || decoded_bytes >= 4 * 1024 * 1024 {
        0.82
    } else if members >= 2 || decoded_bytes >= 512 * 1024 {
        0.76
    } else {
        0.68
    }
}

fn is_zero_block(block: &[u8]) -> bool {
    block.iter().all(|byte| *byte == 0)
}

fn plausible_tar_header(header: &[u8]) -> bool {
    if header.len() != 512 {
        return false;
    }
    if !plausible_tar_name(&header[0..100]) {
        return false;
    }
    if parse_tar_number(&header[100..108]).is_none()
        || parse_tar_number(&header[108..116]).is_none()
        || parse_tar_number(&header[116..124]).is_none()
        || parse_tar_number(&header[124..136]).is_none()
    {
        return false;
    }
    let typeflag = header[156];
    if typeflag != 0 && !(0x20..=0x7e).contains(&typeflag) {
        return false;
    }
    let magic = &header[257..263];
    if magic.iter().any(|byte| *byte != 0)
        && !magic.starts_with(b"ustar\0")
        && !magic.starts_with(b"ustar ")
    {
        return false;
    }
    true
}

fn plausible_tar_name(field: &[u8]) -> bool {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if end == 0 {
        return false;
    }
    field[..end]
        .iter()
        .all(|byte| *byte >= 0x20 && *byte != 0x7f)
}

fn parse_tar_number(field: &[u8]) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    if field[0] & 0x80 != 0 {
        let mut value = (field[0] & 0x7f) as u64;
        for byte in &field[1..] {
            value = value.checked_mul(256)?.checked_add(*byte as u64)?;
        }
        return Some(value);
    }

    let mut value = 0u64;
    let mut seen_digit = false;
    for byte in field {
        match *byte {
            b'0'..=b'7' => {
                seen_digit = true;
                value = value.checked_mul(8)?.checked_add((*byte - b'0') as u64)?;
            }
            b'\0' | b' ' => {}
            _ => return None,
        }
    }
    if seen_digit {
        Some(value)
    } else {
        Some(0)
    }
}

fn padded_tar_payload_span(size: u64) -> Option<usize> {
    let padded = size.checked_add(511)? / 512 * 512;
    usize::try_from(padded).ok()
}

fn tar_checksum(header: &[u8]) -> u64 {
    header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                b' ' as u64
            } else {
                *byte as u64
            }
        })
        .sum()
}

fn format_tar_checksum(value: u64) -> [u8; 8] {
    let text = format!("{value:06o}\0 ");
    let mut output = [0u8; 8];
    output.copy_from_slice(text.as_bytes());
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn gzip_truncated_stream_recompresses_recovered_prefix() {
        let payload = patterned_payload(512 * 1024);
        let mut encoded = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut encoded, GzipCompression::default());
            encoder.write_all(&payload).unwrap();
            encoder.finish().unwrap();
        }
        encoded.truncate(encoded.len() * 3 / 4);
        let output = temp_output("gzip_stream_partial.gz");

        let stats =
            recover_stream_prefix(&encoded, StreamFormat::Gzip, &output, &test_options()).unwrap();

        assert!(stats.decoded_bytes > 0);
        let recovered = fs::read(&output).unwrap();
        let mut decoder = GzDecoder::new(Cursor::new(recovered));
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert!(payload.starts_with(&decoded));
        assert!(decoded.len() < payload.len());
        let _ = fs::remove_file(output);
    }

    #[test]
    fn bzip2_truncated_stream_recompresses_recovered_prefix() {
        let payload = patterned_payload(2 * 1024 * 1024);
        let mut encoded = Vec::new();
        {
            let mut encoder = BzEncoder::new(&mut encoded, Bzip2Compression::default());
            encoder.write_all(&payload).unwrap();
            encoder.finish().unwrap();
        }
        encoded.truncate(encoded.len() * 9 / 10);
        let output = temp_output("bzip2_stream_partial.bz2");

        let stats =
            recover_stream_prefix(&encoded, StreamFormat::Bzip2, &output, &test_options()).unwrap();

        assert!(stats.decoded_bytes > 0);
        let recovered = fs::read(&output).unwrap();
        let mut decoder = BzDecoder::new(Cursor::new(recovered));
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert!(payload.starts_with(&decoded));
        let _ = fs::remove_file(output);
    }

    #[test]
    fn xz_truncated_stream_recompresses_recovered_prefix() {
        let payload = patterned_payload(1024 * 1024);
        let mut encoded = Vec::new();
        {
            let mut encoder = XzEncoder::new(&mut encoded, 6);
            encoder.write_all(&payload).unwrap();
            encoder.finish().unwrap();
        }
        encoded.truncate(encoded.len() * 9 / 10);
        let output = temp_output("xz_stream_partial.xz");

        let stats =
            recover_stream_prefix(&encoded, StreamFormat::Xz, &output, &test_options()).unwrap();

        assert!(stats.decoded_bytes > 0);
        let recovered = fs::read(&output).unwrap();
        let mut decoder = XzDecoder::new(Cursor::new(recovered));
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert!(payload.starts_with(&decoded));
        let _ = fs::remove_file(output);
    }

    #[test]
    fn zstd_truncated_stream_recompresses_recovered_prefix() {
        let payload = pseudo_random_payload(4 * 1024 * 1024);
        let encoded = zstd::stream::encode_all(Cursor::new(&payload), 0).unwrap();
        let mut truncated = encoded.clone();
        truncated.truncate(encoded.len() * 9 / 10);
        let output = temp_output("zstd_stream_partial.zst");

        let stats = recover_stream_prefix(&truncated, StreamFormat::Zstd, &output, &test_options())
            .unwrap();

        assert!(stats.decoded_bytes > 0);
        let recovered = fs::read(&output).unwrap();
        let decoded = zstd::stream::decode_all(Cursor::new(recovered)).unwrap();
        assert!(payload.starts_with(&decoded));
        let _ = fs::remove_file(output);
    }

    #[test]
    fn tar_prefix_repair_drops_truncated_member_and_appends_zero_blocks() {
        let first = tar_member("first.bin", b"first payload");
        let second = tar_member("second.bin", &patterned_payload(4096));
        let mut prefix = first.clone();
        prefix.extend_from_slice(&second[..512 + 32]);

        let repaired = repair_tar_prefix(&prefix, &test_options(), 20000).unwrap();

        assert_eq!(repaired.members, 1);
        assert_eq!(repaired.truncated_members, 1);
        assert_eq!(repaired.checksum_fixes, 0);
        assert_eq!(&repaired.bytes[..first.len()], first.as_slice());
        assert_eq!(&repaired.bytes[first.len()..], &[0u8; 1024]);
    }

    #[test]
    fn tar_prefix_repair_fixes_header_checksum() {
        let mut member = tar_member("payload.txt", b"payload");
        member[148] = b'7';

        let repaired = repair_tar_prefix(&member, &test_options(), 20000).unwrap();

        assert_eq!(repaired.members, 1);
        assert_eq!(repaired.checksum_fixes, 1);
        assert!(repaired.changed);
        assert_eq!(
            parse_tar_number(&repaired.bytes[148..156]),
            Some(tar_checksum(&repaired.bytes[..512]))
        );
    }

    #[test]
    fn gzip_tar_combo_recompresses_repaired_tar_prefix() {
        let first = tar_member("first.bin", &patterned_payload(2048));
        let second = tar_member("second.bin", &patterned_payload(4096));
        let mut tar_prefix = first.clone();
        tar_prefix.extend_from_slice(&second[..512 + 128]);
        let mut encoded = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut encoded, GzipCompression::default());
            encoder.write_all(&tar_prefix).unwrap();
            encoder.finish().unwrap();
        }
        encoded.truncate(encoded.len().saturating_sub(8));

        let decoded =
            decode_stream_prefix_to_vec(&encoded, StreamFormat::Gzip, &test_options()).unwrap();
        let tar = repair_tar_prefix(&decoded.bytes, &test_options(), 20000).unwrap();
        let output = temp_output("tar_gzip_combo.tar.gz");
        let output_bytes =
            write_recompressed_stream(StreamFormat::Gzip, &tar.bytes, &output, &test_options())
                .unwrap();

        assert!(output_bytes > 0);
        assert_eq!(tar.members, 1);
        let recovered = fs::read(&output).unwrap();
        let mut decoder = GzDecoder::new(Cursor::new(recovered));
        let mut repaired_tar = Vec::new();
        decoder.read_to_end(&mut repaired_tar).unwrap();
        assert_eq!(&repaired_tar[..first.len()], first.as_slice());
        assert_eq!(&repaired_tar[first.len()..], &[0u8; 1024]);
        let _ = fs::remove_file(output);
    }

    fn test_options() -> StreamRepairOptions {
        StreamRepairOptions {
            max_input_bytes: None,
            max_output_bytes: Some(10 * 1024 * 1024),
            max_duration: None,
        }
    }

    fn patterned_payload(size: usize) -> Vec<u8> {
        (0..size).map(|index| (index % 251) as u8).collect()
    }

    fn pseudo_random_payload(size: usize) -> Vec<u8> {
        let mut value = 0x1234_5678u32;
        let mut output = Vec::with_capacity(size);
        for _ in 0..size {
            value ^= value << 13;
            value ^= value >> 17;
            value ^= value << 5;
            output.push((value & 0xFF) as u8);
        }
        output
    }

    fn temp_output(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic enough for tests")
            .as_nanos();
        std::env::temp_dir().join(format!("sunpack_native_{name}_{nonce}"))
    }

    fn tar_member(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[0..name.len()].copy_from_slice(name.as_bytes());
        write_tar_octal(&mut header[100..108], 0o644);
        write_tar_octal(&mut header[108..116], 0);
        write_tar_octal(&mut header[116..124], 0);
        write_tar_octal(&mut header[124..136], payload.len() as u64);
        write_tar_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = tar_checksum(&header);
        header[148..156].copy_from_slice(&format_tar_checksum(checksum));

        let mut output = header.to_vec();
        output.extend_from_slice(payload);
        let padding = (512 - (payload.len() % 512)) % 512;
        output.extend(std::iter::repeat(0).take(padding));
        output
    }

    fn write_tar_octal(field: &mut [u8], value: u64) {
        let width = field.len() - 1;
        let text = format!("{:0width$o}\0", value, width = width);
        field.copy_from_slice(text.as_bytes());
    }
}
