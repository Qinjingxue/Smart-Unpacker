fn read_source_input(
    source_input: &Bound<'_, PyDict>,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, String> {
    let kind = get_optional_string(source_input, "kind")
        .map_err(|err| err.to_string())?
        .unwrap_or_else(|| "file".to_string());
    match kind.as_str() {
        "bytes" | "memory" => {
            let data_obj = source_input
                .get_item("data")
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "missing bytes repair input data".to_string())?;
            let data = data_obj
                .cast::<PyBytes>()
                .map_err(|err| err.to_string())?
                .as_bytes();
            if max_bytes.is_some_and(|limit| data.len() as u64 > limit) {
                return Err("archive deep repair input exceeds max_input_size_mb".to_string());
            }
            Ok(data.to_vec())
        }
        "file" => {
            let path = get_required_string(source_input, "path").map_err(|err| err.to_string())?;
            read_range_to_vec(&path, 0, None, max_bytes)
        }
        "file_range" => {
            let path = get_required_string(source_input, "path").map_err(|err| err.to_string())?;
            let start = get_optional_u64(source_input, "start")
                .map_err(|err| err.to_string())?
                .unwrap_or(0);
            let end = get_optional_u64(source_input, "end").map_err(|err| err.to_string())?;
            read_range_to_vec(&path, start, end, max_bytes)
        }
        "concat_ranges" => {
            let ranges_obj = source_input
                .get_item("ranges")
                .map_err(|err| err.to_string())?
                .ok_or_else(|| "missing ranges".to_string())?;
            let ranges = ranges_obj.cast::<PyList>().map_err(|err| err.to_string())?;
            let mut output = Vec::new();
            for item in ranges.iter() {
                let dict = item.cast::<PyDict>().map_err(|err| err.to_string())?;
                let path = get_required_string(dict, "path").map_err(|err| err.to_string())?;
                let start = get_optional_u64(dict, "start")
                    .map_err(|err| err.to_string())?
                    .unwrap_or(0);
                let end = get_optional_u64(dict, "end").map_err(|err| err.to_string())?;
                let remaining_limit =
                    max_bytes.map(|limit| limit.saturating_sub(output.len() as u64));
                let chunk = read_range_to_vec(&path, start, end, remaining_limit)?;
                output.extend_from_slice(&chunk);
                if max_bytes.is_some_and(|limit| output.len() as u64 > limit) {
                    return Err("archive deep repair input exceeds max_input_size_mb".to_string());
                }
            }
            Ok(output)
        }
        _ => Err(format!("unsupported repair input kind: {kind}")),
    }
}

fn read_range_to_vec(
    path: &str,
    start: u64,
    end: Option<u64>,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, String> {
    crate::io::util::read_source_range(
        path,
        start,
        end,
        max_bytes,
        "archive deep repair input exceeds max_input_size_mb",
    )
}

fn extract_password(source_input: &Bound<'_, PyDict>) -> Option<String> {
    source_input
        .get_item("password")
        .ok()
        .flatten()
        .and_then(|value| value.extract::<String>().ok())
        .filter(|value| !value.is_empty())
}

fn seven_zip_password(password: Option<&str>) -> Password {
    match password {
        Some(value) if !value.is_empty() => Password::from(value),
        _ => Password::empty(),
    }
}

struct SevenZipPasswordStatus {
    archive_readable: bool,
    password_required: bool,
    password_rejected: bool,
    encrypted_header: bool,
    message: Option<String>,
}

fn seven_zip_password_status(data: &[u8], password: Option<&str>) -> SevenZipPasswordStatus {
    if !data.starts_with(SEVEN_Z_MAGIC) {
        return SevenZipPasswordStatus {
            archive_readable: false,
            password_required: false,
            password_rejected: false,
            encrypted_header: false,
            message: None,
        };
    }
    let Some(header) = parse_seven_zip_header(data, 0) else {
        return SevenZipPasswordStatus {
            archive_readable: false,
            password_required: false,
            password_rejected: false,
            encrypted_header: false,
            message: None,
        };
    };
    let facts = seven_zip_encryption_facts_from_next_header(
        data.get(header.next_header_start..header.archive_end)
            .unwrap_or(&[]),
    );
    let password_rejected = facts.password_required && password.is_some();
    SevenZipPasswordStatus {
        archive_readable: facts.scan_complete && !facts.password_required,
        password_required: facts.password_required,
        password_rejected,
        encrypted_header: facts.encrypted_header,
        message: facts.password_required.then(|| {
            if password.is_some() {
                "7z encrypted header or payload requires password verification".to_string()
            } else {
                "7z encrypted header or payload requires a password".to_string()
            }
        }),
    }
}

fn is_password_related_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("password") || lower.contains("encrypted") || lower.contains("decrypt")
}

fn password_residual_fact(message: &str, password_present: bool) -> Vec<String> {
    if is_password_related_error(message) {
        if password_present {
            vec!["password_rejected".to_string()]
        } else {
            vec![
                "password_required".to_string(),
                "wrong_password".to_string(),
            ]
        }
    } else {
        Vec::new()
    }
}

fn push_unique_string(items: &mut Vec<String>, value: &str) {
    if !items.iter().any(|item| item == value) {
        items.push(value.to_string());
    }
}
fn write_slice_candidate(bytes: &[u8], output: &Path) -> std::io::Result<u64> {
    ensure_parent(output)?;
    let temp = temp_path(output);
    let result = (|| -> std::io::Result<u64> {
        let mut file = File::create(&temp)?;
        file.write_all(bytes)?;
        file.flush()?;
        Ok(bytes.len() as u64)
    })();
    match result {
        Ok(written) => {
            if output.exists() {
                fs::remove_file(output)?;
            }
            fs::rename(&temp, output)?;
            Ok(written)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}
fn carrier_crop_patch_facts(format: &str, offset: u64, end_offset: u64) -> Vec<String> {
    vec![
        "fixed_field=carrier_prefix_crop".to_string(),
        "after_archive_carrier_crop".to_string(),
        format!("cropped_format={format}"),
        format!("cropped_start={offset}"),
        format!("cropped_end={end_offset}"),
    ]
}

fn carrier_crop_residual_facts(format: &str) -> Vec<&'static str> {
    if format == "zip" {
        vec![
            "central_directory_bad",
            "content_integrity_bad_or_unknown",
            "payload_hash_mismatch",
        ]
    } else {
        Vec::new()
    }
}

fn candidate_crc32(path: &str) -> String {
    match crate::io::reader::ManagedReader::open(path).and_then(|reader| reader.read_all()) {
        Ok(bytes) => format!("{:08x}", crc32(&bytes)),
        Err(_) => String::new(),
    }
}

fn find_all(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return Vec::new();
    }
    let mut output = Vec::new();
    let mut start = 0usize;
    while start + needle.len() <= data.len() {
        let Some(index) = find_subslice(&data[start..], needle) else {
            break;
        };
        let absolute = start + index;
        output.push(absolute);
        start = absolute + 1;
    }
    output
}

fn find_subslice(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len())
        .position(|window| window == needle)
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
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

fn mb_to_bytes(value: f64) -> Option<u64> {
    if value <= 0.0 {
        None
    } else {
        Some((value * 1024.0 * 1024.0) as u64)
    }
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
