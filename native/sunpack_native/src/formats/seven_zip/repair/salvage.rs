fn seven_zip_salvage_solid_prefix_native(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let password = extract_password(source_input);
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "7z", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let recovered = match recover_seven_zip_entries_by_block(
        &data,
        max_entries.max(1),
        password.as_deref(),
        mb_to_bytes(max_output_size_mb).unwrap_or(512 * 1024 * 1024),
    ) {
        Ok(entries) => entries,
        Err(message) => {
            let residual = password_residual_fact(&message, password.is_some());
            let residual_refs = residual.iter().map(String::as_str).collect::<Vec<_>>();
            return seven_zip_atomic_status(
                py,
                "unrepairable",
                "solid_prefix",
                "7z",
                "",
                &message,
                &[],
                &[],
                &[],
                0.0,
                &residual_refs,
                &[],
            );
        }
    };
    if recovered.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "7z",
            "no decodable 7z block entries were recoverable",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    }
    let output_path = Path::new(workspace).join("seven_zip_salvage_solid_prefix.7z");
    let output_bytes =
        match write_stored_7z_entries(&recovered, &output_path, mb_to_bytes(max_output_size_mb)) {
            Ok(bytes) => bytes,
            Err(message) => {
                return status_dict(
                    py,
                    "unrepairable",
                    "",
                    "7z",
                    &message,
                    &[],
                    0,
                    data.len() as u64,
                    0,
                    0.0,
                    &[],
                )
            }
        };
    let selected = WrittenArchiveCandidate {
        name: "seven_zip_salvage_solid_prefix".to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "partial".to_string(),
        offset: 0,
        end_offset: data.len() as u64,
        output_bytes,
        confidence: (0.58 + recovered.len() as f64 * 0.04).min(0.88),
        actions: vec![
            "parse_7z_next_header_blocks".to_string(),
            "decode_7z_blocks_independently".to_string(),
            "repack_recoverable_entries_as_7z".to_string(),
        ],
        warnings: vec!["7z partial salvage container contains recovered files only".to_string()],
    };
    let result = status_dict_with_candidates(
        py,
        "partial",
        &selected.path,
        "7z",
        "7z block-level salvage recovered decodable entries into a 7z partial candidate",
        &selected.warnings,
        0,
        data.len() as u64,
        output_bytes,
        selected.confidence,
        &[
            "parse_7z_next_header_blocks",
            "decode_7z_blocks_independently",
            "repack_recoverable_entries_as_7z",
        ],
        &[selected.clone()],
    )?;
    result
        .bind(py)
        .set_item("recovered_entry_count", recovered.len())?;
    add_seven_zip_candidate_replace_patch_plans(py, &result, &data, "solid_prefix")?;
    Ok(result)
}

fn seven_zip_salvage_non_solid_entries_native(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let password = extract_password(source_input);
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "7z", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let recovered = match recover_seven_zip_entries_by_block(
        &data,
        max_entries.max(1),
        password.as_deref(),
        mb_to_bytes(max_output_size_mb).unwrap_or(512 * 1024 * 1024),
    ) {
        Ok(entries) => entries,
        Err(message) => {
            let residual = password_residual_fact(&message, password.is_some());
            let residual_refs = residual.iter().map(String::as_str).collect::<Vec<_>>();
            return seven_zip_atomic_status(
                py,
                "unrepairable",
                "non_solid_entries",
                "7z",
                "",
                &message,
                &[],
                &[],
                &[],
                0.0,
                &residual_refs,
                &[],
            );
        }
    };
    if recovered.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "7z",
            "no independently decodable non-solid 7z entries were recoverable",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    }
    let output_path = Path::new(workspace).join("seven_zip_salvage_non_solid_entries.7z");
    let output_bytes =
        match write_stored_7z_entries(&recovered, &output_path, mb_to_bytes(max_output_size_mb)) {
            Ok(bytes) => bytes,
            Err(message) => {
                return status_dict(
                    py,
                    "unrepairable",
                    "",
                    "7z",
                    &message,
                    &[],
                    0,
                    data.len() as u64,
                    0,
                    0.0,
                    &[],
                )
            }
        };
    let selected = WrittenArchiveCandidate {
        name: "seven_zip_salvage_non_solid_entries".to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "partial".to_string(),
        offset: 0,
        end_offset: data.len() as u64,
        output_bytes,
        confidence: (0.62 + recovered.len() as f64 * 0.05).min(0.92),
        actions: vec![
            "parse_7z_folder_streams".to_string(),
            "decode_independent_7z_entries".to_string(),
            "quarantine_failed_7z_entries".to_string(),
            "repack_recoverable_entries_as_7z".to_string(),
        ],
        warnings: vec!["7z partial salvage container contains recovered files only".to_string()],
    };
    let result = status_dict_with_candidates(
        py,
        "partial",
        &selected.path,
        "7z",
        "7z non-solid partial salvage recovered independently decodable entries into a 7z partial candidate",
        &selected.warnings,
        0,
        data.len() as u64,
        output_bytes,
        selected.confidence,
        &[
            "parse_7z_folder_streams",
            "decode_independent_7z_entries",
            "quarantine_failed_7z_entries",
            "repack_recoverable_entries_as_7z",
        ],
        &[selected.clone()],
    )?;
    result
        .bind(py)
        .set_item("recovered_entry_count", recovered.len())?;
    add_seven_zip_candidate_replace_patch_plans(py, &result, &data, "non_solid_entries")?;
    Ok(result)
}

struct StoredZipEntry {
    name: Vec<u8>,
    data: Vec<u8>,
}

fn recover_seven_zip_entries_by_block(
    data: &[u8],
    max_entries: usize,
    password: Option<&str>,
    max_output_bytes: u64,
) -> Result<Vec<StoredZipEntry>, String> {
    if !data.starts_with(SEVEN_Z_MAGIC) {
        return Err("input does not start with a 7z signature".to_string());
    }
    guard_seven_zip_salvage_header(data)?;
    let mut cursor = Cursor::new(data.to_vec());
    let password = seven_zip_password(password);
    let archive = Archive::read(&mut cursor, &password).map_err(|err| err.to_string())?;
    let mut output = Vec::new();
    let mut output_bytes = 0u64;
    for file in &archive.files {
        if output.len() >= max_entries {
            break;
        }
        if file.is_directory || file.is_anti_item || file.has_stream || file.size != 0 {
            continue;
        }
        let name = sanitize_archive_name(file.name());
        if name.is_empty() {
            continue;
        }
        output.push(StoredZipEntry {
            name: name.into_bytes(),
            data: Vec::new(),
        });
    }
    for block_index in 0..archive.blocks.len() {
        if output.len() >= max_entries {
            break;
        }
        let mut source = Cursor::new(data.to_vec());
        let decoder = BlockDecoder::new(1, block_index, &archive, &password, &mut source);
        let _ = decoder.for_each_entries(&mut |entry, reader| {
            if output.len() >= max_entries {
                return Ok(false);
            }
            if entry.is_directory || entry.is_anti_item {
                return Ok(true);
            }
            let name = sanitize_archive_name(entry.name());
            if name.is_empty() {
                return Ok(true);
            }
            let remaining = max_output_bytes.saturating_sub(output_bytes);
            if remaining == 0 {
                return Ok(false);
            }
            let mut bytes = Vec::new();
            let mut limited = reader.take(remaining.saturating_add(1));
            limited.read_to_end(&mut bytes)?;
            if bytes.len() as u64 > remaining {
                return Ok(false);
            }
            if entry.has_crc && crc32(&bytes) as u64 != entry.crc {
                return Ok(true);
            }
            output_bytes = output_bytes.saturating_add(bytes.len() as u64);
            output.push(StoredZipEntry {
                name: name.into_bytes(),
                data: bytes,
            });
            Ok(true)
        });
    }
    Ok(output)
}

fn guard_seven_zip_salvage_header(data: &[u8]) -> Result<(), String> {
    let Some(header) = parse_seven_zip_header(data, 0) else {
        return Err("7z salvage requires a parseable start header".to_string());
    };
    if !header.start_crc_ok() {
        return Err("7z salvage requires a valid start header CRC".to_string());
    }
    if !header.next_header_crc_ok() {
        return Err(
            "7z salvage requires a valid next header CRC before block decoding".to_string(),
        );
    }
    if header.next_header_nid == SZ_ENCODED_HEADER {
        return Err("7z EncodedHeader must be decoded before entry salvage".to_string());
    }
    if !header.next_header_nid_valid {
        return Err("7z salvage requires a valid Header or EncodedHeader NID".to_string());
    }
    parse_seven_zip_header_ast(data, &header)
        .and_then(|ast| {
            if ast.diagnostics.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "7z Header graph is incomplete: {}",
                    ast.diagnostics.join(", ")
                ))
            }
        })
        .map_err(|message| format!("7z salvage requires a parseable plain Header: {message}"))
}
fn write_stored_7z_entries(
    entries: &[StoredZipEntry],
    output: &Path,
    max_output_bytes: Option<u64>,
) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let recovered_payload_bytes = entries
        .iter()
        .try_fold(0u64, |total, entry| {
            total.checked_add(entry.data.len() as u64)
        })
        .ok_or_else(|| "recovered entry payload size overflow".to_string())?;
    if max_output_bytes.is_some_and(|limit| recovered_payload_bytes > limit) {
        return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
    }

    let temp = temp_path(output);
    let result = (|| -> Result<u64, String> {
        let file = crate::io::resource_lifecycle::TrackedFile::create(
            &temp,
            "seven_zip_salvage_output",
        )
        .map_err(|err| err.to_string())?;
        let mut writer = ArchiveWriter::new(file).map_err(|err| err.to_string())?;
        writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
        writer.set_encrypt_header(false);
        for entry in entries {
            let name = stored_7z_entry_name(entry);
            let archive_entry = ArchiveEntry::new_file(&name);
            if entry.data.is_empty() {
                writer
                    .push_archive_entry::<&[u8]>(archive_entry, None)
                    .map_err(|err| err.to_string())?;
            } else {
                writer
                    .push_archive_entry(archive_entry, Some(entry.data.as_slice()))
                    .map_err(|err| err.to_string())?;
            }
        }
        let mut file = writer.finish().map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        let size = file.stream_position().map_err(|err| err.to_string())?;
        if max_output_bytes.is_some_and(|limit| size > limit) {
            return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
        }
        Ok(size)
    })();
    match result {
        Ok(size) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(size)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn stored_7z_entry_name(entry: &StoredZipEntry) -> String {
    let name = String::from_utf8_lossy(&entry.name).replace('\\', "/");
    let name = name.trim_start_matches('/').trim_start_matches("./");
    if name.is_empty() {
        "recovered_entry".to_string()
    } else {
        name.to_string()
    }
}

fn sanitize_archive_name(name: &str) -> String {
    let normalized = name.replace('\\', "/");
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>();
    parts.join("/")
}
