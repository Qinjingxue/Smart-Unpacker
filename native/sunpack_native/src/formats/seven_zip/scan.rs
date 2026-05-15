#[pyfunction]
#[pyo3(signature = (
    source_input,
    max_input_size_mb=512.0,
    max_scan_bytes=1048576,
    max_candidates=8
))]
pub(crate) fn seven_zip_scan_source(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    max_input_size_mb: f64,
    max_scan_bytes: usize,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let password = extract_password(source_input);
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => return seven_zip_scan_error(py, "skipped", &message),
    };
    let password_status = seven_zip_password_status(&data, password.as_deref());
    let result = PyDict::new(py);
    result.set_item("status", "ok")?;
    result.set_item("native_key", "native_7z_scan_source")?;
    result.set_item("native_target", "seven_zip_scan_source")?;
    result.set_item("format", "7z")?;
    result.set_item("input_size", data.len() as u64)?;
    result.set_item("password_present", password.is_some())?;

    let offsets = find_all(&data, SEVEN_Z_MAGIC);
    result.set_item("signature_count", offsets.len())?;
    result.set_item("signature_offsets", PyList::new(py, offsets.iter().take(max_candidates.max(1)).copied().collect::<Vec<_>>())?)?;
    let Some(offset) = offsets.first().copied() else {
        result.set_item("route_evidence_flags", PyList::new(py, ["seven_zip_signature_missing"])?)?;
        result.set_item("structure", PyDict::new(py))?;
        result.set_item("candidates", PyList::empty(py))?;
        return Ok(result.unbind());
    };

    let loose = loose_seven_zip_header_facts(&data, offset);
    let header = parse_seven_zip_header(&data, offset);
    let candidates = scan_archive_signatures(&data, TargetFormat::SevenZip, false, max_candidates.max(1));
    let candidate_list = PyList::empty(py);
    for candidate in &candidates {
        let item = PyDict::new(py);
        item.set_item("offset", candidate.offset)?;
        item.set_item("archive_end", candidate.archive_end)?;
        item.set_item("start_crc_ok", candidate.start_crc_ok)?;
        item.set_item("next_header_crc_ok", candidate.next_header_crc_ok)?;
        item.set_item("warnings", PyList::new(py, &candidate.warnings)?)?;
        candidate_list.append(item)?;
    }
    result.set_item("candidates", candidate_list)?;

    let structure = PyDict::new(py);
    structure.set_item("password_present", password.is_some())?;
    structure.set_item("password_required", password_status.password_required)?;
    structure.set_item("password_rejected", password_status.password_rejected)?;
    structure.set_item("archive_readable_with_password", password_status.archive_readable)?;
    structure.set_item("encrypted_header", password_status.encrypted_header)?;
    if let Some(message) = password_status.message.as_ref() {
        structure.set_item("password_diagnostic", message)?;
    }
    structure.set_item("signature_offset", offset)?;
    if offset + 8 <= data.len() {
        let major = data[offset + 6];
        let minor = data[offset + 7];
        structure.set_item("signature_header_major_version", major)?;
        structure.set_item("signature_header_minor_version", minor)?;
        structure.set_item("signature_header_version_bad", major != 0 || minor > 4)?;
    }
    structure.set_item("carrier_prefix_bytes", offset)?;
    structure.set_item("has_carrier_prefix", offset > 0)?;
    structure.set_item("stored_next_header_offset", loose.next_header_offset)?;
    structure.set_item("stored_next_header_size", loose.next_header_size)?;
    structure.set_item("stored_start_crc", loose.stored_start_crc)?;
    structure.set_item("computed_start_crc", loose.computed_start_crc)?;
    structure.set_item("start_crc_ok", loose.start_crc_ok)?;
    structure.set_item("next_header_range_valid", loose.range_valid)?;
    structure.set_item("next_header_out_of_range", !loose.range_valid)?;
    if let Some(header) = &header {
        structure.set_item("archive_end", header.archive_end)?;
        structure.set_item("trailing_bytes", data.len().saturating_sub(header.archive_end))?;
        structure.set_item("next_header_start", header.next_header_start)?;
        structure.set_item("next_header_offset", header.next_header_offset)?;
        structure.set_item("next_header_size", header.next_header_size)?;
        structure.set_item("stored_next_header_crc", header.stored_next_header_crc)?;
        structure.set_item("computed_next_header_crc", header.computed_next_header_crc)?;
        structure.set_item("next_header_nid", header.next_header_nid)?;
        structure.set_item("next_header_crc_ok", header.next_header_crc_ok())?;
        structure.set_item("next_header_nid_valid", header.next_header_nid_valid)?;
        structure.set_item("encoded_header_present", header.next_header_nid == SZ_ENCODED_HEADER)?;
        let ast_for_scan = if header.next_header_nid == SZ_ENCODED_HEADER {
            parse_seven_zip_encoded_header_ast(&data, header)
        } else {
            parse_seven_zip_header_ast(&data, header)
        };
        if let Ok(ast) = ast_for_scan {
            if let Some(pack) = ast.pack_info.as_ref() {
                structure.set_item("pack_stream_count", pack.num_streams)?;
                structure.set_item("pack_stream_offset", pack.pack_pos.value)?;
                let pack_sizes = pack.sizes.iter().map(|item| item.value).collect::<Vec<_>>();
                structure.set_item("pack_stream_sizes", PyList::new(py, pack_sizes)?)?;
                if pack.num_streams == 1 && pack.sizes.len() == 1 {
                    let expected_offset = if header.next_header_nid == SZ_ENCODED_HEADER {
                        header.next_header_offset.checked_sub(pack.sizes[0].value).unwrap_or(0)
                    } else {
                        0
                    };
                    structure.set_item("pack_stream_offset_expected", expected_offset)?;
                    structure.set_item("pack_stream_offset_bad", pack.pack_pos.value != expected_offset)?;
                    let expected_size = header.next_header_offset.checked_sub(pack.pack_pos.value).unwrap_or(0);
                    structure.set_item("pack_stream_size_expected", expected_size)?;
                    structure.set_item("pack_stream_size_bad", expected_size > 0 && expected_size != pack.sizes[0].value)?;
                } else {
                    structure.set_item("pack_stream_offset_bad", pack.pack_pos.value != 0)?;
                }
                if pack.num_streams == 1 && pack.sizes.len() == 1 {
                    if pack.crc_values.len() == 1 && pack.crc_defined_all {
                        let stream_start = SEVEN_Z_HEADER_SIZE
                            .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                            .unwrap_or(usize::MAX);
                        let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
                        let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
                        if stream_start >= SEVEN_Z_HEADER_SIZE && stream_end <= data.len() && stream_end <= header.next_header_start {
                            let computed_crc = crc32(&data[stream_start..stream_end]);
                            structure.set_item("computed_stream_crc", computed_crc)?;
                            structure.set_item("stored_stream_crc", pack.crc_values[0].value)?;
                            if header.next_header_nid == SZ_ENCODED_HEADER {
                                structure.set_item("encoded_header_stream_crc_bad", computed_crc != pack.crc_values[0].value)?;
                            } else {
                                structure.set_item("stream_crc_bad", computed_crc != pack.crc_values[0].value)?;
                            }
                        }
                    }
                }
            }
            if let Some(files) = ast.files_info.as_ref() {
                structure.set_item("file_count_metadata", files.num_files.value)?;
                structure.set_item("empty_stream_property_present", files.empty_stream_property.is_some())?;
                structure.set_item("empty_file_property_present", files.empty_file_property.is_some())?;
                structure.set_item("anti_item_property_present", files.anti_property.is_some())?;
            }
        }
    } else {
        structure.set_item("archive_end", 0)?;
        structure.set_item("trailing_bytes", 0)?;
        structure.set_item("next_header_crc_ok", false)?;
        structure.set_item("next_header_nid_valid", false)?;
        structure.set_item("encoded_header_present", false)?;
    }
    let needs_header_candidate_scan = !loose.range_valid
        || header
            .as_ref()
            .is_none_or(|item| !item.next_header_nid_valid);
    if needs_header_candidate_scan {
        if let Some((offset_candidate, size_candidate)) = find_next_header_candidate(&data[offset..], max_scan_bytes.max(1)) {
            structure.set_item("encoded_header_candidate_found", true)?;
            structure.set_item("encoded_header_candidate_offset", offset_candidate)?;
            structure.set_item("encoded_header_candidate_size", size_candidate)?;
        } else {
            structure.set_item("encoded_header_candidate_found", false)?;
        }
    } else {
        structure.set_item("encoded_header_candidate_found", false)?;
    }
    if let Some(header) = &header {
        if header.next_header_nid == SZ_ENCODED_HEADER {
            match decode_seven_zip_encoded_header_payload(&data, header, password.as_deref()) {
                Ok(_) => {
                    structure.set_item("encoded_header_decodable", true)?;
                    structure.set_item("encoded_header_decoder_method_supported", true)?;
                }
                Err(reason) => {
                    structure.set_item("encoded_header_decodable", false)?;
                    structure.set_item("encoded_header_decoder_method_supported", !reason.contains("unsupported"))?;
                    structure.set_item(
                        "encoded_header_coder_properties_bad",
                        !reason.contains("password") && reason.contains("coder_properties"),
                    )?;
                    if reason.contains("password") {
                        structure.set_item(
                            if password.is_some() { "encoded_header_decode_password_rejected" } else { "encoded_header_decode_password_required" },
                            true,
                        )?;
                    }
                }
            }
        } else {
            structure.set_item("encoded_header_decodable", false)?;
        }
    } else {
        structure.set_item("encoded_header_decodable", false)?;
    }
    if !structure.contains("encoded_header_stream_crc_bad")? {
        structure.set_item("encoded_header_stream_crc_bad", false)?;
    }
    if !structure.contains("pack_stream_offset_bad")? {
        structure.set_item("pack_stream_offset_bad", false)?;
    }
    if !structure.contains("pack_stream_size_bad")? {
        structure.set_item("pack_stream_size_bad", false)?;
    }
    if !structure.contains("encoded_header_coder_properties_bad")? {
        structure.set_item("encoded_header_coder_properties_bad", false)?;
    }
    if let Some(header) = &header {
        let raw = data.get(header.next_header_start..header.archive_end).unwrap_or(&[]);
        structure.set_item(
            "header_end_marker_bad",
            raw.last().copied().is_some_and(|item| item != SZ_END),
        )?;
    } else {
        structure.set_item("header_end_marker_bad", false)?;
    }
    structure.set_item("unpack_size_bad", false)?;
    if !structure.contains("stream_crc_bad")? {
        structure.set_item("stream_crc_bad", false)?;
    }
    structure.set_item("substream_crc_bad", false)?;
    structure.set_item("empty_stream_flags_bad", false)?;
    structure.set_item("empty_file_flags_bad", false)?;
    structure.set_item("anti_item_flags_bad", false)?;
    if let Some(header) = &header {
        if header.next_header_nid == SZ_ENCODED_HEADER {
            let raw = data.get(header.next_header_start..header.archive_end).unwrap_or(&[]);
            structure.set_item(
                "folder_bind_pairs_bad",
                matches!(seven_zip_encoded_header_folder_bind_pairs_patch(raw), Ok(Some(_))),
            )?;
            structure.set_item(
                "folder_stream_counts_bad",
                matches!(seven_zip_encoded_header_folder_stream_counts_patch(raw), Ok(Some(_))),
            )?;
        } else {
            structure.set_item("folder_bind_pairs_bad", false)?;
            structure.set_item("folder_stream_counts_bad", false)?;
        }
    } else {
        structure.set_item("folder_bind_pairs_bad", false)?;
        structure.set_item("folder_stream_counts_bad", false)?;
    }
    structure.set_item("file_count_metadata_bad", false)?;
    structure.set_item("file_names_utf16_bad", false)?;
    structure.set_item("unreferenced_folder", false)?;
    structure.set_item("unreferenced_file_record", false)?;
    structure.set_item("invalid_stream_crc_defined_flag", false)?;
    structure.set_item("bad_folder_detected", false)?;
    structure.set_item("verified_folder_available", false)?;
    result.set_item("structure", structure)?;

    let mut route_flags = seven_zip_route_flags(&data, offset, header.as_ref(), &loose, password.as_deref());
    if password_status.password_required {
        push_unique_string(&mut route_flags, "password_required");
        push_unique_string(&mut route_flags, "encrypted_header");
    }
    if password_status.password_rejected {
        push_unique_string(&mut route_flags, "wrong_password");
        push_unique_string(&mut route_flags, "encrypted_header");
    }
    result.set_item("route_evidence_flags", PyList::new(py, &route_flags)?)?;
    result.set_item("container_tags", PyList::new(py, seven_zip_container_tags(offset, header.as_ref(), data.len()))?)?;
    Ok(result.unbind())
}

fn scan_archive_signatures(
    data: &[u8],
    _target: TargetFormat,
    require_carrier_offset: bool,
    max_candidates: usize,
) -> Vec<ArchiveCandidate> {
    let mut output = Vec::new();
    for offset in find_all(data, SEVEN_Z_MAGIC) {
        if require_carrier_offset && offset == 0 {
            continue;
        }
        if let Some(candidate) = seven_zip_candidate(data, offset) {
            output.push(candidate);
            if output.len() >= max_candidates { return output; }
        }
    }
    output.sort_by_key(|candidate| candidate.offset);
    output
}

pub(crate) fn carrier_scan_candidates(
    data: &[u8],
    require_carrier_offset: bool,
    max_candidates: usize,
) -> Vec<CarrierScanCandidate> {
    scan_archive_signatures(data, TargetFormat::SevenZip, require_carrier_offset, max_candidates)
        .into_iter()
        .map(|candidate| CarrierScanCandidate {
            offset: candidate.offset,
            archive_end: candidate.archive_end,
            start_crc_ok: candidate.start_crc_ok,
            next_header_crc_ok: candidate.next_header_crc_ok,
            warnings: candidate.warnings,
        })
        .collect()
}

fn seven_zip_route_flags(
    data: &[u8],
    offset: usize,
    header: Option<&SevenZipHeader>,
    loose: &SevenZipLooseHeaderFacts,
    password: Option<&str>,
) -> Vec<String> {
    let mut flags = vec!["seven_zip_signature_found".to_string()];
    if offset + 8 <= data.len() && (data[offset + 6] != 0 || data[offset + 7] > 4) {
        flags.push("signature_header_version_bad".to_string());
    }
    if offset > 0 {
        flags.extend([
            "carrier_prefix".to_string(),
            "carrier_archive".to_string(),
            "embedded_archive".to_string(),
        ]);
    }
    if !loose.start_crc_ok {
        flags.push("start_header_crc_bad".to_string());
    }
    if !loose.range_valid {
        flags.push("next_header_out_of_range".to_string());
    }
    if let Some(header) = header {
        if header.archive_end < data.len() {
            flags.push("trailing_junk".to_string());
        }
        if !header.next_header_crc_ok() {
            flags.push("next_header_crc_bad".to_string());
        }
        if header.next_header_nid == SZ_ENCODED_HEADER {
            flags.push("encoded_header_present".to_string());
            let raw = data.get(header.next_header_start..header.archive_end).unwrap_or(&[]);
            if raw.last().copied().is_some_and(|item| item != SZ_END) {
                flags.push("header_end_marker_bad".to_string());
            }
            if matches!(seven_zip_encoded_header_folder_bind_pairs_patch(raw), Ok(Some(_))) {
                flags.push("folder_bind_pairs_bad".to_string());
            }
            if matches!(seven_zip_encoded_header_folder_stream_counts_patch(raw), Ok(Some(_))) {
                flags.push("folder_stream_counts_bad".to_string());
            }
        }
        if !header.next_header_nid_valid {
            flags.push("encoded_header_unreadable".to_string());
        }
        let ast_for_route = if header.next_header_nid == SZ_ENCODED_HEADER {
            parse_seven_zip_encoded_header_ast(data, header)
        } else {
            parse_seven_zip_header_ast(data, header)
        };
        if let Ok(ast) = ast_for_route {
            if let Some(pack) = ast.pack_info.as_ref() {
                if pack.num_streams == 1 && pack.sizes.len() == 1 {
                    let expected_offset = if header.next_header_nid == SZ_ENCODED_HEADER {
                        header.next_header_offset.checked_sub(pack.sizes[0].value).unwrap_or(0)
                    } else {
                        0
                    };
                    if pack.pack_pos.value != expected_offset {
                        flags.push("pack_stream_offset_bad".to_string());
                    }
                    let expected_size = header.next_header_offset.checked_sub(pack.pack_pos.value).unwrap_or(0);
                    if expected_size > 0 && expected_size != pack.sizes[0].value {
                        flags.push("pack_stream_size_bad".to_string());
                    }
                    if pack.crc_values.len() == 1 && pack.crc_defined_all {
                        let stream_start = SEVEN_Z_HEADER_SIZE
                            .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                            .unwrap_or(usize::MAX);
                        let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
                        let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
                        if stream_start >= SEVEN_Z_HEADER_SIZE && stream_end <= data.len() && stream_end <= header.next_header_start {
                            let computed_crc = crc32(&data[stream_start..stream_end]);
                            if computed_crc != pack.crc_values[0].value {
                                if header.next_header_nid == SZ_ENCODED_HEADER {
                                    flags.push("encoded_header_stream_crc_bad".to_string());
                                } else {
                                    flags.push("stream_crc_bad".to_string());
                                }
                            }
                        }
                    }
                } else if pack.pack_pos.value != 0 {
                    flags.push("pack_stream_offset_bad".to_string());
                }
            }
        }
        if header.next_header_nid == SZ_ENCODED_HEADER {
            if let Err(reason) = decode_seven_zip_encoded_header_payload(data, header, password) {
                if !reason.contains("password")
                    && reason.contains("coder_properties")
                {
                    flags.push("encoded_header_coder_properties_bad".to_string());
                }
            }
        }
    }
    flags
}

fn seven_zip_container_tags(offset: usize, header: Option<&SevenZipHeader>, input_len: usize) -> Vec<String> {
    let mut tags = vec!["7z".to_string()];
    if offset > 0 {
        tags.push("carrier_prefix".to_string());
        tags.push("embedded_archive".to_string());
    }
    if header.is_some_and(|item| item.archive_end < input_len) {
        tags.push("trailing_junk".to_string());
    }

    tags
}

