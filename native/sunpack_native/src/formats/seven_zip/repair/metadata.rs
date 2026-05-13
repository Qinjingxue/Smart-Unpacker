#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    target,
    max_input_size_mb=512.0,
    max_scan_bytes=1048576,
    max_output_size_mb=2048.0,
    max_entries=20000,
    max_candidates=8
))]
pub(crate) fn seven_zip_atomic_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    target: &str,
    max_input_size_mb: f64,
    max_scan_bytes: usize,
    max_output_size_mb: f64,
    max_entries: usize,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    match target {
        "unpack_size"
        | "bad_folder_quarantine"
        | "file_names_utf16"
        | "unreferenced_folder"
        | "unreferenced_file_record"
        | "stream_crc_defined_flag"
        | "folder_stream_counts"
        | "file_count_metadata" => return seven_zip_metadata_target_not_materialized(py, target),
        _ => {}
    }
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => return seven_zip_atomic_status(py, "skipped", target, "7z", "", &message, &[], &[], &[], 0.0, &[], &[]),
    };
    match target {
        "trailing_junk" => seven_zip_repair_boundary_target(py, &data, workspace, target, false, max_candidates),
        "carrier_prefix" => seven_zip_repair_boundary_target(py, &data, workspace, target, true, max_candidates),
        "signature_header_version" => seven_zip_repair_signature_header_version(py, &data, workspace, target),
        "start_header_crc" => seven_zip_repair_crc_target(py, &data, workspace, target),
        "next_header_crc" => seven_zip_repair_crc_target(py, &data, workspace, target),
        "next_header_offset" => seven_zip_repair_next_header_target(py, &data, workspace, target, max_scan_bytes),
        "next_header_size" => seven_zip_repair_next_header_target(py, &data, workspace, target, max_scan_bytes),
        "next_header_repoint" => seven_zip_repair_next_header_target(py, &data, workspace, target, max_scan_bytes),
        "pack_stream_offset"
        | "pack_stream_size"
        | "stream_crc"
        | "encoded_header_decode"
        | "encoded_header_stream_crc"
        | "folder_bind_pairs"
        | "empty_stream_flags" => seven_zip_repair_metadata_target(py, &data, workspace, target, extract_password(source_input).as_deref()),
        "non_solid_entries" => {
            let result = seven_zip_salvage_non_solid_entries_native(py, source_input, workspace, max_input_size_mb, max_output_size_mb, max_entries)?;
            set_seven_zip_atomic_fields(py, &result, target, &["salvaged_non_solid_entries", "source_format=7z", "output_container=7z", "partial=true", "repacked_recovered_entries_as_7z"], &["partial_recovery_remaining"])?;
            Ok(result)
        }
        "solid_prefix" => {
            let result = seven_zip_salvage_solid_prefix_native(py, source_input, workspace, max_input_size_mb, max_output_size_mb, max_entries)?;
            set_seven_zip_atomic_fields(py, &result, target, &["salvaged_solid_prefix", "source_format=7z", "output_container=7z", "partial=true", "repacked_recovered_entries_as_7z"], &["partial_recovery_remaining"])?;
            Ok(result)
        }
        _ => seven_zip_atomic_status(py, "target_mismatch", target, "7z", "", "unsupported 7z atomic repair target", &[], &[], &[], 0.0, &[], &[]),
    }
}
fn seven_zip_repair_metadata_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
    password: Option<&str>,
) -> PyResult<Py<PyDict>> {
    let offset = if data.starts_with(SEVEN_Z_MAGIC) {
        0
    } else if data.windows(SEVEN_Z_MAGIC.len()).any(|window| window == SEVEN_Z_MAGIC) {
        1
    } else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z signature was not found", &[], &[], &[], 0.0, &["seven_zip_signature_missing"], &[]);
    };
    if offset != 0 {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z metadata writer requires the current source to start at the 7z signature", &[], &[], &[], 0.0, &["carrier_prefix_remaining"], &[]);
    }
    let Some(header) = parse_seven_zip_header(data, offset) else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z start header could not be parsed", &[], &[], &[], 0.0, &["start_header_unreadable"], &[]);
    };
    if target == "encoded_header_decode" {
        return seven_zip_repair_encoded_header_decode_target(py, data, workspace, &header, target, password);
    }
    if target == "folder_bind_pairs" && header.next_header_nid == SZ_ENCODED_HEADER {
        return match seven_zip_repair_encoded_header_folder_bind_pairs(py, data, workspace, &header, target) {
            Ok(result) => Ok(result),
            Err(message) => seven_zip_atomic_status(
                py,
                "unrepairable",
                target,
                "7z",
                "",
                &message,
                &[],
                &[],
                &[],
                0.0,
                &["folder_bind_pairs_not_repairable"],
                &[],
            ),
        };
    }
    if header.next_header_nid == SZ_ENCODED_HEADER && matches!(target, "pack_stream_offset" | "pack_stream_size") {
        match seven_zip_repair_encoded_header_pack_target(py, data, workspace, &header, target) {
            Ok(result) => return Ok(result),
            Err(message) => {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    &message,
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["encoded_header_pack_info_unrepairable"],
                    &[],
                );
            }
        }
    }
    let ast = match if target == "encoded_header_stream_crc" {
        parse_seven_zip_encoded_header_ast(data, &header)
    } else {
        parse_seven_zip_header_ast(data, &header)
    } {
        Ok(ast) => ast,
        Err(message) => {
            return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &message, &[], &[], &[], 0.0, &["seven_zip_header_graph_unparsed"], &[]);
        }
    };
    let Some(pack) = ast.pack_info.as_ref() else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z Header graph does not contain PackInfo metadata for this target", &[], &[], &[], 0.0, &["pack_info_missing"], &[]);
    };
    let (new_header, patch_fact, action, detail_fact) = match target {
        "pack_stream_offset" => {
            if pack.pack_pos.value == 0 {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z PackInfo offset is already canonical", &[], &[], &[], 0.0, &["pack_stream_offset_already_valid"], &[]);
            }
            (
                replace_header_vint(&ast.header, pack.pack_pos, 0),
                "fixed_field=pack_stream_offset",
                "repair_7z_pack_stream_offset",
                "pack_stream_offset_inferred_from_start_header",
            )
        }
        "pack_stream_size" => {
            if pack.num_streams != 1 || pack.sizes.len() != 1 {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z PackSizes repair requires exactly one pack stream", &[], &[], &[], 0.0, &["pack_stream_size_not_unique"], &[]);
            }
            let expected = header
                .next_header_offset
                .checked_sub(pack.pack_pos.value)
                .unwrap_or(0);
            if expected == 0 || expected == pack.sizes[0].value {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z PackSizes value is already valid or cannot be inferred", &[], &[], &[], 0.0, &["pack_stream_size_not_inferable"], &[]);
            }
            (
                replace_header_vint(&ast.header, pack.sizes[0], expected),
                "fixed_field=pack_stream_size",
                "repair_7z_pack_stream_size",
                "pack_stream_size_inferred_from_next_header_offset",
            )
        }
        "stream_crc" => {
            if pack.num_streams != 1 || pack.sizes.len() != 1 || pack.crc_values.len() != 1 || !pack.crc_defined_all {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z stream CRC repair requires one defined pack stream CRC", &[], &[], &[], 0.0, &["stream_crc_not_unique"], &[]);
            }
            let stream_start = SEVEN_Z_HEADER_SIZE
                .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                .unwrap_or(usize::MAX);
            let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
            let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
            if stream_start < SEVEN_Z_HEADER_SIZE || stream_end > data.len() || stream_end > header.next_header_start {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z stream CRC repair cannot read a unique pack stream range", &[], &[], &[], 0.0, &["stream_range_invalid"], &[]);
            }
            let computed = crc32(&data[stream_start..stream_end]);
            if computed == pack.crc_values[0].value {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z stream CRC metadata already matches payload", &[], &[], &[], 0.0, &["stream_crc_already_valid"], &[]);
            }
            (
                replace_header_u32_le(&ast.header, pack.crc_values[0].start, computed),
                "fixed_field=stream_crc",
                "repair_7z_stream_crc",
                "stream_crc_recomputed_from_payload",
            )
        }
        "encoded_header_stream_crc" => {
            if header.next_header_nid != SZ_ENCODED_HEADER {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EncodedHeader stream CRC target requires an EncodedHeader", &[], &[], &[], 0.0, &["encoded_header_absent"], &[]);
            }
            if pack.num_streams != 1 || pack.sizes.len() != 1 || pack.crc_values.len() != 1 || !pack.crc_defined_all {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EncodedHeader stream CRC repair requires one defined pack stream CRC", &[], &[], &[], 0.0, &["encoded_header_stream_crc_not_unique"], &[]);
            }
            let stream_start = SEVEN_Z_HEADER_SIZE
                .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                .unwrap_or(usize::MAX);
            let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
            let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
            if stream_start < SEVEN_Z_HEADER_SIZE || stream_end > data.len() || stream_end > header.next_header_start {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EncodedHeader stream CRC repair cannot read a unique pack stream range", &[], &[], &[], 0.0, &["encoded_header_stream_range_invalid"], &[]);
            }
            let computed = crc32(&data[stream_start..stream_end]);
            if computed == pack.crc_values[0].value {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EncodedHeader stream CRC metadata already matches payload", &[], &[], &[], 0.0, &["encoded_header_stream_crc_already_valid"], &[]);
            }
            (
                replace_header_u32_le(&ast.header, pack.crc_values[0].start, computed),
                "fixed_field=encoded_header_stream_crc",
                "repair_7z_encoded_header_stream_crc",
                "encoded_header_stream_crc_recomputed_from_payload",
            )
        }
        "empty_stream_flags" => {
            let Some(files) = ast.files_info.as_ref() else {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z FilesInfo is missing for EmptyStream flag repair", &[], &[], &[], 0.0, &["files_info_missing"], &[]);
            };
            let expected = (usize::try_from(files.num_files.value).unwrap_or(usize::MAX) + 7) / 8;
            let Some((start, end)) = files.empty_stream_property else {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EmptyStream property is absent", &[], &[], &[], 0.0, &["empty_stream_flags_absent"], &[]);
            };
            if end.saturating_sub(start) == expected {
                return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EmptyStream flag length is already valid", &[], &[], &[], 0.0, &["empty_stream_flags_already_valid"], &[]);
            }
            return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z EmptyStream value repair needs unique file-to-stream mapping; length-only evidence is not sufficient", &[], &[], &[], 0.0, &["empty_stream_flags_not_unique"], &[]);
        }
        _ => return seven_zip_metadata_target_not_materialized(py, target),
    };
    seven_zip_materialize_header_graph_patch(
        py,
        data,
        workspace,
        &header,
        target,
        &new_header,
        action,
        patch_fact,
        detail_fact,
    )
}

fn seven_zip_repair_encoded_header_pack_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    header: &SevenZipHeader,
    target: &str,
) -> Result<Py<PyDict>, String> {
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z encoded header range is invalid".to_string())?;
    let (pack_pos, num_streams, after_num_streams) = parse_seven_zip_encoded_pack_prefix(raw)?;
    if num_streams.value != 1 {
        return Err("7z EncodedHeader PackInfo repair requires exactly one pack stream".to_string());
    }
    match target {
        "pack_stream_offset" => {
            let mut pos = 2usize;
            let pack = match parse_seven_zip_pack_info(raw, &mut pos) {
                Ok(pack) => pack,
                Err(message) => return Err(format!("7z EncodedHeader PackInfo offset needs parseable PackSizes: {message}")),
            };
            if pack.sizes.len() != 1 {
                return Err("7z EncodedHeader PackInfo offset repair requires one PackSize".to_string());
            }
            let expected = header
                .next_header_offset
                .checked_sub(pack.sizes[0].value)
                .ok_or_else(|| "7z EncodedHeader PackInfo offset cannot be inferred".to_string())?;
            if pack.pack_pos.value == expected {
                return Err("7z EncodedHeader PackInfo offset is already valid".to_string());
            }
            let new_header = replace_header_vint(raw, pack.pack_pos, expected);
            seven_zip_materialize_header_graph_patch(
                py,
                data,
                workspace,
                header,
                target,
                &new_header,
                "repair_7z_encoded_header_pack_stream_offset",
                "fixed_field=pack_stream_offset",
                "encoded_header_pack_stream_offset_inferred_from_pack_size_and_next_header",
            )
            .map_err(|err| err.to_string())
        }
        "pack_stream_size" => {
            let expected = header
                .next_header_offset
                .checked_sub(pack_pos.value)
                .ok_or_else(|| "7z EncodedHeader PackSize cannot be inferred".to_string())?;
            if expected == 0 {
                return Err("7z EncodedHeader PackSize cannot be inferred".to_string());
            }
            let mut property_end = None;
            if raw.get(after_num_streams).copied() == Some(SZ_SIZE) {
                let mut pos = after_num_streams + 1;
                let current = read_sz_vint(raw, &mut pos)
                    .ok_or_else(|| "7z EncodedHeader PackSize value is truncated".to_string())?;
                if current.value == expected {
                    return Err("7z EncodedHeader PackSize value is already valid".to_string());
                }
                property_end = Some(pos);
            } else {
                let scan_end = raw.len().min(after_num_streams.saturating_add(48));
                for index in after_num_streams + 1..scan_end {
                    if matches!(raw[index], SZ_CRC | SZ_UNPACK_INFO | SZ_SUB_STREAMS_INFO | SZ_END) {
                        property_end = Some(index);
                        break;
                    }
                }
            }
            let property_end = property_end.ok_or_else(|| "7z EncodedHeader PackSize boundary is not unique".to_string())?;
            let mut replacement = vec![SZ_SIZE];
            replacement.extend_from_slice(&write_sz_vint(expected));
            let new_header = replace_header_range(raw, after_num_streams, property_end, &replacement);
            seven_zip_materialize_header_graph_patch(
                py,
                data,
                workspace,
                header,
                target,
                &new_header,
                "repair_7z_encoded_header_pack_stream_size",
                "fixed_field=pack_stream_size",
                "encoded_header_pack_size_inferred_from_next_header_offset",
            )
            .map_err(|err| err.to_string())
        }
        _ => Err("unsupported EncodedHeader PackInfo target".to_string()),
    }
}

fn seven_zip_encoded_header_folder_bind_pairs_patch(raw: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_ENCODED_HEADER) {
        return Err("7z EncodedHeader NID is missing".to_string());
    }
    pos += 1;
    loop {
        let Some(nid) = raw.get(pos).copied() else {
            return Err("7z EncodedHeader tree is truncated".to_string());
        };
        pos += 1;
        match nid {
            SZ_END => break,
            SZ_PACK_INFO => {
                parse_seven_zip_pack_info(raw, &mut pos)
                    .map_err(|message| format!("7z EncodedHeader PackInfo is not parseable: {message}"))?;
            }
            SZ_UNPACK_INFO => loop {
                let Some(unpack_nid) = raw.get(pos).copied() else {
                    return Err("7z EncodedHeader UnpackInfo is truncated".to_string());
                };
                pos += 1;
                match unpack_nid {
                    SZ_END => break,
                    SZ_FOLDER => {
                        let num_folders = read_sz_vint(raw, &mut pos)
                            .ok_or_else(|| "7z EncodedHeader Folder count is truncated".to_string())?
                            .value;
                        if num_folders != 1 {
                            return Err("7z folder bind pair repair requires exactly one folder".to_string());
                        }
                        let external = *raw
                            .get(pos)
                            .ok_or_else(|| "7z EncodedHeader Folder external flag is missing".to_string())?;
                        pos += 1;
                        if external != 0 {
                            return Err("7z external Folder graph is not supported".to_string());
                        }
                        let num_coders = usize::try_from(
                            read_sz_vint(raw, &mut pos)
                                .ok_or_else(|| "7z EncodedHeader coder count is truncated".to_string())?
                                .value,
                        )
                        .map_err(|_| "7z EncodedHeader coder count is too large".to_string())?;
                        if num_coders < 2 || num_coders > 8 {
                            return Err("7z folder bind pair repair requires a small multi-coder folder".to_string());
                        }
                        let mut total_in = 0u64;
                        let mut total_out = 0u64;
                        for _ in 0..num_coders {
                            let flags = *raw
                                .get(pos)
                                .ok_or_else(|| "7z EncodedHeader coder flags are missing".to_string())?;
                            pos += 1;
                            let id_size = usize::from(flags & 0x0f);
                            if id_size == 0 || pos + id_size > raw.len() {
                                return Err("7z EncodedHeader coder id is truncated".to_string());
                            }
                            pos += id_size;
                            let (num_in_streams, num_out_streams) = if flags & 0x10 != 0 {
                                let in_streams = read_sz_vint(raw, &mut pos)
                                    .ok_or_else(|| "7z EncodedHeader coder input stream count is truncated".to_string())?
                                    .value;
                                let out_streams = read_sz_vint(raw, &mut pos)
                                    .ok_or_else(|| "7z EncodedHeader coder output stream count is truncated".to_string())?
                                    .value;
                                (in_streams, out_streams)
                            } else {
                                (1, 1)
                            };
                            if num_in_streams != 1 || num_out_streams != 1 {
                                return Err("7z folder bind pair repair only supports single-stream coder chains".to_string());
                            }
                            total_in = total_in.saturating_add(num_in_streams);
                            total_out = total_out.saturating_add(num_out_streams);
                            if flags & 0x20 != 0 {
                                let prop_size = usize::try_from(
                                    read_sz_vint(raw, &mut pos)
                                        .ok_or_else(|| "7z EncodedHeader coder properties size is truncated".to_string())?
                                        .value,
                                )
                                .unwrap_or(usize::MAX);
                                if pos + prop_size > raw.len() {
                                    return Err("7z EncodedHeader coder properties are truncated".to_string());
                                }
                                pos += prop_size;
                            }
                            if flags & 0x80 != 0 {
                                return Err("7z alternative coder methods are not supported".to_string());
                            }
                        }
                        let bind_pair_count = usize::try_from(total_out.saturating_sub(1))
                            .map_err(|_| "7z bind pair count is too large".to_string())?;
                        if bind_pair_count + 1 != num_coders || total_in != total_out {
                            return Err("7z folder bind pair repair requires a linear coder chain".to_string());
                        }
                        let mut replacements: Vec<(usize, usize, Vec<u8>)> = Vec::new();
                        for index in 0..bind_pair_count {
                            let in_span = read_sz_vint(raw, &mut pos)
                                .ok_or_else(|| "7z bind pair input index is truncated".to_string())?;
                            let out_span = read_sz_vint(raw, &mut pos)
                                .ok_or_else(|| "7z bind pair output index is truncated".to_string())?;
                            let expected_in = u64::try_from(index + 1).unwrap_or(u64::MAX);
                            let expected_out = u64::try_from(index).unwrap_or(u64::MAX);
                            if in_span.value != expected_in {
                                replacements.push((in_span.start, in_span.end, write_sz_vint(expected_in)));
                            }
                            if out_span.value != expected_out {
                                replacements.push((out_span.start, out_span.end, write_sz_vint(expected_out)));
                            }
                        }
                        let packed_streams = total_in.saturating_sub(u64::try_from(bind_pair_count).unwrap_or(0));
                        if packed_streams != 1 {
                            return Err("7z folder bind pair repair requires a unique packed stream".to_string());
                        }
                        if replacements.is_empty() {
                            return Ok(None);
                        }
                        replacements.sort_by(|a, b| b.0.cmp(&a.0));
                        let mut patched = raw.to_vec();
                        for (start, end, bytes) in replacements {
                            patched.splice(start..end, bytes);
                        }
                        return Ok(Some(patched));
                    }
                    SZ_CODERS_UNPACK_SIZE => {
                        read_sz_vint(raw, &mut pos)
                            .ok_or_else(|| "7z EncodedHeader unpack size is truncated".to_string())?;
                    }
                    SZ_CRC => {
                        let defined = parse_seven_zip_bool_vector(raw, &mut pos, 1)
                            .map_err(|message| format!("7z EncodedHeader CRC bitset is not parseable: {message}"))?;
                        for is_defined in defined {
                            if is_defined {
                                if pos + 4 > raw.len() {
                                    return Err("7z EncodedHeader CRC value is truncated".to_string());
                                }
                                pos += 4;
                            }
                        }
                    }
                    _ => return Err(format!("7z EncodedHeader UnpackInfo NID 0x{unpack_nid:02x} is unsupported for bind pair repair")),
                }
            },
            SZ_SUB_STREAMS_INFO => skip_seven_zip_unhandled_property_tree(raw, &mut pos, "EncodedHeader SubStreamsInfo")?,
            _ => return Err(format!("7z EncodedHeader StreamsInfo NID 0x{nid:02x} is unsupported for bind pair repair")),
        }
    }
    Err("7z EncodedHeader Folder graph was not found".to_string())
}

fn seven_zip_repair_encoded_header_folder_bind_pairs(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    header: &SevenZipHeader,
    target: &str,
) -> Result<Py<PyDict>, String> {
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z encoded header range is invalid".to_string())?;
    let Some(new_header) = seven_zip_encoded_header_folder_bind_pairs_patch(raw)? else {
        return Err("7z folder bind pairs are already canonical".to_string());
    };
    seven_zip_materialize_header_graph_patch(
        py,
        data,
        workspace,
        header,
        target,
        &new_header,
        "repair_7z_folder_bind_pairs",
        "fixed_field=folder_bind_pairs",
        "folder_bind_pairs_canonicalized",
    )
    .map_err(|err| err.to_string())
}

fn seven_zip_repair_encoded_header_decode_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    header: &SevenZipHeader,
    target: &str,
    password: Option<&str>,
) -> PyResult<Py<PyDict>> {
    if header.next_header_nid != SZ_ENCODED_HEADER {
        return seven_zip_atomic_status(
            py,
            "unrepairable",
            target,
            "7z",
            "",
            "7z EncodedHeader decode target requires an EncodedHeader",
            &[],
            &[],
            &[],
            0.0,
            &["encoded_header_absent"],
            &[],
        );
    }
    let decoded = match decode_seven_zip_encoded_header_payload(data, header, password) {
        Ok(decoded) => decoded,
        Err(reason) => {
            let residual = if reason.contains("password") {
                if password.is_some() {
                    "encoded_header_decode_password_rejected"
                } else {
                    "encoded_header_decode_password_required"
                }
            } else if reason.contains("unsupported") {
                "encoded_header_decoder_unsupported_method"
            } else if reason.contains("crc") {
                "encoded_header_payload_crc_bad"
            } else {
                "encoded_header_ast_write_failed"
            };
            return seven_zip_atomic_status(
                py,
                "unrepairable",
                target,
                "7z",
                "",
                &format!("7z EncodedHeader could not be decoded: {reason}"),
                &[],
                &[],
                &[],
                0.0,
                &[residual],
                &[],
            );
        }
    };
    seven_zip_materialize_header_graph_patch(
        py,
        data,
        workspace,
        header,
        target,
        &decoded,
        "decode_7z_encoded_header",
        "fixed_field=encoded_header_representation",
        "decoded_encoded_header",
    )
}

fn seven_zip_materialize_header_graph_patch(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    header: &SevenZipHeader,
    target: &str,
    new_header: &[u8],
    action: &str,
    patch_fact: &str,
    detail_fact: &str,
) -> PyResult<Py<PyDict>> {
    let next_header_crc = crc32(new_header);
    let next_header_size = new_header.len() as u64;
    let mut candidate = Vec::with_capacity(data.len() + new_header.len());
    candidate.extend_from_slice(&data[..header.next_header_start]);
    candidate.extend_from_slice(new_header);
    candidate.extend_from_slice(&data[header.archive_end..]);
    candidate[20..28].copy_from_slice(&next_header_size.to_le_bytes());
    candidate[28..32].copy_from_slice(&next_header_crc.to_le_bytes());
    let mut start_header = [0u8; 20];
    start_header.copy_from_slice(&candidate[12..32]);
    let start_crc = crc32(&start_header);
    candidate[8..12].copy_from_slice(&start_crc.to_le_bytes());
    let output_path = Path::new(workspace).join(format!("seven_zip_{target}.7z"));
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &format!("7z header graph patch could not be written: {err}"), &[], &[], &[], 0.0, &[], &[]),
    };
    let selected = WrittenArchiveCandidate {
        name: target.to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "repaired".to_string(),
        offset: 0,
        end_offset: candidate.len() as u64,
        output_bytes,
        confidence: 0.88,
        actions: vec![action.to_string(), "rewrite_7z_header_graph".to_string(), "recompute_7z_next_header_crc".to_string(), "recompute_7z_start_header_crc".to_string()],
        warnings: Vec::new(),
    };
    let selected_path = selected.path.clone();
    let result = status_dict_with_candidates(
        py,
        "repaired",
        &selected_path,
        "7z",
        "7z header graph metadata was repaired",
        &[],
        0,
        candidate.len() as u64,
        output_bytes,
        0.88,
        &[action, "rewrite_7z_header_graph", "recompute_7z_next_header_crc", "recompute_7z_start_header_crc"],
        &[selected],
    )?;
    set_seven_zip_atomic_fields(
        py,
        &result,
        target,
        &[patch_fact, detail_fact, "rewrote_7z_header_graph_ast", "updated_next_header_crc", "updated_start_header_crc", "source_format=7z"],
        &[],
    )?;
    Ok(result)
}

fn seven_zip_metadata_target_not_materialized(
    py: Python<'_>,
    target: &str,
) -> PyResult<Py<PyDict>> {
    let reason = match target {
        "encoded_header_decode" => "7z encoded header decode requires a decoded header writer",
        "encoded_header_stream_crc" => "7z encoded header stream CRC repair requires parsed stream metadata",
        "pack_stream_offset" => "7z PackInfo offset repair requires parsed pack stream metadata",
        "pack_stream_size" => "7z PackSizes repair requires parsed pack stream metadata",
        "unpack_size" => "7z UnpackSize repair requires parsed folder/substream metadata",
        "stream_crc" => "7z stream CRC repair requires verified decoded stream payloads",
        "bad_folder_quarantine" => "7z folder quarantine requires folder-level decode verification",
        "empty_stream_flags" => "7z empty stream flag repair requires parsed file table metadata",
        "folder_bind_pairs" => "7z folder bind pair repair requires parsed folder graph metadata",
        "folder_stream_counts" => "7z folder stream count repair requires parsed folder graph metadata",
        "file_count_metadata" => "7z file count repair requires parsed file table metadata",
        "file_names_utf16" => "7z UTF-16 filename repair requires parsed Names property graph metadata",
        "unreferenced_folder" => "7z unreferenced folder drop requires parsed folder-to-file graph metadata",
        "unreferenced_file_record" => "7z unreferenced file record drop requires parsed file-to-stream graph metadata",
        "stream_crc_defined_flag" => "7z CRC defined flag repair requires parsed CRC bitset and stream map metadata",
        _ => "unsupported 7z metadata repair target",
    };
    seven_zip_atomic_status(
        py,
        "unrepairable",
        target,
        "7z",
        "",
        reason,
        &[],
        &[],
        &[],
        0.0,
        &["seven_zip_metadata_writer_missing"],
        &[],
    )
}
