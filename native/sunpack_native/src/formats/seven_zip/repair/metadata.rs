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
        | "file_count_metadata" => return seven_zip_metadata_target_not_materialized(py, target),
        _ => {}
    }
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return seven_zip_atomic_status(
                py,
                "skipped",
                target,
                "7z",
                "",
                &message,
                &[],
                &[],
                &[],
                0.0,
                &[],
                &[],
            )
        }
    };
    match target {
        "trailing_junk" => {
            seven_zip_repair_boundary_target(py, &data, workspace, target, false, max_candidates)
        }
        "carrier_prefix" => {
            seven_zip_repair_boundary_target(py, &data, workspace, target, true, max_candidates)
        }
        "signature_header_version" => {
            seven_zip_repair_signature_header_version(py, &data, workspace, target)
        }
        "start_header_crc" => seven_zip_repair_crc_target(py, &data, workspace, target),
        "next_header_crc" => seven_zip_repair_crc_target(py, &data, workspace, target),
        "next_header_offset" => {
            seven_zip_repair_next_header_target(py, &data, workspace, target, max_scan_bytes)
        }
        "next_header_size" => {
            seven_zip_repair_next_header_target(py, &data, workspace, target, max_scan_bytes)
        }
        "next_header_repoint" => {
            seven_zip_repair_next_header_target(py, &data, workspace, target, max_scan_bytes)
        }
        "pack_stream_offset"
        | "pack_stream_size"
        | "stream_crc"
        | "header_end_marker"
        | "encoded_header_decode"
        | "encoded_header_coder_properties"
        | "encoded_header_stream_crc"
        | "folder_bind_pairs"
        | "folder_stream_counts"
        | "empty_stream_flags" => seven_zip_repair_metadata_target(
            py,
            &data,
            workspace,
            target,
            extract_password(source_input).as_deref(),
        ),
        "non_solid_entries" => {
            let result = seven_zip_salvage_non_solid_entries_native(
                py,
                source_input,
                workspace,
                max_input_size_mb,
                max_output_size_mb,
                max_entries,
            )?;
            set_seven_zip_atomic_fields(
                py,
                &result,
                target,
                &[
                    "salvaged_non_solid_entries",
                    "source_format=7z",
                    "output_container=7z",
                    "partial=true",
                    "repacked_recovered_entries_as_7z",
                ],
                &["partial_recovery_remaining"],
            )?;
            Ok(result)
        }
        "solid_prefix" => {
            let result = seven_zip_salvage_solid_prefix_native(
                py,
                source_input,
                workspace,
                max_input_size_mb,
                max_output_size_mb,
                max_entries,
            )?;
            set_seven_zip_atomic_fields(
                py,
                &result,
                target,
                &[
                    "salvaged_solid_prefix",
                    "source_format=7z",
                    "output_container=7z",
                    "partial=true",
                    "repacked_recovered_entries_as_7z",
                ],
                &["partial_recovery_remaining"],
            )?;
            Ok(result)
        }
        _ => seven_zip_atomic_status(
            py,
            "target_mismatch",
            target,
            "7z",
            "",
            "unsupported 7z atomic repair target",
            &[],
            &[],
            &[],
            0.0,
            &[],
            &[],
        ),
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
    } else if data
        .windows(SEVEN_Z_MAGIC.len())
        .any(|window| window == SEVEN_Z_MAGIC)
    {
        1
    } else {
        return seven_zip_atomic_status(
            py,
            "unrepairable",
            target,
            "7z",
            "",
            "7z signature was not found",
            &[],
            &[],
            &[],
            0.0,
            &["seven_zip_signature_missing"],
            &[],
        );
    };
    if offset != 0 {
        return seven_zip_atomic_status(
            py,
            "unrepairable",
            target,
            "7z",
            "",
            "7z metadata writer requires the current source to start at the 7z signature",
            &[],
            &[],
            &[],
            0.0,
            &["carrier_prefix_remaining"],
            &[],
        );
    }
    let Some(header) = parse_seven_zip_header(data, offset) else {
        return seven_zip_atomic_status(
            py,
            "unrepairable",
            target,
            "7z",
            "",
            "7z start header could not be parsed",
            &[],
            &[],
            &[],
            0.0,
            &["start_header_unreadable"],
            &[],
        );
    };
    if target == "encoded_header_decode" {
        return seven_zip_repair_encoded_header_decode_target(
            py, data, workspace, &header, target, password,
        );
    }
    if target == "header_end_marker" {
        return seven_zip_repair_header_end_marker(py, data, workspace, &header, target);
    }
    if target == "encoded_header_coder_properties" && header.next_header_nid == SZ_ENCODED_HEADER {
        return match seven_zip_repair_encoded_header_coder_properties(
            py, data, workspace, &header, target, password,
        ) {
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
                &["encoded_header_coder_properties_not_repairable"],
                &[],
            ),
        };
    }
    if target == "folder_bind_pairs" && header.next_header_nid == SZ_ENCODED_HEADER {
        return match seven_zip_repair_encoded_header_folder_bind_pairs(
            py, data, workspace, &header, target,
        ) {
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
    if target == "folder_stream_counts" && header.next_header_nid == SZ_ENCODED_HEADER {
        return match seven_zip_repair_encoded_header_folder_stream_counts(
            py, data, workspace, &header, target,
        ) {
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
                &["folder_stream_counts_not_repairable"],
                &[],
            ),
        };
    }
    if header.next_header_nid == SZ_ENCODED_HEADER
        && matches!(target, "pack_stream_offset" | "pack_stream_size")
    {
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
                &["seven_zip_header_graph_unparsed"],
                &[],
            );
        }
    };
    let pack_target = matches!(
        target,
        "pack_stream_offset" | "pack_stream_size" | "stream_crc" | "encoded_header_stream_crc"
    );
    if pack_target && ast.pack_info.is_none() {
        return seven_zip_atomic_status(
            py,
            "unrepairable",
            target,
            "7z",
            "",
            "7z Header graph does not contain PackInfo metadata for this target",
            &[],
            &[],
            &[],
            0.0,
            &["pack_info_missing"],
            &[],
        );
    }
    let pack = ast.pack_info.as_ref();
    let (new_header, patch_fact, action, detail_fact) = match target {
        "pack_stream_offset" => {
            let pack = pack.expect("pack target was validated above");
            if pack.pack_pos.value == 0 {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z PackInfo offset is already canonical",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["pack_stream_offset_already_valid"],
                    &[],
                );
            }
            (
                replace_header_vint(&ast.header, pack.pack_pos, 0),
                "fixed_field=pack_stream_offset",
                "repair_7z_pack_stream_offset",
                "pack_stream_offset_inferred_from_start_header",
            )
        }
        "pack_stream_size" => {
            let pack = pack.expect("pack target was validated above");
            if pack.num_streams != 1 || pack.sizes.len() != 1 {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z PackSizes repair requires exactly one pack stream",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["pack_stream_size_not_unique"],
                    &[],
                );
            }
            let expected = header
                .next_header_offset
                .checked_sub(pack.pack_pos.value)
                .unwrap_or(0);
            if expected == 0 || expected == pack.sizes[0].value {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z PackSizes value is already valid or cannot be inferred",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["pack_stream_size_not_inferable"],
                    &[],
                );
            }
            (
                replace_header_vint(&ast.header, pack.sizes[0], expected),
                "fixed_field=pack_stream_size",
                "repair_7z_pack_stream_size",
                "pack_stream_size_inferred_from_next_header_offset",
            )
        }
        "stream_crc" => {
            let pack = pack.expect("pack target was validated above");
            if pack.num_streams != 1
                || pack.sizes.len() != 1
                || pack.crc_values.len() != 1
                || !pack.crc_defined_all
            {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z stream CRC repair requires one defined pack stream CRC",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["stream_crc_not_unique"],
                    &[],
                );
            }
            let stream_start = SEVEN_Z_HEADER_SIZE
                .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                .unwrap_or(usize::MAX);
            let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
            let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
            if stream_start < SEVEN_Z_HEADER_SIZE
                || stream_end > data.len()
                || stream_end > header.next_header_start
            {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z stream CRC repair cannot read a unique pack stream range",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["stream_range_invalid"],
                    &[],
                );
            }
            let computed = crc32(&data[stream_start..stream_end]);
            if computed == pack.crc_values[0].value {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z stream CRC metadata already matches payload",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["stream_crc_already_valid"],
                    &[],
                );
            }
            (
                replace_header_u32_le(&ast.header, pack.crc_values[0].start, computed),
                "fixed_field=stream_crc",
                "repair_7z_stream_crc",
                "stream_crc_recomputed_from_payload",
            )
        }
        "encoded_header_stream_crc" => {
            let pack = pack.expect("pack target was validated above");
            if header.next_header_nid != SZ_ENCODED_HEADER {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z EncodedHeader stream CRC target requires an EncodedHeader",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["encoded_header_absent"],
                    &[],
                );
            }
            if pack.num_streams != 1
                || pack.sizes.len() != 1
                || pack.crc_values.len() != 1
                || !pack.crc_defined_all
            {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z EncodedHeader stream CRC repair requires one defined pack stream CRC",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["encoded_header_stream_crc_not_unique"],
                    &[],
                );
            }
            let stream_start = SEVEN_Z_HEADER_SIZE
                .checked_add(usize::try_from(pack.pack_pos.value).unwrap_or(usize::MAX))
                .unwrap_or(usize::MAX);
            let stream_size = usize::try_from(pack.sizes[0].value).unwrap_or(usize::MAX);
            let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
            if stream_start < SEVEN_Z_HEADER_SIZE
                || stream_end > data.len()
                || stream_end > header.next_header_start
            {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z EncodedHeader stream CRC repair cannot read a unique pack stream range",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["encoded_header_stream_range_invalid"],
                    &[],
                );
            }
            let computed = crc32(&data[stream_start..stream_end]);
            if computed == pack.crc_values[0].value {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z EncodedHeader stream CRC metadata already matches payload",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["encoded_header_stream_crc_already_valid"],
                    &[],
                );
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
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z FilesInfo is missing for EmptyStream flag repair",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["files_info_missing"],
                    &[],
                );
            };
            let expected = (usize::try_from(files.num_files.value).unwrap_or(usize::MAX) + 7) / 8;
            let Some((start, end)) = files.empty_stream_property else {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z EmptyStream property is absent",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["empty_stream_flags_absent"],
                    &[],
                );
            };
            if end.saturating_sub(start) == expected {
                return seven_zip_atomic_status(
                    py,
                    "unrepairable",
                    target,
                    "7z",
                    "",
                    "7z EmptyStream flag length is already valid",
                    &[],
                    &[],
                    &[],
                    0.0,
                    &["empty_stream_flags_already_valid"],
                    &[],
                );
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
    if target == "pack_stream_offset" && num_streams.value != 1 {
        if let Some((new_header, expected_offset)) =
            repair_encoded_header_pack_offset_by_tail_resync(raw, header)?
        {
            return seven_zip_materialize_header_graph_patch(
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
            .map_err(|err| {
                format!(
                    "{err}; resynced encoded header pack stream offset candidate={expected_offset}"
                )
            });
        }
    }
    if num_streams.value != 1 {
        return Err(
            "7z EncodedHeader PackInfo repair requires exactly one pack stream".to_string(),
        );
    }
    match target {
        "pack_stream_offset" => {
            let mut pos = 2usize;
            let pack = match parse_seven_zip_pack_info(raw, &mut pos) {
                Ok(pack) => pack,
                Err(message) => {
                    return Err(format!(
                        "7z EncodedHeader PackInfo offset needs parseable PackSizes: {message}"
                    ))
                }
            };
            if pack.sizes.len() != 1 {
                return Err(
                    "7z EncodedHeader PackInfo offset repair requires one PackSize".to_string(),
                );
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
                    if matches!(
                        raw[index],
                        SZ_CRC | SZ_UNPACK_INFO | SZ_SUB_STREAMS_INFO | SZ_END
                    ) {
                        property_end = Some(index);
                        break;
                    }
                }
            }
            let property_end = property_end
                .ok_or_else(|| "7z EncodedHeader PackSize boundary is not unique".to_string())?;
            let mut replacement = vec![SZ_SIZE];
            replacement.extend_from_slice(&write_sz_vint(expected));
            let new_header =
                replace_header_range(raw, after_num_streams, property_end, &replacement);
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

fn seven_zip_repair_header_end_marker(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    header: &SevenZipHeader,
    target: &str,
) -> PyResult<Py<PyDict>> {
    let Some(raw) = data.get(header.next_header_start..header.archive_end) else {
        return seven_zip_atomic_status(
            py,
            "unrepairable",
            target,
            "7z",
            "",
            "7z next header range is invalid",
            &[],
            &[],
            &[],
            0.0,
            &["header_end_marker_range_invalid"],
            &[],
        );
    };
    if raw.is_empty() {
        return seven_zip_atomic_status(
            py,
            "unrepairable",
            target,
            "7z",
            "",
            "7z header end marker repair requires a non-empty next header",
            &[],
            &[],
            &[],
            0.0,
            &["header_end_marker_absent"],
            &[],
        );
    }
    if raw.last().copied() == Some(SZ_END) {
        return seven_zip_atomic_status(
            py,
            "unrepairable",
            target,
            "7z",
            "",
            "7z header end marker is already canonical",
            &[],
            &[],
            &[],
            0.0,
            &["header_end_marker_already_valid"],
            &[],
        );
    }
    let mut new_header = raw.to_vec();
    if let Some(last) = new_header.last_mut() {
        *last = SZ_END;
    }
    seven_zip_materialize_header_graph_patch(
        py,
        data,
        workspace,
        header,
        target,
        &new_header,
        "repair_7z_header_end_marker",
        "fixed_field=header_end_marker",
        "header_end_marker_canonicalized",
    )
}

fn repair_encoded_header_pack_offset_by_tail_resync(
    raw: &[u8],
    header: &SevenZipHeader,
) -> Result<Option<(Vec<u8>, u64)>, String> {
    let mut candidates: Vec<(Vec<u8>, u64)> = Vec::new();
    let max_pack_pos_end = raw.len().min(11);
    for pack_pos_end in 3..=max_pack_pos_end {
        let mut pos = pack_pos_end;
        let Some(num_streams) = read_sz_vint(raw, &mut pos) else {
            continue;
        };
        if num_streams.value != 1 {
            continue;
        }
        if raw.get(pos).copied() != Some(SZ_SIZE) {
            continue;
        }
        pos += 1;
        let Some(size) = read_sz_vint(raw, &mut pos) else {
            continue;
        };
        if !matches!(
            raw.get(pos).copied(),
            Some(SZ_END | SZ_CRC | SZ_UNPACK_INFO | SZ_SUB_STREAMS_INFO)
        ) {
            continue;
        }
        let Some(expected_offset) = header.next_header_offset.checked_sub(size.value) else {
            continue;
        };
        if expected_offset == 0 {
            continue;
        }
        let stream_start = SEVEN_Z_HEADER_SIZE
            .checked_add(usize::try_from(expected_offset).unwrap_or(usize::MAX))
            .unwrap_or(usize::MAX);
        let stream_size = usize::try_from(size.value).unwrap_or(usize::MAX);
        let stream_end = stream_start.checked_add(stream_size).unwrap_or(usize::MAX);
        if stream_start < SEVEN_Z_HEADER_SIZE
            || stream_end > raw.len().saturating_add(header.next_header_start)
            || stream_end > header.next_header_start
        {
            continue;
        }
        let replacement = write_sz_vint(expected_offset);
        if replacement.len() != pack_pos_end.saturating_sub(2) {
            continue;
        }
        if raw.get(2..pack_pos_end) == Some(replacement.as_slice()) {
            continue;
        }
        candidates.push((
            replace_header_range(raw, 2, pack_pos_end, &replacement),
            expected_offset,
        ));
    }
    if candidates.len() > 1 {
        return Err("7z EncodedHeader PackInfo offset resync is not unique".to_string());
    }
    Ok(candidates.pop())
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
                parse_seven_zip_pack_info(raw, &mut pos).map_err(|message| {
                    format!("7z EncodedHeader PackInfo is not parseable: {message}")
                })?;
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
            SZ_SUB_STREAMS_INFO => consume_empty_seven_zip_property_tree(
                raw,
                &mut pos,
                "EncodedHeader SubStreamsInfo",
            )?,
            _ => return Err(format!(
                "7z EncodedHeader StreamsInfo NID 0x{nid:02x} is unsupported for bind pair repair"
            )),
        }
    }
    Err("7z EncodedHeader Folder graph was not found".to_string())
}

fn consume_empty_seven_zip_property_tree(
    data: &[u8],
    pos: &mut usize,
    label: &str,
) -> Result<(), String> {
    match data.get(*pos).copied() {
        Some(SZ_END) => {
            *pos += 1;
            Ok(())
        }
        Some(nid) => Err(format!("7z {label} is non-empty at NID 0x{nid:02x}")),
        None => Err(format!("7z {label} ended before End NID")),
    }
}

fn encoded_header_raw_parses(raw: &[u8]) -> bool {
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_ENCODED_HEADER) {
        return false;
    }
    pos += 1;
    let mut saw_pack = false;
    let mut saw_unpack = false;
    let mut unpack_info = None;
    loop {
        let Some(nid) = raw.get(pos).copied() else {
            return false;
        };
        pos += 1;
        match nid {
            SZ_END => return saw_pack && saw_unpack,
            SZ_PACK_INFO => {
                if parse_seven_zip_pack_info(raw, &mut pos).is_err() {
                    return false;
                }
                saw_pack = true;
            }
            SZ_UNPACK_INFO => {
                let Ok(parsed) = parse_seven_zip_unpack_info(raw, &mut pos) else {
                    return false;
                };
                unpack_info = Some(parsed);
                saw_unpack = true;
            }
            SZ_SUB_STREAMS_INFO => {
                let Some(unpack) = unpack_info.as_ref() else {
                    return false;
                };
                if parse_seven_zip_substreams_info(raw, &mut pos, unpack).is_err() {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

fn seven_zip_encoded_header_folder_stream_counts_patch(
    raw: &[u8],
) -> Result<Option<Vec<u8>>, String> {
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
                        let folder_count = read_sz_vint(raw, &mut pos)
                            .ok_or_else(|| "7z EncodedHeader Folder count is truncated".to_string())?;
                        if folder_count.value != 1 {
                            let replacement = write_sz_vint(1);
                            if replacement.len() == folder_count.end.saturating_sub(folder_count.start) {
                                let patched = replace_header_range(raw, folder_count.start, folder_count.end, &replacement);
                                if encoded_header_raw_parses(&patched)
                                    || matches!(raw.get(folder_count.end).copied(), Some(0 | 1))
                                {
                                    return Ok(Some(patched));
                                }
                            }
                            return Err("7z folder stream count repair requires exactly one folder".to_string());
                        }
                        let external_pos = pos;
                        let external = *raw
                            .get(pos)
                            .ok_or_else(|| "7z EncodedHeader Folder external flag is missing".to_string())?;
                        pos += 1;
                        if external != 0 {
                            let mut patched = raw.to_vec();
                            patched[external_pos] = 0;
                            if encoded_header_raw_parses(&patched)
                                || read_sz_vint(raw, &mut pos).is_some_and(|span| span.value > 0 && span.value <= 8)
                            {
                                return Ok(Some(patched));
                            }
                            return Err("7z external Folder graph is not supported".to_string());
                        }
                        let num_coders = usize::try_from(
                            read_sz_vint(raw, &mut pos)
                                .ok_or_else(|| "7z EncodedHeader coder count is truncated".to_string())?
                                .value,
                        )
                        .map_err(|_| "7z EncodedHeader coder count is too large".to_string())?;
                        if num_coders == 0 || num_coders > 8 {
                            return Err("7z folder stream count repair requires a small coder graph".to_string());
                        }
                        let mut flag_positions = Vec::new();
                        let mut probe = pos;
                        for _ in 0..num_coders {
                            flag_positions.push(probe);
                            let flags = *raw
                                .get(probe)
                                .ok_or_else(|| "7z EncodedHeader coder flags are missing".to_string())?;
                            probe += 1;
                            let id_size = usize::from(flags & 0x0f);
                            if id_size == 0 || probe + id_size > raw.len() {
                                break;
                            }
                            probe += id_size;
                            if flags & 0x10 != 0 {
                                if read_sz_vint(raw, &mut probe).is_none() || read_sz_vint(raw, &mut probe).is_none() {
                                    break;
                                }
                            }
                            if flags & 0x20 != 0 {
                                let Some(prop_size) = read_sz_vint(raw, &mut probe) else {
                                    break;
                                };
                                let size = usize::try_from(prop_size.value).unwrap_or(usize::MAX);
                                if probe + size > raw.len() {
                                    break;
                                }
                                probe += size;
                            }
                            if flags & 0x80 != 0 {
                                break;
                            }
                        }
                        if flag_positions.is_empty() {
                            return Err("7z EncodedHeader coder flags were not found".to_string());
                        }
                        let mut candidates: Vec<(Vec<u8>, usize, u8)> = Vec::new();
                        let plausible_flags: Vec<u8> = (1u8..=8)
                            .flat_map(|id_size| [id_size, id_size | 0x20, id_size | 0x10, id_size | 0x30])
                            .collect();
                        for flag_pos in flag_positions {
                            for candidate_flag in &plausible_flags {
                                if Some(*candidate_flag) == raw.get(flag_pos).copied().as_ref().copied() {
                                    continue;
                                }
                                let mut patched = raw.to_vec();
                                patched[flag_pos] = *candidate_flag;
                                if encoded_header_raw_parses(&patched) {
                                    candidates.push((patched, flag_pos, *candidate_flag));
                                }
                            }
                        }
                        candidates.sort_by(|a, b| (a.1, a.2).cmp(&(b.1, b.2)));
                        candidates.dedup_by(|a, b| a.0 == b.0);
                        if candidates.is_empty() {
                            return Err("7z EncodedHeader coder flag repair has no parseable candidate".to_string());
                        }
                        if candidates.len() > 1 {
                            return Err("7z EncodedHeader coder flag repair is not unique".to_string());
                        }
                        let (patched, _, _) = candidates.remove(0);
                        if patched == raw {
                            return Ok(None);
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
                    _ => return Err(format!("7z EncodedHeader UnpackInfo NID 0x{unpack_nid:02x} is unsupported for folder stream count repair")),
                }
            },
            SZ_SUB_STREAMS_INFO => return Err("7z EncodedHeader repair target was not found before SubStreamsInfo".to_string()),
            _ => return Err(format!("7z EncodedHeader StreamsInfo NID 0x{nid:02x} is unsupported for folder stream count repair")),
        }
    }
    Err("7z EncodedHeader Folder graph was not found".to_string())
}

fn seven_zip_repair_encoded_header_folder_stream_counts(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    header: &SevenZipHeader,
    target: &str,
) -> Result<Py<PyDict>, String> {
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z encoded header range is invalid".to_string())?;
    let Some(new_header) = seven_zip_encoded_header_folder_stream_counts_patch(raw)? else {
        return Err("7z folder stream counts are already canonical".to_string());
    };
    seven_zip_materialize_header_graph_patch(
        py,
        data,
        workspace,
        header,
        target,
        &new_header,
        "repair_7z_folder_stream_counts",
        "fixed_field=folder_stream_counts",
        "folder_coder_flags_canonicalized",
    )
    .map_err(|err| err.to_string())
}

fn seven_zip_encoded_header_coder_property_ranges(
    raw: &[u8],
) -> Result<Vec<(usize, usize, Vec<u8>)>, String> {
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
                            return Err("7z coder property repair requires exactly one folder".to_string());
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
                        if num_coders == 0 || num_coders > 8 {
                            return Err("7z coder property repair requires a small coder graph".to_string());
                        }
                        let mut ranges = Vec::new();
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
                            let method_id = raw[pos..pos + id_size].to_vec();
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
                                ranges.push((pos, pos + prop_size, method_id.clone()));
                                pos += prop_size;
                            }
                            if flags & 0x80 != 0 {
                                return Err("7z alternative coder methods are not supported".to_string());
                            }
                        }
                        let bind_pairs = total_out.saturating_sub(1);
                        for _ in 0..bind_pairs {
                            read_sz_vint(raw, &mut pos).ok_or_else(|| "7z bind pair input index is truncated".to_string())?;
                            read_sz_vint(raw, &mut pos).ok_or_else(|| "7z bind pair output index is truncated".to_string())?;
                        }
                        let packed_streams = total_in.saturating_sub(bind_pairs);
                        if packed_streams > 1 {
                            for _ in 0..packed_streams {
                                read_sz_vint(raw, &mut pos).ok_or_else(|| "7z packed stream index is truncated".to_string())?;
                            }
                        }
                        return Ok(ranges);
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
                    _ => return Err(format!("7z EncodedHeader UnpackInfo NID 0x{unpack_nid:02x} is unsupported for coder property repair")),
                }
            },
            SZ_SUB_STREAMS_INFO => consume_empty_seven_zip_property_tree(raw, &mut pos, "EncodedHeader SubStreamsInfo")?,
            _ => return Err(format!("7z EncodedHeader StreamsInfo NID 0x{nid:02x} is unsupported for coder property repair")),
        }
    }
    Err("7z EncodedHeader Folder graph was not found".to_string())
}

fn seven_zip_aes_property_candidate_values(properties: &[u8], relative_index: usize) -> Vec<u8> {
    if properties.len() < 2 {
        return Vec::new();
    }
    let mut values = Vec::new();
    let current_b0 = properties[0];
    let common_cycles = [19u8, 20, 18, 21];
    if relative_index == 0 {
        let size_bits = current_b0 & 0xc0;
        for cycles in common_cycles {
            let b0 = size_bits | cycles;
            if b0 != current_b0 {
                values.push(b0);
            }
        }
    }
    values.sort();
    values.dedup();
    values
}

fn seven_zip_property_candidate_values(
    method_id: &[u8],
    properties: &[u8],
    relative_index: usize,
) -> Vec<u8> {
    if method_id == EncoderMethod::ID_AES256_SHA256 {
        return seven_zip_aes_property_candidate_values(properties, relative_index);
    }
    if method_id == EncoderMethod::ID_LZMA2 && properties.len() == 1 && relative_index == 0 {
        let mut values: Vec<u8> = (0u8..=40).collect();
        values.retain(|item| *item != properties[0]);
        return values;
    }
    if method_id == EncoderMethod::ID_LZMA && properties.len() == 5 && relative_index == 0 {
        let mut values: Vec<u8> = (0u8..=224).collect();
        values.retain(|item| *item != properties[0]);
        return values;
    }
    Vec::new()
}

#[derive(Clone)]
enum SevenZipEncodedHeaderCoderPropertiesCacheValue {
    Success(Vec<u8>),
    Failure(String),
}

fn seven_zip_encoded_header_coder_properties_cache() -> &'static std::sync::Mutex<
    std::collections::HashMap<String, SevenZipEncodedHeaderCoderPropertiesCacheValue>,
> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<
            std::collections::HashMap<String, SevenZipEncodedHeaderCoderPropertiesCacheValue>,
        >,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn seven_zip_encoded_header_pack_stream_range_from_raw(
    header: &SevenZipHeader,
    raw: &[u8],
) -> Option<(usize, usize)> {
    let mut pos = 0usize;
    if raw.get(pos).copied() != Some(SZ_ENCODED_HEADER) {
        return None;
    }
    pos += 1;
    loop {
        let nid = raw.get(pos).copied()?;
        pos += 1;
        match nid {
            SZ_END => return None,
            SZ_PACK_INFO => {
                let pack = parse_seven_zip_pack_info(raw, &mut pos).ok()?;
                if pack.num_streams != 1 || pack.sizes.len() != 1 {
                    return None;
                }
                let stream_start =
                    SEVEN_Z_HEADER_SIZE.checked_add(usize::try_from(pack.pack_pos.value).ok()?)?;
                let stream_size = usize::try_from(pack.sizes[0].value).ok()?;
                let stream_end = stream_start.checked_add(stream_size)?;
                if stream_start < SEVEN_Z_HEADER_SIZE || stream_end > header.next_header_start {
                    return None;
                }
                return Some((stream_start, stream_end));
            }
            SZ_UNPACK_INFO => {
                consume_empty_seven_zip_property_tree(raw, &mut pos, "EncodedHeader UnpackInfo")
                    .ok()?;
            }
            SZ_SUB_STREAMS_INFO => {
                consume_empty_seven_zip_property_tree(
                    raw,
                    &mut pos,
                    "EncodedHeader SubStreamsInfo",
                )
                .ok()?;
            }
            _ => return None,
        }
    }
}

fn seven_zip_encoded_header_coder_properties_cache_key(
    data: &[u8],
    header: &SevenZipHeader,
    raw: &[u8],
    password: Option<&str>,
) -> String {
    let mut sha = sha2::Sha256::default();
    sha.update(b"7z-encoded-header-coder-properties-v1");
    sha.update(raw);
    if let Some((stream_start, stream_end)) =
        seven_zip_encoded_header_pack_stream_range_from_raw(header, raw)
    {
        if let Some(stream) = data.get(stream_start..stream_end) {
            sha.update(b"|stream|");
            sha.update(stream);
        }
    }
    sha.update(b"|password|");
    if let Some(password) = password {
        sha.update(password.as_bytes());
    }
    format!("{:x}", sha.finalize())
}

fn seven_zip_encoded_header_coder_properties_infer(
    data: &[u8],
    header: &SevenZipHeader,
    raw: &[u8],
    password: Option<&str>,
) -> Result<Vec<u8>, String> {
    let cache_key =
        seven_zip_encoded_header_coder_properties_cache_key(data, header, raw, password);
    if let Ok(cache) = seven_zip_encoded_header_coder_properties_cache().lock() {
        if let Some(cached) = cache.get(&cache_key) {
            return match cached {
                SevenZipEncodedHeaderCoderPropertiesCacheValue::Success(value) => Ok(value.clone()),
                SevenZipEncodedHeaderCoderPropertiesCacheValue::Failure(message) => {
                    Err(message.clone())
                }
            };
        }
    }

    let result =
        seven_zip_encoded_header_coder_properties_infer_uncached(data, header, raw, password);
    if let Ok(mut cache) = seven_zip_encoded_header_coder_properties_cache().lock() {
        if cache.len() >= 2048 {
            cache.clear();
        }
        let value = match &result {
            Ok(header) => SevenZipEncodedHeaderCoderPropertiesCacheValue::Success(header.clone()),
            Err(message) => {
                SevenZipEncodedHeaderCoderPropertiesCacheValue::Failure(message.clone())
            }
        };
        cache.insert(cache_key, value);
    }
    result
}

fn seven_zip_encoded_header_coder_properties_infer_uncached(
    data: &[u8],
    header: &SevenZipHeader,
    raw: &[u8],
    password: Option<&str>,
) -> Result<Vec<u8>, String> {
    if let Ok(decoded) =
        decode_seven_zip_encoded_header_payload_from_raw(data, header, raw, password)
    {
        if decoded.first().copied() == Some(SZ_HEADER) {
            return Err("7z EncodedHeader coder properties are already decodable".to_string());
        }
    }

    let ranges = match seven_zip_encoded_header_coder_property_ranges(raw) {
        Ok(ranges) => ranges,
        Err(message) if message.contains("coder properties are truncated") => {
            if let Some(new_header) = seven_zip_encoded_header_coder_property_size_patch(raw)? {
                return Ok(new_header);
            }
            return Err(message);
        }
        Err(message) => return Err(message),
    };
    if ranges.is_empty() {
        return Err("7z EncodedHeader has no inline coder properties".to_string());
    }
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    let mut attempts = 0usize;
    'property_ranges: for (start, end, method_id) in ranges {
        let properties = &raw[start..end];
        for index in start..end {
            let relative_index = index - start;
            for value in seven_zip_property_candidate_values(&method_id, properties, relative_index)
            {
                let mut patched = raw.to_vec();
                patched[index] = value;
                attempts += 1;
                if attempts > 1024 {
                    return Err(
                        "7z EncodedHeader coder properties repair exceeded candidate limit"
                            .to_string(),
                    );
                }
                if matches!(
                    decode_seven_zip_encoded_header_payload_from_raw(data, header, &patched, password),
                    Ok(decoded) if decoded.first().copied() == Some(SZ_HEADER)
                ) {
                    candidates.push(patched);
                }
            }
        }
        if method_id == EncoderMethod::ID_AES256_SHA256 && !candidates.is_empty() {
            break 'property_ranges;
        }
    }
    candidates.sort();
    candidates.dedup();
    if candidates.is_empty() {
        return Err(
            "7z EncodedHeader coder properties repair found no decodable candidate".to_string(),
        );
    }
    if candidates.len() > 1 {
        return Err("7z EncodedHeader coder properties repair is not unique".to_string());
    }
    Ok(candidates.remove(0))
}

fn seven_zip_repair_encoded_header_coder_properties(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    header: &SevenZipHeader,
    target: &str,
    password: Option<&str>,
) -> Result<Py<PyDict>, String> {
    let raw = data
        .get(header.next_header_start..header.archive_end)
        .ok_or_else(|| "7z encoded header range is invalid".to_string())?;
    let new_header = seven_zip_encoded_header_coder_properties_infer(data, header, raw, password)?;
    let fact = if new_header.len() != raw.len() {
        "encoded_header_coder_property_size_canonicalized"
    } else {
        "encoded_header_coder_properties_inferred_by_decode"
    };
    seven_zip_materialize_header_graph_patch(
        py,
        data,
        workspace,
        header,
        target,
        &new_header,
        "repair_7z_encoded_header_coder_properties",
        "fixed_field=encoded_header_coder_properties",
        fact,
    )
    .map_err(|err| err.to_string())
}

fn seven_zip_encoded_header_coder_property_size_patch(
    raw: &[u8],
) -> Result<Option<Vec<u8>>, String> {
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
            SZ_END => return Ok(None),
            SZ_PACK_INFO => {
                parse_seven_zip_pack_info(raw, &mut pos).map_err(|message| {
                    format!("7z EncodedHeader PackInfo is not parseable: {message}")
                })?;
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
                            .ok_or_else(|| {
                                "7z EncodedHeader Folder count is truncated".to_string()
                            })?
                            .value;
                        if num_folders != 1 {
                            return Err(
                                "7z coder property size repair requires exactly one folder"
                                    .to_string(),
                            );
                        }
                        let external = *raw.get(pos).ok_or_else(|| {
                            "7z EncodedHeader Folder external flag is missing".to_string()
                        })?;
                        pos += 1;
                        if external != 0 {
                            return Err("7z external Folder graph is not supported".to_string());
                        }
                        let num_coders = usize::try_from(
                            read_sz_vint(raw, &mut pos)
                                .ok_or_else(|| {
                                    "7z EncodedHeader coder count is truncated".to_string()
                                })?
                                .value,
                        )
                        .map_err(|_| "7z EncodedHeader coder count is too large".to_string())?;
                        if num_coders == 0 || num_coders > 8 {
                            return Err(
                                "7z coder property size repair requires a small coder graph"
                                    .to_string(),
                            );
                        }
                        let mut candidates = Vec::new();
                        for _ in 0..num_coders {
                            let flags = *raw.get(pos).ok_or_else(|| {
                                "7z EncodedHeader coder flags are missing".to_string()
                            })?;
                            pos += 1;
                            let id_size = usize::from(flags & 0x0f);
                            if id_size == 0 || pos + id_size > raw.len() {
                                return Err("7z EncodedHeader coder id is truncated".to_string());
                            }
                            let method_id = raw[pos..pos + id_size].to_vec();
                            pos += id_size;
                            if flags & 0x10 != 0 {
                                read_sz_vint(raw, &mut pos).ok_or_else(|| {
                                    "7z EncodedHeader coder input stream count is truncated"
                                        .to_string()
                                })?;
                                read_sz_vint(raw, &mut pos).ok_or_else(|| {
                                    "7z EncodedHeader coder output stream count is truncated"
                                        .to_string()
                                })?;
                            }
                            if flags & 0x20 != 0 {
                                let size_span = read_sz_vint(raw, &mut pos).ok_or_else(|| {
                                    "7z EncodedHeader coder properties size is truncated"
                                        .to_string()
                                })?;
                                let current_size =
                                    usize::try_from(size_span.value).unwrap_or(usize::MAX);
                                if pos + current_size <= raw.len() {
                                    pos += current_size;
                                } else {
                                    let mut size_candidates: Vec<u64> = Vec::new();
                                    if method_id == EncoderMethod::ID_AES256_SHA256 {
                                        if pos + 2 <= raw.len() {
                                            let b0 = raw[pos];
                                            let b1 = raw[pos + 1];
                                            let iv_size = usize::from(((b0 >> 6) & 1) + (b1 & 15));
                                            let salt_size =
                                                usize::from(((b0 >> 7) & 1) + (b1 >> 4));
                                            let expected = 2 + salt_size + iv_size;
                                            if expected <= 48 {
                                                size_candidates
                                                    .push(u64::try_from(expected).unwrap_or(0));
                                            }
                                        }
                                    } else if method_id == EncoderMethod::ID_LZMA {
                                        size_candidates.push(5);
                                    } else if method_id == EncoderMethod::ID_LZMA2 {
                                        size_candidates.push(1);
                                    }
                                    if size_candidates.is_empty() {
                                        size_candidates.extend(0u64..=48);
                                    }
                                    size_candidates.sort_unstable();
                                    size_candidates.dedup();
                                    for size in size_candidates {
                                        let replacement = write_sz_vint(size);
                                        if replacement.len()
                                            != size_span.end.saturating_sub(size_span.start)
                                            || size == size_span.value
                                        {
                                            continue;
                                        }
                                        let patched = replace_header_range(
                                            raw,
                                            size_span.start,
                                            size_span.end,
                                            &replacement,
                                        );
                                        if seven_zip_encoded_header_coder_property_ranges(&patched)
                                            .is_ok()
                                        {
                                            candidates.push(patched);
                                        }
                                    }
                                    candidates.sort();
                                    candidates.dedup();
                                    if candidates.len() > 1 {
                                        return Err(
                                            "7z EncodedHeader coder properties size repair is not unique".to_string(),
                                        );
                                    }
                                    return Ok(candidates.pop());
                                }
                            }
                            if flags & 0x80 != 0 {
                                return Err(
                                    "7z alternative coder methods are not supported".to_string()
                                );
                            }
                        }
                    }
                    SZ_CODERS_UNPACK_SIZE => {
                        read_sz_vint(raw, &mut pos).ok_or_else(|| {
                            "7z EncodedHeader unpack size is truncated".to_string()
                        })?;
                    }
                    SZ_CRC => {
                        let defined =
                            parse_seven_zip_bool_vector(raw, &mut pos, 1).map_err(|message| {
                                format!("7z EncodedHeader CRC bitset is not parseable: {message}")
                            })?;
                        for is_defined in defined {
                            if is_defined {
                                if pos + 4 > raw.len() {
                                    return Err(
                                        "7z EncodedHeader CRC value is truncated".to_string()
                                    );
                                }
                                pos += 4;
                            }
                        }
                    }
                    _ => {
                        return Err(format!(
                            "7z EncodedHeader UnpackInfo NID 0x{unpack_nid:02x} is unsupported for coder property size repair"
                        ));
                    }
                }
            },
            SZ_SUB_STREAMS_INFO => {
                consume_empty_seven_zip_property_tree(
                    raw,
                    &mut pos,
                    "EncodedHeader SubStreamsInfo",
                )?;
            }
            _ => {
                return Err(format!(
                    "7z EncodedHeader StreamsInfo NID 0x{nid:02x} is unsupported for coder property size repair"
                ));
            }
        }
    }
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
        Err(err) => {
            return seven_zip_atomic_status(
                py,
                "unrepairable",
                target,
                "7z",
                "",
                &format!("7z header graph patch could not be written: {err}"),
                &[],
                &[],
                &[],
                0.0,
                &[],
                &[],
            )
        }
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
        actions: vec![
            action.to_string(),
            "rewrite_7z_header_graph".to_string(),
            "recompute_7z_next_header_crc".to_string(),
            "recompute_7z_start_header_crc".to_string(),
        ],
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
        &[
            action,
            "rewrite_7z_header_graph",
            "recompute_7z_next_header_crc",
            "recompute_7z_start_header_crc",
        ],
        &[selected],
    )?;
    set_seven_zip_atomic_fields(
        py,
        &result,
        target,
        &[
            patch_fact,
            detail_fact,
            "rewrote_7z_header_graph_ast",
            "updated_next_header_crc",
            "updated_start_header_crc",
            "source_format=7z",
        ],
        &[],
    )?;
    add_seven_zip_candidate_replace_patch_plans(py, &result, data, target)?;
    Ok(result)
}

fn seven_zip_metadata_target_not_materialized(
    py: Python<'_>,
    target: &str,
) -> PyResult<Py<PyDict>> {
    let reason = match target {
        "encoded_header_decode" => "7z encoded header decode requires a decoded header writer",
        "encoded_header_stream_crc" => {
            "7z encoded header stream CRC repair requires parsed stream metadata"
        }
        "pack_stream_offset" => "7z PackInfo offset repair requires parsed pack stream metadata",
        "pack_stream_size" => "7z PackSizes repair requires parsed pack stream metadata",
        "unpack_size" => "7z UnpackSize repair requires parsed folder/substream metadata",
        "stream_crc" => "7z stream CRC repair requires verified decoded stream payloads",
        "bad_folder_quarantine" => "7z folder quarantine requires folder-level decode verification",
        "empty_stream_flags" => "7z empty stream flag repair requires parsed file table metadata",
        "folder_bind_pairs" => "7z folder bind pair repair requires parsed folder graph metadata",
        "folder_stream_counts" => {
            "7z folder stream count repair requires parsed folder graph metadata"
        }
        "file_count_metadata" => "7z file count repair requires parsed file table metadata",
        "file_names_utf16" => {
            "7z UTF-16 filename repair requires parsed Names property graph metadata"
        }
        "unreferenced_folder" => {
            "7z unreferenced folder drop requires parsed folder-to-file graph metadata"
        }
        "unreferenced_file_record" => {
            "7z unreferenced file record drop requires parsed file-to-stream graph metadata"
        }
        "stream_crc_defined_flag" => {
            "7z CRC defined flag repair requires parsed CRC bitset and stream map metadata"
        }
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
