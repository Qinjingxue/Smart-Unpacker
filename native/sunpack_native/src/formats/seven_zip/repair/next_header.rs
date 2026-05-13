fn seven_zip_repair_next_header_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
    max_scan_bytes: usize,
) -> PyResult<Py<PyDict>> {
    if data.len() < SEVEN_Z_HEADER_SIZE || !data.starts_with(SEVEN_Z_MAGIC) {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z signature is not at the current source start", &[], &[], &[], 0.0, &[], &[]);
    }
    let Some((next_offset, next_size)) = find_next_header_candidate(data, max_scan_bytes.max(1)) else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z next header candidate could not be inferred", &[], &[], &[], 0.0, &["encoded_header_candidate_missing"], &[]);
    };
    let current_offset = u64_le(data, 12);
    let current_size = u64_le(data, 20);
    let offset_differs = current_offset != next_offset;
    let size_differs = current_size != next_size;
    let allowed = match target {
        "next_header_offset" => offset_differs && !size_differs,
        "next_header_size" => size_differs && !offset_differs,
        "next_header_repoint" => offset_differs && size_differs,
        _ => false,
    };
    if !allowed {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z next header inferred fields do not match requested atomic target", &[], &[], &[], 0.0, &[], &[]);
    }
    let next_crc = u32_le(data, 28);
    let mut start_header = [0u8; 20];
    start_header[0..8].copy_from_slice(&next_offset.to_le_bytes());
    start_header[8..16].copy_from_slice(&next_size.to_le_bytes());
    start_header[16..20].copy_from_slice(&next_crc.to_le_bytes());
    let start_crc = crc32(&start_header);
    let mut candidate = data.to_vec();
    candidate[8..12].copy_from_slice(&start_crc.to_le_bytes());
    candidate[12..20].copy_from_slice(&next_offset.to_le_bytes());
    candidate[20..28].copy_from_slice(&next_size.to_le_bytes());
    let output_path = Path::new(workspace).join(format!("seven_zip_{target}.7z"));
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &format!("7z next header candidate could not be written: {err}"), &[], &[], &[], 0.0, &[], &[]),
    };
    let action = match target {
        "next_header_offset" => "repair_7z_next_header_offset",
        "next_header_size" => "repair_7z_next_header_size",
        _ => "repoint_7z_next_header",
    };
    let selected = WrittenArchiveCandidate {
        name: target.to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "repaired".to_string(),
        offset: 0,
        end_offset: candidate.len() as u64,
        output_bytes,
        confidence: 0.9,
        actions: vec![action.to_string(), "recompute_7z_start_header_crc".to_string()],
        warnings: Vec::new(),
    };
    let selected_path = selected.path.clone();
    let result = status_dict_with_candidates(py, "repaired", &selected_path, "7z", "7z next header field was repaired", &[], 0, candidate.len() as u64, output_bytes, 0.9, &[action, "recompute_7z_start_header_crc"], &[selected])?;
    let patch_fact = match target {
        "next_header_offset" => "fixed_field=next_header_offset",
        "next_header_size" => "fixed_field=next_header_size",
        _ => "fixed_field=next_header_repoint",
    };
    set_seven_zip_atomic_fields(py, &result, target, &[patch_fact, "updated_start_header_crc_after_next_header_field", "source_format=7z"], &[])?;
    Ok(result)
}
