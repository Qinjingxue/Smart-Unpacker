fn seven_zip_repair_crc_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
) -> PyResult<Py<PyDict>> {
    let offset = if data.starts_with(SEVEN_Z_MAGIC) {
        0
    } else {
        find_all(data, SEVEN_Z_MAGIC).into_iter().next().unwrap_or(0)
    };
    let Some(header) = parse_seven_zip_header(data, offset) else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z header is not readable for CRC repair", &[], &[], &[], 0.0, &["encoded_header_unreadable"], &[]);
    };
    let mut candidate = data[offset..header.archive_end].to_vec();
    let mut start_header = header.start_header;
    let (needed, action, patch_fact) = match target {
        "start_header_crc" => {
            let computed_start_crc = crc32(&start_header);
            if header.stored_start_crc == computed_start_crc {
                (false, "recompute_7z_start_header_crc", "fixed_field=start_header_crc")
            } else {
                candidate[8..12].copy_from_slice(&computed_start_crc.to_le_bytes());
                (true, "recompute_7z_start_header_crc", "fixed_field=start_header_crc")
            }
        }
        "next_header_crc" => {
            if header.stored_next_header_crc == header.computed_next_header_crc {
                (false, "recompute_7z_next_header_crc", "fixed_field=next_header_crc")
            } else {
                start_header[16..20].copy_from_slice(&header.computed_next_header_crc.to_le_bytes());
                candidate[28..32].copy_from_slice(&header.computed_next_header_crc.to_le_bytes());
                let computed_start_crc = crc32(&start_header);
                candidate[8..12].copy_from_slice(&computed_start_crc.to_le_bytes());
                (true, "recompute_7z_next_header_crc", "fixed_field=next_header_crc")
            }
        }
        _ => (false, "", ""),
    };
    if !needed || action.is_empty() {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z CRC target is already consistent or unsupported", &[], &[], &[], 0.0, &[], &[]);
    }
    let output_path = Path::new(workspace).join(format!("seven_zip_{target}.7z"));
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &format!("7z CRC candidate could not be written: {err}"), &[], &[], &[], 0.0, &[], &[]),
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
        actions: vec![action.to_string()],
        warnings: Vec::new(),
    };
    let selected_path = selected.path.clone();
    let result = status_dict_with_candidates(py, "repaired", &selected_path, "7z", "7z CRC field was repaired", &[], 0, candidate.len() as u64, output_bytes, 0.9, &[action], &[selected])?;
    let mut facts = vec![patch_fact, "source_format=7z"];
    if target == "next_header_crc" {
        facts.push("updated_start_header_crc_after_next_header_crc");
    }
    set_seven_zip_atomic_fields(py, &result, target, &facts, &[])?;
    add_seven_zip_candidate_replace_patch_plans(py, &result, data, target)?;
    Ok(result)
}
fn seven_zip_repair_signature_header_version(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
) -> PyResult<Py<PyDict>> {
    if data.len() < SEVEN_Z_HEADER_SIZE || !data.starts_with(SEVEN_Z_MAGIC) {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z signature header version repair requires the current source to start at the 7z signature", &[], &[], &[], 0.0, &["seven_zip_signature_missing"], &[]);
    }
    let major = data[6];
    let minor = data[7];
    if major == 0 && minor <= 4 {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "7z signature header version is already supported", &[], &[], &[], 0.0, &["signature_header_version_already_valid"], &[]);
    }
    let mut candidate = data.to_vec();
    candidate[6] = 0;
    candidate[7] = 4;
    let output_path = Path::new(workspace).join("seven_zip_signature_header_version.7z");
    let output_bytes = match write_slice_candidate(&candidate, &output_path) {
        Ok(bytes) => bytes,
        Err(err) => return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", &format!("7z signature header version candidate could not be written: {err}"), &[], &[], &[], 0.0, &[], &[]),
    };
    let action = "repair_7z_signature_header_version";
    let selected = WrittenArchiveCandidate {
        name: target.to_string(),
        path: output_path.to_string_lossy().to_string(),
        format: "7z".to_string(),
        status: "repaired".to_string(),
        offset: 0,
        end_offset: candidate.len() as u64,
        output_bytes,
        confidence: 0.9,
        actions: vec![action.to_string()],
        warnings: Vec::new(),
    };
    let selected_path = selected.path.clone();
    let result = status_dict_with_candidates(
        py,
        "repaired",
        &selected_path,
        "7z",
        "7z signature header version was normalized",
        &[],
        0,
        candidate.len() as u64,
        output_bytes,
        0.9,
        &[action],
        &[selected],
    )?;
    set_seven_zip_atomic_fields(
        py,
        &result,
        target,
        &["fixed_field=signature_header_version", "signature_header_version_normalized", "source_format=7z"],
        &[],
    )?;
    add_seven_zip_candidate_replace_patch_plans(py, &result, data, target)?;

    Ok(result)
}

