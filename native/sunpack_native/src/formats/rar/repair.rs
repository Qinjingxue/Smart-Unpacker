#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn rar_block_chain_trim_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "rar", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let walks = rar_walks(&data, max_candidates.max(1));
    if walks.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "no RAR block chain with valid leading block CRCs was found",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };

    let mut written = Vec::new();
    let mut write_warnings = Vec::new();
    for walk in walks {
        if walk.last_complete_end <= walk.offset
            || (walk.offset == 0 && walk.last_complete_end == data.len())
        {
            continue;
        }

        let output_path =
            Path::new(workspace).join(format!("rar_block_chain_trim_{:08x}.rar", walk.offset));
        let output_bytes =
            match write_slice_candidate(&data[walk.offset..walk.last_complete_end], &output_path) {
                Ok(bytes) => bytes,
                Err(err) => {
                    write_warnings.push(format!(
                        "candidate at offset {} could not be written: {err}",
                        walk.offset
                    ));
                    continue;
                }
            };
        let status = if walk.end_block_found {
            "repaired"
        } else {
            "partial"
        };
        let action = match walk.version {
            RarVersion::Rar4 => "walk_rar4_block_chain_trim_boundary",
            RarVersion::Rar5 => "walk_rar5_block_chain_trim_boundary",
        };
        written.push(WrittenArchiveCandidate {
            name: format!("block_chain_trim_{:08x}", walk.offset),
            path: output_path.to_string_lossy().to_string(),
            format: "rar".to_string(),
            status: status.to_string(),
            offset: walk.offset as u64,
            end_offset: walk.last_complete_end as u64,
            output_bytes,
            confidence: if walk.end_block_found { 0.9 } else { 0.72 },
            actions: vec![action.to_string()],
            warnings: walk.warnings,
        });
    }

    let Some(selected) = written.first() else {
        let warnings = write_warnings;
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "RAR block chains already end at the input boundary",
            &warnings,
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    let action_refs = selected
        .actions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    status_dict_with_candidates(
        py,
        &selected.status,
        &selected.path,
        "rar",
        "RAR block chain was cropped to the last complete CRC-verified block",
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &action_refs,
        &written,
    )
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn rar_end_block_repair(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "rar", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let walks = rar_walks(&data, max_candidates.max(1));
    if walks.is_empty() {
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "no RAR block chain with valid leading block CRCs was found",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };

    let mut written = Vec::new();
    let mut skipped_warnings = Vec::new();
    for walk in walks {
        if walk.end_block_found || walk.missing_volume || !walk.last_block_can_precede_end {
            skipped_warnings.extend(walk.warnings);
            continue;
        }

        let mut candidate = data[walk.offset..walk.last_complete_end].to_vec();
        let end_block = match walk.version {
            RarVersion::Rar4 => rar4_end_block(),
            RarVersion::Rar5 => rar5_end_block(),
        };
        candidate.extend_from_slice(&end_block);
        let output_path =
            Path::new(workspace).join(format!("rar_end_block_repair_{:08x}.rar", walk.offset));
        let output_bytes = match write_slice_candidate(&candidate, &output_path) {
            Ok(bytes) => bytes,
            Err(err) => {
                skipped_warnings.push(format!(
                    "candidate at offset {} could not be written: {err}",
                    walk.offset
                ));
                continue;
            }
        };
        let action = match walk.version {
            RarVersion::Rar4 => "append_rar4_end_block",
            RarVersion::Rar5 => "append_rar5_end_block",
        };
        let mut actions = vec![action.to_string()];
        if walk.last_complete_end < data.len() {
            actions.push("crop_trailing_bytes_before_end_block".to_string());
        }
        written.push(WrittenArchiveCandidate {
            name: format!("end_block_repair_{:08x}", walk.offset),
            path: output_path.to_string_lossy().to_string(),
            format: "rar".to_string(),
            status: "repaired".to_string(),
            offset: walk.offset as u64,
            end_offset: (walk.last_complete_end + end_block.len()) as u64,
            output_bytes,
            confidence: 0.82,
            actions,
            warnings: walk.warnings,
        });
    }

    let Some(selected) = written.first() else {
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "RAR block chain is not safe for canonical end block synthesis",
            &skipped_warnings,
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    let action_refs = selected
        .actions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    status_dict_with_candidates(
        py,
        "repaired",
        &selected.path,
        "rar",
        "canonical RAR end block was appended after a complete CRC-verified block chain",
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &action_refs,
        &written,
    )
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_candidates=8
))]
pub(crate) fn rar_file_quarantine_rebuild(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let data = match read_source_input(source_input, mb_to_bytes(max_input_size_mb)) {
        Ok(data) => data,
        Err(message) => {
            return status_dict(py, "skipped", "", "rar", &message, &[], 0, 0, 0, 0.0, &[])
        }
    };
    let candidates =
        rebuild_rar_file_quarantine_candidates(&data, workspace, max_candidates.max(1));
    let Some(selected) = candidates.first() else {
        return status_dict(
            py,
            "unrepairable",
            "",
            "rar",
            "no complete RAR file blocks were available for quarantine rebuild",
            &[],
            0,
            data.len() as u64,
            0,
            0.0,
            &[],
        );
    };
    let action_refs = selected
        .actions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    status_dict_with_candidates(
        py,
        &selected.status,
        &selected.path,
        "rar",
        "RAR file-level quarantine produced a candidate with complete file blocks only",
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &action_refs,
        &candidates,
    )
}

