fn seven_zip_repair_boundary_target(
    py: Python<'_>,
    data: &[u8],
    workspace: &str,
    target: &str,
    require_prefix: bool,
    max_candidates: usize,
) -> PyResult<Py<PyDict>> {
    let mut written = Vec::new();
    let candidates = scan_archive_signatures(data, TargetFormat::SevenZip, require_prefix, max_candidates.max(1));
    for candidate in candidates.into_iter().filter(|candidate| {
        candidate.format == TargetFormat::SevenZip
            && candidate.archive_end > candidate.offset
            && if require_prefix { candidate.offset > 0 } else { candidate.offset == 0 && candidate.archive_end < data.len() }
    }) {
        let output_path = Path::new(workspace).join(format!("seven_zip_{target}_{:08x}.7z", candidate.offset));
        let output_bytes = match write_slice_candidate(&data[candidate.offset..candidate.archive_end], &output_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        written.push(WrittenArchiveCandidate {
            name: format!("{target}_{:08x}", candidate.offset),
            path: output_path.to_string_lossy().to_string(),
            format: "7z".to_string(),
            status: "repaired".to_string(),
            offset: candidate.offset as u64,
            end_offset: candidate.archive_end as u64,
            output_bytes,
            confidence: if require_prefix { 0.94 } else { 0.88 },
            actions: vec![if require_prefix { "crop_7z_carrier_prefix" } else { "trim_7z_trailing_junk" }.to_string()],
            warnings: candidate.warnings,
        });
    }
    if require_prefix && written.is_empty() {
        for offset in find_all(data, SEVEN_Z_MAGIC).into_iter().filter(|offset| *offset > 0).take(max_candidates.max(1)) {
            let output_path = Path::new(workspace).join(format!("seven_zip_{target}_{:08x}.7z", offset));
            let output_bytes = match write_slice_candidate(&data[offset..], &output_path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            written.push(WrittenArchiveCandidate {
                name: format!("{target}_{:08x}", offset),
                path: output_path.to_string_lossy().to_string(),
                format: "7z".to_string(),
                status: "repaired".to_string(),
                offset: offset as u64,
                end_offset: data.len() as u64,
                output_bytes,
                confidence: 0.86,
                actions: vec!["crop_7z_carrier_prefix".to_string()],
                warnings: vec!["7z carrier prefix was cropped while header end is not yet reliable".to_string()],
            });
        }
    }
    let Some(selected) = written.first() else {
        return seven_zip_atomic_status(py, "unrepairable", target, "7z", "", "no matching 7z boundary candidate", &[], &[], &[], 0.0, &[], &[]);
    };
    let boundary_fact = if require_prefix { "fixed_field=carrier_prefix_crop" } else { "fixed_field=trailing_junk" };
    let patch_fact = if require_prefix { "cropped_carrier_prefix" } else { "trimmed_trailing_junk" };
    let start_fact = format!("cropped_start={}", selected.offset);
    let end_fact = format!("cropped_end={}", selected.end_offset);
    let action = if require_prefix { "crop_7z_carrier_prefix" } else { "trim_7z_trailing_junk" };
    let result = status_dict_with_candidates(
        py,
        "repaired",
        &selected.path,
        "7z",
        if require_prefix { "7z carrier prefix was cropped" } else { "7z trailing junk was trimmed" },
        &selected.warnings,
        selected.offset,
        selected.end_offset,
        selected.output_bytes,
        selected.confidence,
        &[action],
        &written,
    )?;
    set_seven_zip_atomic_fields(
        py,
        &result,
        target,
        &[boundary_fact, patch_fact, start_fact.as_str(), end_fact.as_str(), "source_format=7z"],
        &[],
    )?;
    Ok(result)
}
