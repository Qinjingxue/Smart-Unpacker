#[pyfunction]
#[pyo3(signature = (
    source_input,
    format,
    workspace,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_seconds=30.0,
    max_entries=20000
))]
pub(crate) fn tar_compressed_partial_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    format: &str,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_seconds: f64,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let Some(format) = CompressedTarFormat::from_name(format) else {
        return tar_status_dict(
            py,
            "unsupported",
            "",
            "",
            "unsupported compressed TAR format",
            &[],
            format,
            "",
            0,
            0,
            0,
            0,
            0,
            0,
            0.0,
            &[],
        );
    };
    let options = StreamRepairOptions {
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_duration: duration_from_seconds(max_seconds),
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => {
            return tar_status_dict(
                py,
                "skipped",
                "",
                "",
                &message,
                &[],
                format.name(),
                format.stream().name(),
                0,
                0,
                0,
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };

    let decoded = match decode_stream_prefix_to_vec(&data, format.stream(), &options) {
        Ok(decoded) => decoded,
        Err(message) => {
            return tar_status_dict(
                py,
                "unrepairable",
                "",
                "",
                &message,
                &[],
                format.name(),
                format.stream().name(),
                0,
                0,
                0,
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };

    let tar = match repair_tar_prefix(&decoded.bytes, &options, max_entries) {
        Ok(tar) => tar,
        Err(message) => {
            return tar_status_dict(
                py,
                "unrepairable",
                "",
                decoded.error.as_deref().unwrap_or(""),
                &message,
                &decoded.warnings,
                format.name(),
                format.stream().name(),
                decoded.decoded_bytes,
                0,
                0,
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };

    if decoded.error.is_none() && !decoded.timed_out && !tar.changed {
        return tar_status_dict(
            py,
            "unrepairable",
            "",
            "",
            "compressed TAR decoded cleanly and inner TAR already looks canonical",
            &tar.warnings,
            format.name(),
            format.stream().name(),
            decoded.decoded_bytes,
            tar.tar_bytes,
            0,
            tar.members,
            tar.checksum_fixes,
            tar.truncated_members,
            0.0,
            &[],
        );
    }

    let output_path = Path::new(workspace).join(format!(
        "{}_truncated_partial_recovery{}",
        format.file_stem(),
        format.ext()
    ));
    let output_bytes =
        match write_recompressed_stream(format.stream(), &tar.bytes, &output_path, &options) {
            Ok(bytes) => bytes,
            Err(message) => {
                let mut warnings = decoded.warnings.clone();
                warnings.extend(tar.warnings.iter().cloned());
                return tar_status_dict(
                    py,
                    "unrepairable",
                    "",
                    decoded.error.as_deref().unwrap_or(""),
                    &message,
                    &warnings,
                    format.name(),
                    format.stream().name(),
                    decoded.decoded_bytes,
                    tar.tar_bytes,
                    0,
                    tar.members,
                    tar.checksum_fixes,
                    tar.truncated_members,
                    0.0,
                    &[],
                );
            }
        };

    let mut warnings = decoded.warnings.clone();
    warnings.extend(tar.warnings.iter().cloned());
    let status = if decoded.error.is_none() && !decoded.timed_out && tar.truncated_members == 0 {
        "repaired"
    } else {
        "partial"
    };
    let actions = [
        "decode_outer_stream_prefix",
        "repair_tar_headers",
        "append_tar_zero_blocks",
        "recompress_tar_stream",
    ];
    tar_status_dict(
        py,
        status,
        &output_path.to_string_lossy(),
        decoded.error.as_deref().unwrap_or(""),
        "compressed TAR recovery produced a canonical TAR stream candidate",
        &warnings,
        format.name(),
        format.stream().name(),
        decoded.decoded_bytes,
        tar.tar_bytes,
        output_bytes,
        tar.members,
        tar.checksum_fixes,
        tar.truncated_members,
        tar_confidence(tar.members, decoded.decoded_bytes),
        &actions,
    )
}

#[pyfunction]
#[pyo3(signature = (
    source_input,
    workspace,
    max_input_size_mb=512.0,
    max_output_size_mb=2048.0,
    max_entries=20000
))]
pub(crate) fn tar_truncated_partial_recovery(
    py: Python<'_>,
    source_input: &Bound<'_, PyDict>,
    workspace: &str,
    max_input_size_mb: f64,
    max_output_size_mb: f64,
    max_entries: usize,
) -> PyResult<Py<PyDict>> {
    let options = StreamRepairOptions {
        max_input_bytes: mb_to_bytes(max_input_size_mb),
        max_output_bytes: mb_to_bytes(max_output_size_mb),
        max_duration: None,
    };
    let data = match read_source_input(source_input, options.max_input_bytes) {
        Ok(data) => data,
        Err(message) => {
            return tar_status_dict(
                py,
                "skipped",
                "",
                "",
                &message,
                &[],
                "tar",
                "",
                0,
                0,
                0,
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };
    let tar = match repair_tar_prefix(&data, &options, max_entries) {
        Ok(tar) => tar,
        Err(message) => {
            return tar_status_dict(
                py,
                "unrepairable",
                "",
                "",
                &message,
                &[],
                "tar",
                "",
                0,
                0,
                0,
                0,
                0,
                0,
                0.0,
                &[],
            )
        }
    };
    if !tar.changed || tar.truncated_members == 0 {
        return tar_status_dict(
            py,
            "unrepairable",
            "",
            "",
            "TAR stream already looks canonical or has no truncated member",
            &tar.warnings,
            "tar",
            "",
            data.len() as u64,
            tar.tar_bytes,
            0,
            tar.members,
            tar.checksum_fixes,
            tar.truncated_members,
            0.0,
            &[],
        );
    }
    let output_path = Path::new(workspace).join("tar_truncated_partial_recovery.tar");
    let output_bytes = match write_prefix_atomic(&tar.bytes, tar.bytes.len(), &output_path) {
        Ok(bytes) => bytes,
        Err(message) => {
            return tar_status_dict(
                py,
                "unrepairable",
                "",
                "",
                &format!("TAR partial candidate could not be written: {message}"),
                &tar.warnings,
                "tar",
                "",
                data.len() as u64,
                tar.tar_bytes,
                0,
                tar.members,
                tar.checksum_fixes,
                tar.truncated_members,
                0.0,
                &[],
            )
        }
    };
    tar_status_dict(
        py,
        "partial",
        &output_path.to_string_lossy(),
        "",
        "truncated TAR member was dropped and complete members were repacked",
        &tar.warnings,
        "tar",
        "",
        data.len() as u64,
        tar.tar_bytes,
        output_bytes,
        tar.members,
        tar.checksum_fixes,
        tar.truncated_members,
        tar_confidence(tar.members, data.len() as u64),
        &[
            "walk_tar_members",
            "drop_truncated_tar_member",
            "append_tar_zero_blocks",
        ],
    )
}

