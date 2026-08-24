fn write_recompressed_stream(
    format: StreamFormat,
    data: &[u8],
    output: &Path,
    options: &StreamRepairOptions,
) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<u64, String> {
        let file = crate::io::resource_lifecycle::TrackedFile::create(
            &temp,
            "stream_repair_output",
        )
        .map_err(|err| err.to_string())?;
        let mut encoder = CandidateEncoder::new(format, file).map_err(|err| err.to_string())?;
        encoder.write_all(data).map_err(|err| err.to_string())?;
        let mut file = encoder.finish().map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        let output_bytes = file.seek(SeekFrom::End(0)).map_err(|err| err.to_string())?;
        if options
            .max_output_bytes
            .is_some_and(|limit| output_bytes > limit)
        {
            return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
        }
        Ok(output_bytes)
    })();

    match result {
        Ok(output_bytes) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(output_bytes)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

