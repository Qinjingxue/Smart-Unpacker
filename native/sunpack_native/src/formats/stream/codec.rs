fn decode_stream_prefix_to_vec(
    data: &[u8],
    format: StreamFormat,
    options: &StreamRepairOptions,
) -> Result<DecodedPrefix, String> {
    let started = Instant::now();
    let cursor = Cursor::new(data.to_vec());
    let mut decoder = decoder_for(format, cursor)?;
    let mut buffer = vec![0u8; DECODE_CHUNK_SIZE];
    let mut decoded = Vec::new();
    let mut error = None;
    let mut timed_out = false;

    loop {
        if timed_out_at(started, options.max_duration) {
            timed_out = true;
            break;
        }
        match decoder.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                decoded.extend_from_slice(&buffer[..read]);
                if options
                    .max_output_bytes
                    .is_some_and(|limit| decoded.len() as u64 > limit)
                {
                    return Err(
                        "decoded TAR stream exceeds repair.deep.max_output_size_mb".to_string()
                    );
                }
            }
            Err(err) => {
                error = Some(err.to_string());
                break;
            }
        }
    }

    if decoded.is_empty() {
        return Err(
            error.unwrap_or_else(|| "stream produced no recoverable TAR prefix".to_string())
        );
    }

    let mut warnings = Vec::new();
    if timed_out {
        warnings.push("compressed TAR decode time budget reached".to_string());
    }
    Ok(DecodedPrefix {
        decoded_bytes: decoded.len() as u64,
        bytes: decoded,
        error,
        timed_out,
        warnings,
    })
}

fn recover_stream_prefix(
    data: &[u8],
    format: StreamFormat,
    output: &Path,
    options: &StreamRepairOptions,
) -> Result<RecoveryStats, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let started = Instant::now();
    let result = (|| -> Result<RecoveryStats, String> {
        let cursor = Cursor::new(data.to_vec());
        let mut decoder = decoder_for(format, cursor)?;
        let file = File::create(&temp).map_err(|err| err.to_string())?;
        let mut encoder = CandidateEncoder::new(format, file).map_err(|err| err.to_string())?;
        let mut buffer = vec![0u8; DECODE_CHUNK_SIZE];
        let mut decoded = 0u64;
        let mut error = None;
        let mut timed_out = false;

        loop {
            if timed_out_at(started, options.max_duration) {
                timed_out = true;
                break;
            }
            match decoder.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    decoded += read as u64;
                    if options
                        .max_output_bytes
                        .is_some_and(|limit| decoded > limit)
                    {
                        return Err(
                            "recovered stream prefix exceeds repair.deep.max_output_size_mb"
                                .to_string(),
                        );
                    }
                    encoder
                        .write_all(&buffer[..read])
                        .map_err(|err| err.to_string())?;
                }
                Err(err) => {
                    error = Some(err.to_string());
                    break;
                }
            }
        }

        if decoded == 0 {
            return Err(
                error.unwrap_or_else(|| "stream produced no recoverable prefix".to_string())
            );
        }
        if error.is_none() && !timed_out {
            return Err(
                "stream decoded completely; no truncated-prefix recovery needed".to_string(),
            );
        }
        let mut file = encoder.finish().map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        let output_bytes = file.seek(SeekFrom::End(0)).map_err(|err| err.to_string())?;
        if options
            .max_output_bytes
            .is_some_and(|limit| output_bytes > limit)
        {
            return Err("candidate output exceeds repair.deep.max_output_size_mb".to_string());
        }
        let mut warnings = Vec::new();
        if timed_out {
            warnings.push("compression stream partial recovery time budget reached".to_string());
        }
        Ok(RecoveryStats {
            decoded_bytes: decoded,
            output_bytes,
            error,
            warnings,
        })
    })();

    match result {
        Ok(stats) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(stats)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

