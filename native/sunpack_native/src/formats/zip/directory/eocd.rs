fn write_bytes_atomic(data: &[u8], output: &Path) -> Result<u64, String> {
    ensure_parent(output).map_err(|err| err.to_string())?;
    let temp = temp_path(output);
    let result = (|| -> Result<(), String> {
        let mut file = crate::io::resource_lifecycle::TrackedFile::create(
            &temp,
            "zip_directory_output",
        )
        .map_err(|err| err.to_string())?;
        file.write_all(data).map_err(|err| err.to_string())?;
        file.flush().map_err(|err| err.to_string())?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            if output.exists() {
                fs::remove_file(output).map_err(|err| err.to_string())?;
            }
            fs::rename(&temp, output).map_err(|err| err.to_string())?;
            Ok(data.len() as u64)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

fn simple_repair_status(
    py: Python<'_>,
    status: &str,
    format: &str,
    selected_path: &str,
    message: &str,
    actions: &[&str],
    confidence: f64,
    diagnostics: Option<Py<PyDict>>,
) -> PyResult<Py<PyDict>> {
    let result = PyDict::new(py);
    result.set_item("status", status)?;
    result.set_item("format", format)?;
    result.set_item("selected_path", selected_path)?;
    result.set_item("message", message)?;
    result.set_item("confidence", confidence)?;
    result.set_item("actions", PyList::new(py, actions)?)?;
    result.set_item("warnings", PyList::empty(py))?;
    result.set_item("workspace_paths", PyList::empty(py))?;
    if let Some(diag) = diagnostics {
        result.set_item("diagnostics", diag)?;
    }
    Ok(result.unbind())
}

fn u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn scan_recovers_stored_entry_and_skips_bad_crc() {
        let mut data = Vec::new();
        append_local_stored(&mut data, b"good.txt", b"good", crc32_bytes(b"good"));
        append_local_stored(&mut data, b"bad.txt", b"bad", 0);
        let options = test_options();

        let scan = scan_entries(&data, &options, Instant::now());

        assert_eq!(scan.entries.len(), 1);
        assert_eq!(scan.entries[0].name, b"good.txt");
        assert!(!scan.skipped_offsets.is_empty());
    }

    #[test]
    fn scan_recovers_deflate_descriptor_entry() {
        let payload = b"descriptor payload";
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut data = Vec::new();
        append_local_descriptor_deflate(
            &mut data,
            b"dd.txt",
            &compressed,
            crc32_bytes(payload),
            payload.len() as u64,
        );
        data.extend_from_slice(CD_SIG);
        let options = test_options();

        let scan = scan_entries(&data, &options, Instant::now());

        assert_eq!(scan.entries.len(), 1);
        assert!(scan.entries[0].verified);
        assert!(scan.entries[0].descriptor);
    }

    fn test_options() -> DeepZipOptions {
        DeepZipOptions {
            max_candidates: 3,
            max_entries: 100,
            max_input_bytes: None,
            max_output_bytes: None,
            max_entry_uncompressed_bytes: Some(1024 * 1024),
            max_duration: None,
            verify_candidates: true,
            allow_unverified_entries: false,
            password: None,
        }
    }

    fn append_local_stored(output: &mut Vec<u8>, name: &[u8], payload: &[u8], crc32: u32) {
        output.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        output.extend_from_slice(&20u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&crc32.to_le_bytes());
        output.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        output.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        output.extend_from_slice(&(name.len() as u16).to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(name);
        output.extend_from_slice(payload);
    }

    fn append_local_descriptor_deflate(
        output: &mut Vec<u8>,
        name: &[u8],
        compressed: &[u8],
        crc32: u32,
        uncompressed_size: u64,
    ) {
        output.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        output.extend_from_slice(&20u16.to_le_bytes());
        output.extend_from_slice(&0x08u16.to_le_bytes());
        output.extend_from_slice(&8u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&0u32.to_le_bytes());
        output.extend_from_slice(&(name.len() as u16).to_le_bytes());
        output.extend_from_slice(&0u16.to_le_bytes());
        output.extend_from_slice(name);
        output.extend_from_slice(compressed);
        output.extend_from_slice(DD_SIG);
        output.extend_from_slice(&crc32.to_le_bytes());
        output.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        output.extend_from_slice(&(uncompressed_size as u32).to_le_bytes());
    }
}
