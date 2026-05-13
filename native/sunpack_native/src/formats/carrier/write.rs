fn write_slice_candidate(bytes: &[u8], output: &Path) -> std::io::Result<u64> {
    ensure_parent(output)?;
    let temp = temp_path(output);
    let result = (|| -> std::io::Result<u64> {
        let mut file = File::create(&temp)?;
        file.write_all(bytes)?;
        file.flush()?;
        Ok(bytes.len() as u64)
    })();
    match result {
        Ok(written) => {
            if output.exists() {
                fs::remove_file(output)?;
            }
            fs::rename(&temp, output)?;
            Ok(written)
        }
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

