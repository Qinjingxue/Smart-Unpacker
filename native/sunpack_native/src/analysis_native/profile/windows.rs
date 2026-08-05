pub(crate) fn fuzzy_binary_profile<F>(
    py: Python<'_>,
    file_size: u64,
    mut read_at: F,
    config: BinaryProfileConfig,
) -> PyResult<Py<PyDict>>
where
    F: FnMut(u64, usize) -> PyResult<Vec<u8>>,
{
    let windows = sample_windows(
        file_size,
        config.window_bytes,
        config.max_windows,
        config.max_sample_bytes,
    );
    let mut samples = Vec::new();
    let mut sample_data = Vec::new();
    for (offset, size) in windows {
        let data = read_at(offset, size)?;
        if data.is_empty() {
            continue;
        }
        samples.push(window_profile(offset, &data));
        sample_data.push((offset, data));
    }

    let entropy_profile = entropy_profile_py(
        py,
        &samples,
        config.entropy_high_threshold,
        config.entropy_low_threshold,
    )?;
    let byte_class_profile = byte_class_profile_py(py, &samples)?;
    let anomalies = collect_window_anomalies(
        &samples,
        config.entropy_high_threshold,
        config.entropy_low_threshold,
        config.entropy_jump_threshold,
    );
    let run_profile = run_profile_py(py, &samples)?;
    let ngram_sketch = ngram_sketch_py(
        py,
        &sample_data,
        config.ngram_top_k.max(1),
        config.max_ngram_sample_bytes,
    )?;
    let hints = hints_py(py, &samples, &anomalies, &run_profile, &ngram_sketch)?;

    let result = PyDict::new(py);
    result.set_item("sampled", !samples.is_empty())?;
    result.set_item(
        "sampled_bytes",
        samples.iter().map(|item| item.size as u64).sum::<u64>(),
    )?;
    result.set_item("sample_count", samples.len())?;
    result.set_item("window_bytes", config.window_bytes)?;
    result.set_item("windows", windows_py(py, &samples)?)?;
    result.set_item(
        "summary",
        summary_py(py, &samples, &entropy_profile, &byte_class_profile)?,
    )?;
    result.set_item("entropy_profile", entropy_profile)?;
    result.set_item("byte_class_profile", byte_class_profile)?;
    result.set_item("window_anomalies", anomalies_py(py, &anomalies)?)?;
    result.set_item("ngram_sketch", ngram_sketch)?;
    result.set_item("run_profile", run_profile)?;
    result.set_item("offset_hints", PyList::empty(py))?;
    result.set_item("hints", hints)?;
    Ok(result.unbind())
}

fn sample_windows(
    file_size: u64,
    window_size: usize,
    max_windows: usize,
    max_sample_bytes: usize,
) -> Vec<(u64, usize)> {
    if file_size == 0 {
        return Vec::new();
    }
    let budget_windows = max_windows
        .max(1)
        .min((max_sample_bytes / window_size.max(1)).max(1));
    if file_size <= window_size as u64 {
        return vec![(0, file_size as usize)];
    }
    if budget_windows == 1 {
        return vec![(0, window_size.min(file_size as usize))];
    }

    let mut offsets = vec![0u64, file_size.saturating_sub(window_size as u64)];
    let middle_count = budget_windows.saturating_sub(2);
    if middle_count > 0 {
        let span = file_size.saturating_sub(window_size as u64).max(1);
        for index in 1..=middle_count {
            offsets.push((span * index as u64) / (middle_count as u64 + 1));
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
        .into_iter()
        .map(|offset| {
            let remaining = file_size.saturating_sub(offset) as usize;
            (offset, window_size.min(remaining))
        })
        .collect()
}

fn window_profile(offset: u64, data: &[u8]) -> WindowProfile {
    let mut counts = [0usize; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let size = data.len();
    let printable = (0x20..0x7f).map(|value| counts[value]).sum::<usize>();
    let controls = (0x00..0x20).map(|value| counts[value]).sum::<usize>() + counts[0x7f];
    let high_bit = (0x80..=0xff).map(|value| counts[value]).sum::<usize>();
    WindowProfile {
        offset,
        end_offset: offset + size as u64,
        size,
        entropy: entropy(&counts, size),
        printable_ratio: printable as f64 / size as f64,
        control_ratio: controls as f64 / size as f64,
        high_bit_ratio: high_bit as f64 / size as f64,
        zero_ratio: counts[0] as f64 / size as f64,
        ff_ratio: counts[0xff] as f64 / size as f64,
        distinct_bytes: counts.iter().filter(|count| **count > 0).count(),
        run_profile: window_run_profile(offset, data),
    }
}

impl LogicalVolumes {
    fn new(paths: Vec<String>) -> PyResult<Self> {
        let mut volumes = Vec::new();
        let mut cursor = 0u64;
        for path in paths {
            let size = std::fs::metadata(&path)?.len();
            let end = cursor + size;
            volumes.push(LogicalVolume {
                path,
                start: cursor,
                end,
            });
            cursor = end;
        }
        if volumes.is_empty() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "fuzzy binary profile requires at least one path",
            ));
        }
        Ok(Self {
            volumes,
            size: cursor,
        })
    }

    fn read_at(&self, offset: u64, size: usize) -> PyResult<Vec<u8>> {
        if offset >= self.size || size == 0 {
            return Ok(Vec::new());
        }
        let read_size = size.min((self.size - offset) as usize);
        let end = offset + read_size as u64;
        let mut out = Vec::with_capacity(read_size);
        for volume in &self.volumes {
            if offset >= volume.end || end <= volume.start {
                continue;
            }
            let local_start = offset.max(volume.start) - volume.start;
            let local_end = end.min(volume.end) - volume.start;
            let chunk_len = (local_end - local_start) as usize;
            let reader = ManagedReader::open(&volume.path)?;
            let chunk = reader
                .read_exact_field_at(
                    local_start,
                    chunk_len,
                    "profile.sample_window",
                    FieldLocation::Body,
                )
                .map_err(|fault| pyo3::exceptions::PyIOError::new_err(fault.to_string()))?;
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

fn entropy(counts: &[usize; 256], size: usize) -> f64 {
    if size == 0 {
        return 0.0;
    }
    let mut total = 0.0;
    for count in counts.iter().copied().filter(|count| *count > 0) {
        let probability = count as f64 / size as f64;
        total -= probability * probability.log2();
    }
    total
}
