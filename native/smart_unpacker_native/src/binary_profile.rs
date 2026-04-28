use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf\x27\x1c";
const GZIP: &[u8] = b"\x1f\x8b\x08";
const BZIP2: &[u8] = b"BZh";
const XZ: &[u8] = b"\xfd7zXZ\x00";
const ZSTD: &[u8] = b"\x28\xb5\x2f\xfd";
const TAR_USTAR: &[u8] = b"ustar";

const MAGIC_PATTERNS: &[(&str, &[u8])] = &[
    ("zip_local", ZIP_LOCAL),
    ("zip_eocd", ZIP_EOCD),
    ("rar4", RAR4),
    ("rar5", RAR5),
    ("7z", SEVEN_ZIP),
    ("gzip", GZIP),
    ("bzip2", BZIP2),
    ("xz", XZ),
    ("zstd", ZSTD),
    ("tar_ustar", TAR_USTAR),
];

pub(crate) struct BinaryProfileConfig {
    pub(crate) window_bytes: usize,
    pub(crate) max_windows: usize,
    pub(crate) max_sample_bytes: usize,
    pub(crate) entropy_high_threshold: f64,
    pub(crate) entropy_low_threshold: f64,
    pub(crate) entropy_jump_threshold: f64,
    pub(crate) ngram_top_k: usize,
    pub(crate) max_ngram_sample_bytes: usize,
}

#[pyfunction]
#[pyo3(signature = (
    paths,
    window_bytes=65536,
    max_windows=8,
    max_sample_bytes=1048576,
    entropy_high_threshold=6.8,
    entropy_low_threshold=3.5,
    entropy_jump_threshold=1.25,
    ngram_top_k=8,
    max_ngram_sample_bytes=262144
))]
pub(crate) fn fuzzy_binary_profile_for_paths(
    py: Python<'_>,
    paths: Vec<String>,
    window_bytes: usize,
    max_windows: usize,
    max_sample_bytes: usize,
    entropy_high_threshold: f64,
    entropy_low_threshold: f64,
    entropy_jump_threshold: f64,
    ngram_top_k: usize,
    max_ngram_sample_bytes: usize,
) -> PyResult<Py<PyDict>> {
    let volumes = LogicalVolumes::new(paths)?;
    let window_bytes = window_bytes.max(1024);
    let config = BinaryProfileConfig {
        window_bytes,
        max_windows: max_windows.max(1),
        max_sample_bytes: max_sample_bytes.max(window_bytes),
        entropy_high_threshold,
        entropy_low_threshold,
        entropy_jump_threshold,
        ngram_top_k: ngram_top_k.max(1),
        max_ngram_sample_bytes,
    };
    fuzzy_binary_profile(py, volumes.size, |offset, size| volumes.read_at(offset, size), config)
}

#[derive(Clone)]
struct WindowProfile {
    offset: u64,
    end_offset: u64,
    size: usize,
    entropy: f64,
    printable_ratio: f64,
    control_ratio: f64,
    high_bit_ratio: f64,
    zero_ratio: f64,
    ff_ratio: f64,
    distinct_bytes: usize,
    run_profile: WindowRunProfile,
}

#[derive(Clone)]
struct WindowRunProfile {
    longest_zero_run: RunRecord,
    longest_ff_run: RunRecord,
    longest_repeated_byte_run: RunRecord,
    tail_run: RunRecord,
}

#[derive(Clone)]
struct RunRecord {
    byte: Option<u8>,
    offset: Option<u64>,
    length: usize,
}

#[derive(Clone)]
struct WindowAnomaly {
    anomaly_type: &'static str,
    offset: u64,
    previous_offset: Option<u64>,
    next_offset: Option<u64>,
    delta: Option<f64>,
    direction: Option<&'static str>,
    dominant_byte: Option<&'static str>,
    confidence: f64,
    approximate: bool,
}

struct LogicalVolume {
    path: String,
    start: u64,
    end: u64,
}

struct LogicalVolumes {
    volumes: Vec<LogicalVolume>,
    size: u64,
}

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
            let mut file = File::open(&volume.path)?;
            file.seek(SeekFrom::Start(local_start))?;
            let mut chunk = vec![0; chunk_len];
            file.read_exact(&mut chunk)?;
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

fn window_run_profile(offset: u64, data: &[u8]) -> WindowRunProfile {
    let mut zero = empty_run();
    let mut ff = empty_run();
    let mut repeated = empty_run();
    let mut current_byte = None;
    let mut current_start = 0usize;
    let mut current_len = 0usize;
    for (index, value) in data.iter().copied().enumerate() {
        if Some(value) == current_byte {
            current_len += 1;
        } else {
            record_run(
                &mut repeated,
                current_byte,
                current_start,
                current_len,
                offset,
            );
            if current_byte == Some(0) {
                record_run(&mut zero, current_byte, current_start, current_len, offset);
            } else if current_byte == Some(0xff) {
                record_run(&mut ff, current_byte, current_start, current_len, offset);
            }
            current_byte = Some(value);
            current_start = index;
            current_len = 1;
        }
    }
    record_run(
        &mut repeated,
        current_byte,
        current_start,
        current_len,
        offset,
    );
    if current_byte == Some(0) {
        record_run(&mut zero, current_byte, current_start, current_len, offset);
    } else if current_byte == Some(0xff) {
        record_run(&mut ff, current_byte, current_start, current_len, offset);
    }
    WindowRunProfile {
        longest_zero_run: zero,
        longest_ff_run: ff,
        longest_repeated_byte_run: repeated,
        tail_run: tail_run(offset, data),
    }
}

fn collect_window_anomalies(
    samples: &[WindowProfile],
    high_threshold: f64,
    low_threshold: f64,
    jump_threshold: f64,
) -> Vec<WindowAnomaly> {
    let mut anomalies = Vec::new();
    for pair in samples.windows(2) {
        let previous = &pair[0];
        let current = &pair[1];
        let delta = current.entropy - previous.entropy;
        if delta.abs() >= jump_threshold {
            anomalies.push(WindowAnomaly {
                anomaly_type: "entropy_jump",
                offset: current.offset,
                previous_offset: Some(previous.offset),
                next_offset: Some(current.offset),
                delta: Some(delta),
                direction: Some(if delta > 0.0 { "up" } else { "down" }),
                dominant_byte: None,
                confidence: confidence_from_delta(delta.abs(), jump_threshold),
                approximate: true,
            });
        }
        if previous.printable_ratio >= 0.55 && current.entropy >= high_threshold {
            anomalies.push(WindowAnomaly {
                anomaly_type: "printable_to_high_entropy",
                offset: current.offset,
                previous_offset: Some(previous.offset),
                next_offset: Some(current.offset),
                delta: None,
                direction: None,
                dominant_byte: None,
                confidence: 0.76,
                approximate: true,
            });
        }
        if previous.entropy >= high_threshold && current.printable_ratio >= 0.50 {
            anomalies.push(WindowAnomaly {
                anomaly_type: "high_entropy_to_printable",
                offset: current.offset,
                previous_offset: Some(previous.offset),
                next_offset: Some(current.offset),
                delta: None,
                direction: None,
                dominant_byte: None,
                confidence: 0.74,
                approximate: true,
            });
        }
        if previous.entropy >= high_threshold
            && (current.zero_ratio >= 0.35 || current.ff_ratio >= 0.35)
        {
            anomalies.push(WindowAnomaly {
                anomaly_type: "high_entropy_to_padding",
                offset: current.offset,
                previous_offset: Some(previous.offset),
                next_offset: Some(current.offset),
                delta: None,
                direction: None,
                dominant_byte: None,
                confidence: 0.80,
                approximate: true,
            });
        }
    }
    if let Some(tail) = samples.last() {
        if tail.zero_ratio >= 0.35 || tail.ff_ratio >= 0.35 {
            anomalies.push(WindowAnomaly {
                anomaly_type: "tail_padding",
                offset: tail.offset,
                previous_offset: None,
                next_offset: None,
                delta: None,
                direction: None,
                dominant_byte: Some(if tail.zero_ratio >= tail.ff_ratio {
                    "zero"
                } else {
                    "ff"
                }),
                confidence: 0.70,
                approximate: true,
            });
        }
        if tail.printable_ratio >= 0.60 && tail.entropy <= low_threshold.max(5.2) {
            anomalies.push(WindowAnomaly {
                anomaly_type: "tail_printable_region",
                offset: tail.offset,
                previous_offset: None,
                next_offset: None,
                delta: None,
                direction: None,
                dominant_byte: None,
                confidence: 0.62,
                approximate: true,
            });
        }
    }
    anomalies
}

fn windows_py<'py>(py: Python<'py>, samples: &[WindowProfile]) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for sample in samples {
        let dict = PyDict::new(py);
        dict.set_item("offset", sample.offset)?;
        dict.set_item("end_offset", sample.end_offset)?;
        dict.set_item("size", sample.size)?;
        dict.set_item("entropy", sample.entropy)?;
        dict.set_item("printable_ratio", sample.printable_ratio)?;
        dict.set_item("control_ratio", sample.control_ratio)?;
        dict.set_item("high_bit_ratio", sample.high_bit_ratio)?;
        dict.set_item("zero_ratio", sample.zero_ratio)?;
        dict.set_item("ff_ratio", sample.ff_ratio)?;
        dict.set_item("distinct_bytes", sample.distinct_bytes)?;
        dict.set_item(
            "run_profile",
            window_run_profile_py(py, &sample.run_profile)?,
        )?;
        list.append(dict)?;
    }
    Ok(list)
}

fn entropy_profile_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
    high_threshold: f64,
    low_threshold: f64,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    let head = &samples[0];
    let tail = samples.last().unwrap();
    let min_entropy = samples
        .iter()
        .map(|item| item.entropy)
        .fold(f64::INFINITY, f64::min);
    let max_entropy = samples
        .iter()
        .map(|item| item.entropy)
        .fold(f64::NEG_INFINITY, f64::max);
    let avg_entropy = samples.iter().map(|item| item.entropy).sum::<f64>() / samples.len() as f64;
    let middle_entropy = if samples.len() > 2 {
        Some(
            samples[1..samples.len() - 1]
                .iter()
                .map(|item| item.entropy)
                .sum::<f64>()
                / (samples.len() - 2) as f64,
        )
    } else {
        None
    };
    let overall_class = if avg_entropy >= high_threshold {
        "high_entropy"
    } else if max_entropy <= low_threshold {
        "low_entropy"
    } else if max_entropy - min_entropy >= 1.5 {
        "mixed_entropy"
    } else {
        "medium_entropy"
    };
    dict.set_item("head_entropy", head.entropy)?;
    dict.set_item("middle_entropy", middle_entropy)?;
    dict.set_item("tail_entropy", tail.entropy)?;
    dict.set_item("min_entropy", min_entropy)?;
    dict.set_item("max_entropy", max_entropy)?;
    dict.set_item("avg_entropy", avg_entropy)?;
    dict.set_item("entropy_range", max_entropy - min_entropy)?;
    dict.set_item(
        "head_class",
        entropy_class(head.entropy, high_threshold, low_threshold),
    )?;
    dict.set_item(
        "middle_class",
        middle_entropy
            .map(|value| entropy_class(value, high_threshold, low_threshold))
            .unwrap_or("unknown"),
    )?;
    dict.set_item(
        "tail_class",
        entropy_class(tail.entropy, high_threshold, low_threshold),
    )?;
    dict.set_item("overall_class", overall_class)?;
    dict.set_item("overall_high_entropy", avg_entropy >= high_threshold)?;
    dict.set_item("overall_low_entropy", max_entropy <= low_threshold)?;
    dict.set_item(
        "local_high_entropy",
        samples.iter().any(|item| item.entropy >= high_threshold),
    )?;
    dict.set_item(
        "local_low_entropy",
        samples.iter().any(|item| item.entropy <= low_threshold),
    )?;
    dict.set_item("head_low_entropy", head.entropy <= low_threshold)?;
    dict.set_item("tail_low_entropy", tail.entropy <= low_threshold)?;
    dict.set_item(
        "high_entropy_windows",
        entropy_windows_py(py, samples, high_threshold, true)?,
    )?;
    dict.set_item(
        "low_entropy_windows",
        entropy_windows_py(py, samples, low_threshold, false)?,
    )?;
    Ok(dict)
}

fn byte_class_profile_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    dict.set_item("head", ratio_record_py(py, &samples[0])?)?;
    dict.set_item(
        "middle",
        if samples.len() > 2 {
            average_ratio_record_py(py, &samples[1..samples.len() - 1])?
        } else {
            PyDict::new(py)
        },
    )?;
    dict.set_item("tail", ratio_record_py(py, samples.last().unwrap())?)?;
    dict.set_item("average", average_ratio_record_py(py, samples)?)?;
    dict.set_item(
        "max_printable_ratio",
        samples
            .iter()
            .map(|item| item.printable_ratio)
            .fold(0.0, f64::max),
    )?;
    dict.set_item(
        "max_zero_ratio",
        samples
            .iter()
            .map(|item| item.zero_ratio)
            .fold(0.0, f64::max),
    )?;
    dict.set_item(
        "max_ff_ratio",
        samples.iter().map(|item| item.ff_ratio).fold(0.0, f64::max),
    )?;
    dict.set_item(
        "max_control_ratio",
        samples
            .iter()
            .map(|item| item.control_ratio)
            .fold(0.0, f64::max),
    )?;
    dict.set_item(
        "max_high_bit_ratio",
        samples
            .iter()
            .map(|item| item.high_bit_ratio)
            .fold(0.0, f64::max),
    )?;
    Ok(dict)
}

fn anomalies_py<'py>(py: Python<'py>, anomalies: &[WindowAnomaly]) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for anomaly in anomalies {
        let dict = PyDict::new(py);
        dict.set_item("type", anomaly.anomaly_type)?;
        dict.set_item("offset", anomaly.offset)?;
        if let Some(value) = anomaly.previous_offset {
            dict.set_item("previous_offset", value)?;
        }
        if let Some(value) = anomaly.next_offset {
            dict.set_item("next_offset", value)?;
        }
        if let Some(value) = anomaly.delta {
            dict.set_item("delta", value)?;
        }
        if let Some(value) = anomaly.direction {
            dict.set_item("direction", value)?;
        }
        if let Some(value) = anomaly.dominant_byte {
            dict.set_item("dominant_byte", value)?;
        }
        dict.set_item("confidence", anomaly.confidence)?;
        dict.set_item("approximate", anomaly.approximate)?;
        list.append(dict)?;
    }
    Ok(list)
}

fn run_profile_py<'py>(py: Python<'py>, samples: &[WindowProfile]) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    let mut longest_zero = empty_run();
    let mut longest_ff = empty_run();
    let mut longest_repeated = empty_run();
    for sample in samples {
        longest_zero = max_run(&longest_zero, &sample.run_profile.longest_zero_run);
        longest_ff = max_run(&longest_ff, &sample.run_profile.longest_ff_run);
        longest_repeated = max_run(
            &longest_repeated,
            &sample.run_profile.longest_repeated_byte_run,
        );
    }
    let tail = &samples.last().unwrap().run_profile.tail_run;
    let tail_padding_likely = tail.length >= 32usize.max(samples.last().unwrap().size / 8)
        && matches!(tail.byte, Some(0) | Some(0xff));
    dict.set_item("longest_zero_run", run_record_py(py, &longest_zero)?)?;
    dict.set_item("longest_ff_run", run_record_py(py, &longest_ff)?)?;
    dict.set_item(
        "longest_repeated_byte_run",
        run_record_py(py, &longest_repeated)?,
    )?;
    dict.set_item("tail_run", run_record_py(py, tail)?)?;
    dict.set_item("tail_padding_likely", tail_padding_likely)?;
    Ok(dict)
}

fn ngram_sketch_py<'py>(
    py: Python<'py>,
    sample_data: &[(u64, Vec<u8>)],
    top_k: usize,
    max_sample_bytes: usize,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if sample_data.is_empty() || max_sample_bytes == 0 {
        dict.set_item("sampled_bytes", 0usize)?;
        dict.set_item("byte_histogram_top", PyList::empty(py))?;
        dict.set_item("bigram_top", PyList::empty(py))?;
        dict.set_item("magic_like_hits", PyList::empty(py))?;
        dict.set_item("magic_like_density_per_mb", 0.0)?;
        return Ok(dict);
    }
    let mut byte_counts = [0usize; 256];
    let mut bigram_counts: HashMap<[u8; 2], usize> = HashMap::new();
    let mut magic_hits = Vec::new();
    let mut scanned = 0usize;
    for (offset, data) in sample_data {
        if scanned >= max_sample_bytes {
            break;
        }
        let read_len = data.len().min(max_sample_bytes - scanned);
        let chunk = &data[..read_len];
        for byte in chunk {
            byte_counts[*byte as usize] += 1;
        }
        for pair in chunk.windows(2) {
            *bigram_counts.entry([pair[0], pair[1]]).or_insert(0) += 1;
        }
        for (name, magic) in MAGIC_PATTERNS {
            for relative in find_all(chunk, magic) {
                magic_hits.push((*name, *offset + relative as u64));
            }
        }
        scanned += read_len;
    }

    let byte_top = PyList::empty(py);
    let mut byte_pairs = byte_counts
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, count)| *count > 0)
        .collect::<Vec<_>>();
    byte_pairs.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    for (value, count) in byte_pairs.into_iter().take(top_k) {
        let item = PyDict::new(py);
        item.set_item("byte", hex_byte(value as u8))?;
        item.set_item("value", value)?;
        item.set_item("count", count)?;
        item.set_item("ratio", count as f64 / scanned.max(1) as f64)?;
        byte_top.append(item)?;
    }

    let bigram_top = PyList::empty(py);
    let total_bigrams = bigram_counts.values().sum::<usize>();
    let mut bigram_pairs = bigram_counts.into_iter().collect::<Vec<_>>();
    bigram_pairs.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    for (value, count) in bigram_pairs.into_iter().take(top_k) {
        let item = PyDict::new(py);
        item.set_item("ngram_hex", format!("{:02x}{:02x}", value[0], value[1]))?;
        item.set_item("values", vec![value[0], value[1]])?;
        item.set_item("count", count)?;
        item.set_item("ratio", count as f64 / total_bigrams.max(1) as f64)?;
        bigram_top.append(item)?;
    }

    let magic_list = PyList::empty(py);
    for (name, offset) in magic_hits.iter().take(top_k) {
        let item = PyDict::new(py);
        item.set_item("name", name)?;
        item.set_item("offset", *offset)?;
        magic_list.append(item)?;
    }
    dict.set_item("sampled_bytes", scanned)?;
    dict.set_item("byte_histogram_top", byte_top)?;
    dict.set_item("bigram_top", bigram_top)?;
    dict.set_item("magic_like_hits", magic_list)?;
    dict.set_item(
        "magic_like_density_per_mb",
        if scanned > 0 {
            magic_hits.len() as f64 * 1024.0 * 1024.0 / scanned as f64
        } else {
            0.0
        },
    )?;
    Ok(dict)
}

fn summary_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
    entropy_profile: &Bound<'py, PyDict>,
    byte_class_profile: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    let average = byte_class_profile.get_item("average")?.unwrap();
    dict.set_item("min_entropy", entropy_profile.get_item("min_entropy")?)?;
    dict.set_item("max_entropy", entropy_profile.get_item("max_entropy")?)?;
    dict.set_item("avg_entropy", entropy_profile.get_item("avg_entropy")?)?;
    dict.set_item("avg_printable_ratio", average.get_item("printable_ratio")?)?;
    dict.set_item("avg_zero_ratio", average.get_item("zero_ratio")?)?;
    dict.set_item(
        "overall_entropy_class",
        entropy_profile.get_item("overall_class")?,
    )?;
    Ok(dict)
}

fn hints_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
    anomalies: &[WindowAnomaly],
    run_profile: &Bound<'py, PyDict>,
    ngram_sketch: &Bound<'py, PyDict>,
) -> PyResult<Bound<'py, PyList>> {
    let mut hints = Vec::new();
    if samples.is_empty() {
        return Ok(PyList::empty(py));
    }
    let min_entropy = samples
        .iter()
        .map(|item| item.entropy)
        .fold(f64::INFINITY, f64::min);
    let max_entropy = samples
        .iter()
        .map(|item| item.entropy)
        .fold(f64::NEG_INFINITY, f64::max);
    let avg_entropy = samples.iter().map(|item| item.entropy).sum::<f64>() / samples.len() as f64;
    if avg_entropy >= 6.8 {
        hints.push("high_entropy_body");
    }
    if max_entropy - min_entropy >= 1.5
        || anomalies
            .iter()
            .any(|item| item.anomaly_type == "entropy_jump")
    {
        hints.push("entropy_boundary_shift");
    }
    if samples[0].entropy <= 3.5 {
        hints.push("head_low_entropy");
    }
    if samples.last().unwrap().entropy <= 3.5 {
        hints.push("tail_low_entropy");
    }
    if samples.last().unwrap().printable_ratio >= 0.55 {
        hints.push("tail_printable_region");
    }
    if run_profile
        .get_item("tail_padding_likely")?
        .unwrap()
        .extract::<bool>()?
    {
        hints.push("trailing_padding_likely");
    }
    let magic_hits = ngram_sketch.get_item("magic_like_hits")?.unwrap();
    if magic_hits.len()? > 0 {
        hints.push("magic_like_signature_sampled");
    }
    hints.sort_unstable();
    hints.dedup();
    Ok(PyList::new(py, hints)?)
}

fn entropy_windows_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
    threshold: f64,
    high: bool,
) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for sample in samples {
        let selected = if high {
            sample.entropy >= threshold
        } else {
            sample.entropy <= threshold
        };
        if selected {
            let dict = PyDict::new(py);
            dict.set_item("offset", sample.offset)?;
            dict.set_item("end_offset", sample.end_offset)?;
            dict.set_item("entropy", sample.entropy)?;
            list.append(dict)?;
        }
    }
    Ok(list)
}

fn ratio_record_py<'py>(py: Python<'py>, sample: &WindowProfile) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("printable_ratio", sample.printable_ratio)?;
    dict.set_item("control_ratio", sample.control_ratio)?;
    dict.set_item("high_bit_ratio", sample.high_bit_ratio)?;
    dict.set_item("zero_ratio", sample.zero_ratio)?;
    dict.set_item("ff_ratio", sample.ff_ratio)?;
    dict.set_item("offset", sample.offset)?;
    dict.set_item("end_offset", sample.end_offset)?;
    dict.set_item("distinct_bytes", sample.distinct_bytes)?;
    Ok(dict)
}

fn average_ratio_record_py<'py>(
    py: Python<'py>,
    samples: &[WindowProfile],
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    if samples.is_empty() {
        return Ok(dict);
    }
    let count = samples.len() as f64;
    dict.set_item(
        "printable_ratio",
        samples.iter().map(|item| item.printable_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "control_ratio",
        samples.iter().map(|item| item.control_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "high_bit_ratio",
        samples.iter().map(|item| item.high_bit_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "zero_ratio",
        samples.iter().map(|item| item.zero_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "ff_ratio",
        samples.iter().map(|item| item.ff_ratio).sum::<f64>() / count,
    )?;
    dict.set_item(
        "avg_distinct_bytes",
        samples
            .iter()
            .map(|item| item.distinct_bytes as f64)
            .sum::<f64>()
            / count,
    )?;
    Ok(dict)
}

fn window_run_profile_py<'py>(
    py: Python<'py>,
    profile: &WindowRunProfile,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item(
        "longest_zero_run",
        run_record_py(py, &profile.longest_zero_run)?,
    )?;
    dict.set_item(
        "longest_ff_run",
        run_record_py(py, &profile.longest_ff_run)?,
    )?;
    dict.set_item(
        "longest_repeated_byte_run",
        run_record_py(py, &profile.longest_repeated_byte_run)?,
    )?;
    dict.set_item("tail_run", run_record_py(py, &profile.tail_run)?)?;
    Ok(dict)
}

fn run_record_py<'py>(py: Python<'py>, record: &RunRecord) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    match record.byte {
        Some(byte) => dict.set_item("byte", hex_byte(byte))?,
        None => dict.set_item("byte", py.None())?,
    }
    match record.offset {
        Some(offset) => dict.set_item("offset", offset)?,
        None => dict.set_item("offset", py.None())?,
    }
    dict.set_item("length", record.length)?;
    Ok(dict)
}

fn empty_run() -> RunRecord {
    RunRecord {
        byte: None,
        offset: None,
        length: 0,
    }
}

fn record_run(
    target: &mut RunRecord,
    byte: Option<u8>,
    start: usize,
    length: usize,
    base_offset: u64,
) {
    if byte.is_none() || length <= target.length {
        return;
    }
    target.byte = byte;
    target.offset = Some(base_offset + start as u64);
    target.length = length;
}

fn tail_run(offset: u64, data: &[u8]) -> RunRecord {
    let Some(byte) = data.last().copied() else {
        return empty_run();
    };
    let mut length = 0usize;
    for value in data.iter().rev() {
        if *value != byte {
            break;
        }
        length += 1;
    }
    RunRecord {
        byte: Some(byte),
        offset: Some(offset + data.len().saturating_sub(length) as u64),
        length,
    }
}

fn max_run(left: &RunRecord, right: &RunRecord) -> RunRecord {
    if right.length > left.length {
        right.clone()
    } else {
        left.clone()
    }
}

fn entropy_class(value: f64, high_threshold: f64, low_threshold: f64) -> &'static str {
    if value >= high_threshold {
        "high"
    } else if value <= low_threshold {
        "low"
    } else {
        "medium"
    }
}

fn confidence_from_delta(delta: f64, threshold: f64) -> f64 {
    if threshold <= 0.0 {
        return 0.5;
    }
    (0.45 + (delta - threshold) / (threshold * 2.0).max(0.1)).min(0.95)
}

fn find_all(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || data.len() < needle.len() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut start = 0usize;
    while start + needle.len() <= data.len() {
        let Some(index) = data[start..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            break;
        };
        let absolute = start + index;
        result.push(absolute);
        start = absolute + 1;
    }
    result
}

fn hex_byte(byte: u8) -> String {
    format!("0x{byte:02x}")
}
