use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

const BUFFER_SIZE: usize = 1024 * 1024;

#[pyfunction]
pub(crate) fn compute_directory_crc_manifest(
    py: Python<'_>,
    output_dir: &str,
    max_files: Option<usize>,
) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let result = PyDict::new(py);
    let files = PyList::empty(py);
    let errors = PyList::empty(py);
    result.set_item("files", &files)?;
    result.set_item("errors", &errors)?;

    if !root.exists() {
        result.set_item("status", "missing")?;
        return Ok(result.unbind());
    }
    if !root.is_dir() {
        result.set_item("status", "not_directory")?;
        return Ok(result.unbind());
    }

    let limit = max_files.unwrap_or(usize::MAX);
    let mut total_files = 0usize;
    let mut scanned_files = 0usize;
    walk_directory(
        py,
        &root,
        &root,
        limit,
        &mut total_files,
        &mut scanned_files,
        &files,
        &errors,
    )?;
    result.set_item("status", "ok")?;
    result.set_item("total_files", total_files)?;
    result.set_item("scanned_files", scanned_files)?;
    result.set_item("truncated", scanned_files < total_files)?;
    Ok(result.unbind())
}

#[pyfunction]
pub(crate) fn sample_directory_readability(
    py: Python<'_>,
    output_dir: &str,
    max_samples: Option<usize>,
    read_bytes: Option<usize>,
) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let result = PyDict::new(py);
    let samples = PyList::empty(py);
    let errors = PyList::empty(py);
    result.set_item("samples", &samples)?;
    result.set_item("errors", &errors)?;

    if !root.exists() {
        result.set_item("status", "missing")?;
        return Ok(result.unbind());
    }
    if !root.is_dir() {
        result.set_item("status", "not_directory")?;
        return Ok(result.unbind());
    }

    let max_samples = max_samples.unwrap_or(64).max(1);
    let read_bytes = read_bytes.unwrap_or(4096).max(1);
    let mut file_paths = Vec::new();
    collect_regular_files(&root, &root, &mut file_paths, &errors, py)?;

    let selected = select_sample_paths(&file_paths, max_samples);
    let mut readable_files = 0usize;
    let mut empty_files = 0usize;
    let mut unreadable_files = 0usize;
    let mut bytes_read = 0u64;

    for path in selected {
        match read_sample(&path, read_bytes) {
            Ok(sample) => {
                readable_files += 1;
                if sample.size == 0 {
                    empty_files += 1;
                }
                bytes_read += sample.bytes_read;
                let item = PyDict::new(py);
                item.set_item("path", relative_path(&path, &root))?;
                item.set_item("size", sample.size)?;
                item.set_item("bytes_read", sample.bytes_read)?;
                item.set_item("empty", sample.size == 0)?;
                samples.append(item)?;
            }
            Err(err) => {
                unreadable_files += 1;
                append_error(py, &errors, &path, &root, &err.to_string())?;
            }
        }
    }

    result.set_item("status", "ok")?;
    result.set_item("total_files", file_paths.len())?;
    result.set_item("sampled_files", readable_files + unreadable_files)?;
    result.set_item("readable_files", readable_files)?;
    result.set_item("unreadable_files", unreadable_files)?;
    result.set_item("empty_files", empty_files)?;
    result.set_item("bytes_read", bytes_read)?;
    result.set_item("truncated", file_paths.len() > max_samples)?;
    Ok(result.unbind())
}

#[pyfunction]
pub(crate) fn match_archive_output_crc_coverage(
    py: Python<'_>,
    archive_files: &Bound<'_, PyAny>,
    output_dir: &str,
    max_files: Option<usize>,
) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let result = PyDict::new(py);
    let errors = PyList::empty(py);
    result.set_item("errors", &errors)?;

    if !root.exists() {
        result.set_item("status", "missing")?;
        return Ok(result.unbind());
    }
    if !root.is_dir() {
        result.set_item("status", "not_directory")?;
        return Ok(result.unbind());
    }

    let expected = archive_items_from_py(archive_files)?;
    let limit = max_files.unwrap_or(usize::MAX);
    let mut output_files = Vec::new();
    let mut total_files = 0usize;
    let mut scanned_files = 0usize;
    collect_crc_output_files(
        py,
        &root,
        &root,
        limit,
        &mut total_files,
        &mut scanned_files,
        &mut output_files,
        &errors,
    )?;

    let output_index = OutputIndex::new(output_files);
    let mismatches = PyList::empty(py);
    let missing = PyList::empty(py);
    let observations = PyList::empty(py);

    let mut coverage = CoverageAccumulator::default();
    coverage.expected_files = expected.len();

    for item in expected {
        if let Some(expected_size) = item.size {
            coverage.expected_bytes += expected_size;
        }

        if item.unsafe_path {
            coverage.failed_files += 1;
            observations.append(observation_dict(
                py,
                &item.path,
                &item.path,
                "failed",
                0,
                item.size,
                Some(0.0),
                item.crc32,
                None,
                item.has_crc,
                None,
                "",
                true,
                &item.raw_path,
                "output_filesystem",
            )?)?;
            continue;
        }

        let Some(output_item) = output_index.match_item(&item.path) else {
            coverage.missing_files += 1;
            missing.append(item.path.as_str())?;
            observations.append(observation_dict(
                py,
                &item.path,
                &item.path,
                "missing",
                0,
                item.size,
                Some(0.0),
                item.crc32,
                None,
                item.has_crc,
                None,
                "",
                false,
                &item.raw_path,
                "",
            )?)?;
            continue;
        };

        coverage.matched_files += 1;
        let size_progress = size_progress(Some(output_item.size), item.size);
        if let Some(expected_size) = item.size {
            coverage.matched_bytes += output_item.size.min(expected_size);
        } else {
            coverage.matched_bytes += output_item.size;
        }

        let crc_ok = if item.has_crc {
            item.crc32
                .map(|expected_crc| expected_crc == output_item.crc32)
        } else {
            None
        };
        let mut state = "complete";
        let mut progress = size_progress;
        let mut failed_crc = false;

        if item.has_crc && crc_ok == Some(false) {
            state = "failed";
            progress = Some(0.0);
            failed_crc = true;
            coverage.failed_files += 1;
        } else if let Some(expected_size) = item.size {
            if output_item.size < expected_size {
                state = "partial";
                coverage.partial_files += 1;
            } else {
                coverage.complete_files += 1;
                coverage.complete_bytes += expected_size;
            }
        } else {
            coverage.complete_files += 1;
            coverage.complete_bytes += output_item.size;
        }

        if failed_crc {
            let mismatch = PyDict::new(py);
            mismatch.set_item("path", item.path.as_str())?;
            mismatch.set_item("expected_crc32", item.crc32.unwrap_or(0))?;
            mismatch.set_item("actual_crc32", output_item.crc32)?;
            mismatches.append(mismatch)?;
        }

        observations.append(observation_dict(
            py,
            &output_item.path,
            &item.path,
            state,
            output_item.size,
            item.size,
            progress,
            item.crc32,
            Some(output_item.crc32),
            item.has_crc,
            crc_ok,
            output_item.matched_by,
            false,
            &item.raw_path,
            "",
        )?)?;
    }

    let coverage_dict = coverage.to_py(py)?;
    result.set_item("status", "ok")?;
    result.set_item("total_files", total_files)?;
    result.set_item("scanned_files", scanned_files)?;
    result.set_item("truncated", scanned_files < total_files)?;
    result.set_item("mismatches", mismatches)?;
    result.set_item("missing", missing)?;
    result.set_item("coverage", coverage_dict)?;
    result.set_item("observations", observations)?;
    Ok(result.unbind())
}

fn walk_directory(
    py: Python<'_>,
    root: &Path,
    current: &Path,
    limit: usize,
    total_files: &mut usize,
    scanned_files: &mut usize,
    files: &Bound<'_, PyList>,
    errors: &Bound<'_, PyList>,
) -> PyResult<()> {
    let entries = match std::fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) => {
            append_error(py, errors, current, root, &err.to_string())?;
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                append_error(py, errors, current, root, &err.to_string())?;
                continue;
            }
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                append_error(py, errors, &path, root, &err.to_string())?;
                continue;
            }
        };
        if metadata.is_dir() {
            walk_directory(
                py,
                root,
                &path,
                limit,
                total_files,
                scanned_files,
                files,
                errors,
            )?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        *total_files += 1;
        if *scanned_files >= limit {
            continue;
        }
        match crc32_file(&path) {
            Ok(crc32) => {
                let item = PyDict::new(py);
                item.set_item("path", relative_path(&path, root))?;
                item.set_item("size", metadata.len())?;
                item.set_item("crc32", crc32)?;
                files.append(item)?;
                *scanned_files += 1;
            }
            Err(err) => append_error(py, errors, &path, root, &err.to_string())?,
        }
    }
    Ok(())
}

fn collect_crc_output_files(
    py: Python<'_>,
    root: &Path,
    current: &Path,
    limit: usize,
    total_files: &mut usize,
    scanned_files: &mut usize,
    files: &mut Vec<OutputFile>,
    errors: &Bound<'_, PyList>,
) -> PyResult<()> {
    let entries = match std::fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) => {
            append_error(py, errors, current, root, &err.to_string())?;
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                append_error(py, errors, current, root, &err.to_string())?;
                continue;
            }
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                append_error(py, errors, &path, root, &err.to_string())?;
                continue;
            }
        };
        if metadata.is_dir() {
            if entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case(".sunpack")
            {
                continue;
            }
            collect_crc_output_files(
                py,
                root,
                &path,
                limit,
                total_files,
                scanned_files,
                files,
                errors,
            )?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        *total_files += 1;
        if *scanned_files >= limit {
            continue;
        }
        let rel_path = clean_relative_archive_path(&relative_path(&path, root));
        if rel_path.is_empty() {
            continue;
        }
        match crc32_file(&path) {
            Ok(crc32) => {
                files.push(OutputFile {
                    path: rel_path,
                    size: metadata.len(),
                    crc32,
                    matched_by: "",
                });
                *scanned_files += 1;
            }
            Err(err) => append_error(py, errors, &path, root, &err.to_string())?,
        }
    }
    Ok(())
}

fn append_error(
    py: Python<'_>,
    errors: &Bound<'_, PyList>,
    path: &Path,
    root: &Path,
    message: &str,
) -> PyResult<()> {
    let item = PyDict::new(py);
    item.set_item("path", relative_path(path, root))?;
    item.set_item("message", message)?;
    errors.append(item)
}

fn collect_regular_files(
    root: &Path,
    current: &Path,
    paths: &mut Vec<PathBuf>,
    errors: &Bound<'_, PyList>,
    py: Python<'_>,
) -> PyResult<()> {
    let entries = match std::fs::read_dir(current) {
        Ok(entries) => entries,
        Err(err) => {
            append_error(py, errors, current, root, &err.to_string())?;
            return Ok(());
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                append_error(py, errors, current, root, &err.to_string())?;
                continue;
            }
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                append_error(py, errors, &path, root, &err.to_string())?;
                continue;
            }
        };
        if metadata.is_dir() {
            collect_regular_files(root, &path, paths, errors, py)?;
        } else if metadata.is_file() {
            paths.push(path);
        }
    }
    Ok(())
}

fn select_sample_paths(paths: &[PathBuf], max_samples: usize) -> Vec<PathBuf> {
    if paths.len() <= max_samples {
        return paths.to_vec();
    }
    if max_samples == 1 {
        return vec![paths[0].clone()];
    }
    let last = paths.len() - 1;
    (0..max_samples)
        .map(|index| {
            let selected = index * last / (max_samples - 1);
            paths[selected].clone()
        })
        .collect()
}

#[derive(Clone)]
struct ArchiveFile {
    path: String,
    raw_path: String,
    unsafe_path: bool,
    size: Option<u64>,
    has_crc: bool,
    crc32: Option<u32>,
}

#[derive(Clone)]
struct OutputFile {
    path: String,
    size: u64,
    crc32: u32,
    matched_by: &'static str,
}

struct OutputIndex {
    files: Vec<OutputFile>,
    by_path: HashMap<String, usize>,
    by_basename: HashMap<String, Vec<usize>>,
}

impl OutputIndex {
    fn new(files: Vec<OutputFile>) -> Self {
        let mut by_path = HashMap::with_capacity(files.len());
        let mut by_basename: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, item) in files.iter().enumerate() {
            by_path
                .entry(normalize_match_path(&item.path))
                .or_insert(index);
            by_basename
                .entry(normalize_match_name(basename(&item.path)))
                .or_default()
                .push(index);
        }
        Self {
            files,
            by_path,
            by_basename,
        }
    }

    fn match_item(&self, expected_path: &str) -> Option<OutputFile> {
        let normalized = normalize_match_path(expected_path);
        if let Some(index) = self.by_path.get(&normalized) {
            let mut item = self.files[*index].clone();
            item.matched_by = "path";
            return Some(item);
        }
        let basename = normalize_match_name(basename(&normalized));
        let candidates = self.by_basename.get(&basename)?;
        if candidates.len() != 1 {
            return None;
        }
        let mut item = self.files[candidates[0]].clone();
        item.matched_by = "basename";
        Some(item)
    }
}

#[derive(Default)]
struct CoverageAccumulator {
    expected_files: usize,
    matched_files: usize,
    complete_files: usize,
    partial_files: usize,
    failed_files: usize,
    missing_files: usize,
    expected_bytes: u64,
    matched_bytes: u64,
    complete_bytes: u64,
}

impl CoverageAccumulator {
    fn to_py(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let file_coverage = self.matched_files as f64 / self.expected_files.max(1) as f64;
        let byte_coverage = if self.expected_bytes > 0 {
            (self.matched_bytes as f64 / self.expected_bytes as f64).clamp(0.0, 1.0)
        } else {
            file_coverage
        };
        let mut completeness = ((file_coverage + byte_coverage) / 2.0).clamp(0.0, 1.0);
        if self.expected_files > 0 && self.failed_files > 0 {
            let non_failed =
                self.expected_files
                    .saturating_sub(self.failed_files + self.missing_files) as f64;
            completeness = completeness.min((non_failed / self.expected_files as f64).max(0.0));
        }

        let dict = PyDict::new(py);
        dict.set_item("completeness", round6(completeness))?;
        dict.set_item("file_coverage", round6(file_coverage))?;
        dict.set_item("byte_coverage", round6(byte_coverage))?;
        dict.set_item("expected_files", self.expected_files)?;
        dict.set_item("matched_files", self.matched_files)?;
        dict.set_item("complete_files", self.complete_files)?;
        dict.set_item("partial_files", self.partial_files)?;
        dict.set_item("failed_files", self.failed_files)?;
        dict.set_item("missing_files", self.missing_files)?;
        dict.set_item("expected_bytes", self.expected_bytes)?;
        dict.set_item("matched_bytes", self.matched_bytes)?;
        dict.set_item("complete_bytes", self.complete_bytes)?;
        Ok(dict.unbind())
    }
}

fn archive_items_from_py(archive_files: &Bound<'_, PyAny>) -> PyResult<Vec<ArchiveFile>> {
    let mut items = Vec::new();
    for item in archive_files.try_iter()? {
        let item = item?;
        let Ok(dict) = item.cast::<PyDict>() else {
            continue;
        };
        let raw_path = py_string(dict, "path")?
            .or_else(|| py_string(dict, "name").ok().flatten())
            .unwrap_or_default();
        let path = clean_relative_archive_path(&raw_path);
        if path.is_empty() {
            continue;
        }
        let has_crc = py_bool(dict, "has_crc")?
            .unwrap_or_else(|| py_u32(dict, "crc32").ok().flatten().is_some());
        items.push(ArchiveFile {
            path,
            raw_path: raw_path.clone(),
            unsafe_path: unsafe_archive_path(&raw_path, &clean_relative_archive_path(&raw_path)),
            size: py_u64(dict, "size")?.or_else(|| py_u64(dict, "unpacked_size").ok().flatten()),
            has_crc,
            crc32: py_u32(dict, "crc32")?,
        });
    }
    Ok(items)
}

fn observation_dict(
    py: Python<'_>,
    path: &str,
    archive_path: &str,
    state: &str,
    bytes_written: u64,
    expected_size: Option<u64>,
    progress: Option<f64>,
    crc_expected: Option<u32>,
    crc_actual: Option<u32>,
    expected_has_crc: bool,
    crc_ok: Option<bool>,
    matched_by: &str,
    path_blocked: bool,
    raw_archive_path: &str,
    failure_kind: &str,
) -> PyResult<Py<PyDict>> {
    let item = PyDict::new(py);
    item.set_item("path", path)?;
    item.set_item("archive_path", archive_path)?;
    item.set_item("state", state)?;
    item.set_item("bytes_written", bytes_written)?;
    item.set_item("expected_size", expected_size)?;
    item.set_item("progress", progress)?;
    item.set_item("crc_expected", crc_expected)?;
    item.set_item("crc_actual", crc_actual)?;

    let details = PyDict::new(py);
    details.set_item("expected_has_crc", expected_has_crc)?;
    details.set_item("crc_ok", crc_ok)?;
    details.set_item("matched_by", matched_by)?;
    details.set_item("path_blocked", path_blocked)?;
    details.set_item("raw_archive_path", raw_archive_path)?;
    details.set_item("failure_kind", failure_kind)?;
    item.set_item("details", details)?;
    Ok(item.unbind())
}

fn py_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    Ok(Some(value.str()?.to_string_lossy().into_owned()))
}

fn py_bool(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<bool>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    value.extract::<bool>().map(Some)
}

fn py_u64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    if let Ok(value) = value.extract::<u64>() {
        return Ok(Some(value));
    }
    if let Ok(value) = value.extract::<i64>() {
        return Ok(Some(value.max(0) as u64));
    }
    Ok(None)
}

fn py_u32(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u32>> {
    Ok(py_u64(dict, key)?.map(|value| (value & 0xFFFF_FFFF) as u32))
}

fn clean_relative_archive_path(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim()
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/")
}

fn normalize_match_name(value: &str) -> String {
    value.nfc().collect::<String>().to_lowercase()
}

fn normalize_match_path(value: &str) -> String {
    clean_relative_archive_path(value)
        .split('/')
        .filter(|part| !part.is_empty())
        .map(normalize_match_name)
        .collect::<Vec<_>>()
        .join("/")
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn unsafe_archive_path(raw_path: &str, cleaned: &str) -> bool {
    let text = raw_path.replace('\\', "/");
    if text.is_empty() {
        return false;
    }
    if text.starts_with('/') || text.starts_with("//") {
        return true;
    }
    if text.len() >= 3 && text.as_bytes()[1] == b':' && text.as_bytes()[2] == b'/' {
        return true;
    }
    let parts: Vec<&str> = text.split('/').filter(|part| !part.is_empty()).collect();
    if parts.iter().any(|part| *part == "..") {
        return true;
    }
    if parts.iter().any(|part| windows_reserved_path_part(part)) {
        return true;
    }
    if parts.iter().any(|part| part.contains(':')) {
        return true;
    }
    !cleaned.is_empty() && cleaned != text.trim().trim_matches('/')
}

fn windows_reserved_path_part(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or("")
        .trim()
        .trim_end_matches([' ', '.'])
        .to_lowercase();
    if stem.is_empty() {
        return false;
    }
    matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && stem[3..].chars().all(|c| ('1'..='9').contains(&c)))
}

fn size_progress(actual_size: Option<u64>, expected_size: Option<u64>) -> Option<f64> {
    match (actual_size, expected_size) {
        (Some(_), Some(0)) => Some(1.0),
        (Some(actual), Some(expected)) => Some((actual as f64 / expected as f64).clamp(0.0, 1.0)),
        (Some(_), None) => None,
        (None, Some(_)) => None,
        (None, None) => None,
    }
}

fn round6(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

struct ReadSample {
    size: u64,
    bytes_read: u64,
}

fn read_sample(path: &Path, read_bytes: usize) -> std::io::Result<ReadSample> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(ReadSample {
            size,
            bytes_read: 0,
        });
    }
    let mut buffer = vec![0u8; read_bytes];
    let head_read = file.read(&mut buffer)? as u64;
    let mut tail_read = 0u64;
    if size > read_bytes as u64 {
        let tail_offset = size.saturating_sub(read_bytes as u64);
        file.seek(SeekFrom::Start(tail_offset))?;
        tail_read = file.read(&mut buffer)? as u64;
    }
    Ok(ReadSample {
        size,
        bytes_read: head_read + tail_read,
    })
}

fn relative_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn crc32_file(path: &Path) -> std::io::Result<u32> {
    let mut file = File::open(path)?;
    let mut crc = 0xFFFF_FFFFu32;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        crc = crc32_update(crc, &buffer[..read]);
    }
    Ok(!crc)
}

fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    let table = crc32_table();
    for byte in bytes {
        let index = ((crc ^ u32::from(*byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[index];
    }
    crc
}

fn crc32_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for i in 0..256u32 {
            let mut crc = i;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
            table[i as usize] = crc;
        }
        table
    })
}
