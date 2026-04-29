use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::RegexBuilder;
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryEntryRecord {
    path: String,
    is_dir: bool,
    size: Option<u64>,
    mtime_ns: Option<u64>,
}

struct DirectoryScanOptions {
    patterns: Vec<regex::Regex>,
    prune_dirs: Vec<regex::Regex>,
    whitelist_patterns: Vec<regex::Regex>,
    whitelist_prune_dirs: Vec<regex::Regex>,
    blocked_extensions: HashSet<String>,
    min_size: Option<u64>,
}

impl DirectoryEntryRecord {
    fn into_py_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("path", self.path)?;
        dict.set_item("is_dir", self.is_dir)?;
        dict.set_item("size", self.size)?;
        dict.set_item("mtime_ns", self.mtime_ns)?;
        Ok(dict.unbind())
    }
}

impl DirectoryScanOptions {
    fn new(
        patterns: Vec<String>,
        prune_dirs: Vec<String>,
        whitelist_patterns: Vec<String>,
        whitelist_prune_dirs: Vec<String>,
        blocked_extensions: Vec<String>,
        min_size: Option<u64>,
    ) -> PyResult<Self> {
        Ok(Self {
            patterns: compile_case_insensitive_regexes(patterns)?,
            prune_dirs: compile_case_insensitive_regexes(prune_dirs)?,
            whitelist_patterns: compile_case_insensitive_regexes(whitelist_patterns)?,
            whitelist_prune_dirs: compile_case_insensitive_regexes(whitelist_prune_dirs)?,
            blocked_extensions: normalize_extensions(blocked_extensions),
            min_size,
        })
    }
}

#[pyfunction]
#[pyo3(signature = (root_path, max_depth, patterns, prune_dirs, blocked_extensions, min_size, whitelist_patterns=Vec::new(), whitelist_prune_dirs=Vec::new()))]
pub(crate) fn scan_directory_entries(
    py: Python<'_>,
    root_path: &str,
    max_depth: Option<usize>,
    patterns: Vec<String>,
    prune_dirs: Vec<String>,
    blocked_extensions: Vec<String>,
    min_size: Option<u64>,
    whitelist_patterns: Vec<String>,
    whitelist_prune_dirs: Vec<String>,
) -> PyResult<Vec<Py<PyDict>>> {
    let options = DirectoryScanOptions::new(
        patterns,
        prune_dirs,
        whitelist_patterns,
        whitelist_prune_dirs,
        blocked_extensions,
        min_size,
    )?;
    let entries = scan_directory(root_path, max_depth, &options)?;
    entries
        .into_iter()
        .map(|entry| entry.into_py_dict(py))
        .collect()
}

#[pyfunction]
pub(crate) fn list_regular_files_in_directory(
    py: Python<'_>,
    directory: &str,
) -> PyResult<Vec<Py<PyDict>>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return Ok(Vec::new()),
    };
    let mut records = Vec::new();
    for item in entries {
        let Ok(entry) = item else {
            continue;
        };
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }
        records.push(DirectoryEntryRecord {
            path: path_to_string(&path),
            is_dir: false,
            size: Some(metadata.len()),
            mtime_ns: metadata_mtime_ns(&metadata),
        });
    }
    records
        .into_iter()
        .map(|entry| entry.into_py_dict(py))
        .collect()
}

#[pyfunction]
#[pyo3(signature = (paths, magic_size=16))]
pub(crate) fn batch_file_head_facts(
    py: Python<'_>,
    paths: Vec<String>,
    magic_size: usize,
) -> PyResult<Vec<Py<PyDict>>> {
    let records = py.detach(|| {
        paths
            .into_iter()
            .map(|path| file_head_record(path, magic_size))
            .collect::<Vec<_>>()
    });
    records
        .into_iter()
        .map(|record| record.into_py_dict(py))
        .collect()
}

#[pyfunction]
pub(crate) fn scan_output_tree(py: Python<'_>, output_dir: &str) -> PyResult<Py<PyDict>> {
    let root = PathBuf::from(output_dir);
    let result = PyDict::new(py);
    result.set_item("exists", root.exists())?;
    result.set_item("is_dir", root.is_dir())?;
    result.set_item("file_count", 0usize)?;
    result.set_item("dir_count", 0usize)?;
    result.set_item("total_size", 0u64)?;
    result.set_item("transient_file_count", 0usize)?;
    result.set_item("unreadable_count", 0usize)?;
    result.set_item("files", PyList::empty(py))?;
    if !root.is_dir() {
        return Ok(result.unbind());
    }

    let mut stats = OutputTreeStats::default();
    walk_output_tree(py, &root, &root, &mut stats)?;
    result.set_item("file_count", stats.file_count)?;
    result.set_item("dir_count", stats.dir_count)?;
    result.set_item("total_size", stats.total_size)?;
    result.set_item("transient_file_count", stats.transient_file_count)?;
    result.set_item("unreadable_count", stats.unreadable_count)?;
    result.set_item("files", PyList::new(py, stats.files)?)?;
    Ok(result.unbind())
}

struct FileHeadRecord {
    path: String,
    exists: bool,
    is_file: bool,
    size: Option<u64>,
    mtime_ns: Option<u64>,
    magic: Vec<u8>,
}

impl FileHeadRecord {
    fn into_py_dict(self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("path", self.path)?;
        dict.set_item("exists", self.exists)?;
        dict.set_item("is_file", self.is_file)?;
        dict.set_item("size", self.size)?;
        dict.set_item("mtime_ns", self.mtime_ns)?;
        dict.set_item("magic", pyo3::types::PyBytes::new(py, &self.magic))?;
        Ok(dict.unbind())
    }
}

fn file_head_record(path: String, magic_size: usize) -> FileHeadRecord {
    let path_buf = PathBuf::from(&path);
    let metadata = fs::metadata(&path_buf).ok();
    let is_file = metadata
        .as_ref()
        .map(|item| item.is_file())
        .unwrap_or(false);
    let mut magic = Vec::new();
    if is_file && magic_size > 0 {
        if let Ok(mut handle) = fs::File::open(&path_buf) {
            let limit = magic_size.min(1024 * 1024);
            let mut buffer = vec![0u8; limit];
            if let Ok(count) = handle.read(&mut buffer) {
                buffer.truncate(count);
                magic = buffer;
            }
        }
    }
    FileHeadRecord {
        path,
        exists: metadata.is_some(),
        is_file,
        size: metadata.as_ref().map(|item| item.len()),
        mtime_ns: metadata.as_ref().and_then(metadata_mtime_ns),
        magic,
    }
}

#[derive(Default)]
struct OutputTreeStats {
    file_count: usize,
    dir_count: usize,
    total_size: u64,
    transient_file_count: usize,
    unreadable_count: usize,
    files: Vec<Py<PyDict>>,
}

fn walk_output_tree(
    py: Python<'_>,
    root: &Path,
    current: &Path,
    stats: &mut OutputTreeStats,
) -> PyResult<()> {
    let entries = match fs::read_dir(current) {
        Ok(entries) => entries,
        Err(_) => {
            stats.unreadable_count += 1;
            return Ok(());
        }
    };
    for item in entries {
        let Ok(entry) = item else {
            stats.unreadable_count += 1;
            continue;
        };
        let path = entry.path();
        let file_name = entry.file_name().to_string_lossy().to_string();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                stats.unreadable_count += 1;
                continue;
            }
        };
        if metadata.is_dir() {
            if file_name == ".sunpack" {
                continue;
            }
            stats.dir_count += 1;
            walk_output_tree(py, root, &path, stats)?;
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        stats.file_count += 1;
        let size = metadata.len();
        stats.total_size = stats.total_size.saturating_add(size);
        if is_transient_file_name(&file_name) {
            stats.transient_file_count += 1;
        }
        let relative = path
            .strip_prefix(root)
            .map(path_to_string)
            .unwrap_or_else(|_| file_name.clone());
        let dict = PyDict::new(py);
        dict.set_item("path", normalize_path_separator(relative))?;
        dict.set_item("abs_path", path_to_string(&path))?;
        dict.set_item("size", size)?;
        stats.files.push(dict.unbind());
    }
    Ok(())
}

fn is_transient_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".tmp", ".temp", ".part", ".partial", ".crdownload"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn compile_case_insensitive_regexes(patterns: Vec<String>) -> PyResult<Vec<regex::Regex>> {
    let mut regexes = Vec::new();
    for pattern in patterns {
        let regex = RegexBuilder::new(&pattern)
            .case_insensitive(true)
            .build()
            .map_err(|err| pyo3::exceptions::PyValueError::new_err(err.to_string()))?;
        regexes.push(regex);
    }
    Ok(regexes)
}

fn normalize_extensions(extensions: Vec<String>) -> HashSet<String> {
    extensions
        .into_iter()
        .filter_map(|ext| {
            let ext = ext.trim().to_ascii_lowercase();
            if ext.is_empty() {
                None
            } else if ext.starts_with('.') {
                Some(ext)
            } else {
                Some(format!(".{ext}"))
            }
        })
        .collect()
}

fn scan_directory(
    root_path: &str,
    max_depth: Option<usize>,
    options: &DirectoryScanOptions,
) -> PyResult<Vec<DirectoryEntryRecord>> {
    let root = PathBuf::from(root_path);
    if !root.exists() {
        return Ok(Vec::new());
    }
    if root.is_file() {
        return Ok(file_record_if_accepted(&root, options)
            .into_iter()
            .collect());
    }

    let mut records = Vec::new();
    let mut stack = vec![(root, 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let read_dir = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        let mut child_dirs = Vec::new();
        for item in read_dir {
            let Ok(entry) = item else {
                continue;
            };
            let path = entry.path();
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if metadata.is_dir() {
                if max_depth.is_some_and(|limit| depth >= limit) {
                    continue;
                }
                if dir_rejected(&path, options) {
                    continue;
                }
                records.push(DirectoryEntryRecord {
                    path: path_to_string(&path),
                    is_dir: true,
                    size: None,
                    mtime_ns: None,
                });
                child_dirs.push(path);
                continue;
            }

            if !metadata.is_file() || file_rejected_by_path(&path, options) {
                continue;
            }
            let size = metadata.len();
            if options.min_size.is_some_and(|minimum| size < minimum) {
                continue;
            }
            records.push(DirectoryEntryRecord {
                path: path_to_string(&path),
                is_dir: false,
                size: Some(size),
                mtime_ns: metadata_mtime_ns(&metadata),
            });
        }

        child_dirs.sort();
        for child in child_dirs.into_iter().rev() {
            stack.push((child, depth + 1));
        }
    }
    Ok(records)
}

fn file_record_if_accepted(
    path: &Path,
    options: &DirectoryScanOptions,
) -> Option<DirectoryEntryRecord> {
    if file_rejected_by_path(path, options) {
        return None;
    }
    let metadata = fs::metadata(path).ok()?;
    let size = metadata.len();
    if options.min_size.is_some_and(|minimum| size < minimum) {
        return None;
    }
    Some(DirectoryEntryRecord {
        path: path_to_string(path),
        is_dir: false,
        size: Some(size),
        mtime_ns: metadata_mtime_ns(&metadata),
    })
}

fn dir_rejected(path: &Path, options: &DirectoryScanOptions) -> bool {
    let candidates = path_candidates(path);
    regex_matches(&options.prune_dirs, &candidates)
        || regex_matches(&options.patterns, &candidates)
        || !dir_allowed_by_whitelist(&candidates, options)
}

fn file_rejected_by_path(path: &Path, options: &DirectoryScanOptions) -> bool {
    if let Some(ext) = path.extension().and_then(|value| value.to_str()) {
        let ext = format!(".{}", ext.to_ascii_lowercase());
        if options.blocked_extensions.contains(&ext) {
            return true;
        }
    }
    let candidates = path_candidates(path);
    regex_matches(&options.patterns, &candidates) || !file_allowed_by_whitelist(&candidates, options)
}

fn dir_allowed_by_whitelist(candidates: &[String], options: &DirectoryScanOptions) -> bool {
    if options.whitelist_patterns.is_empty() && options.whitelist_prune_dirs.is_empty() {
        return true;
    }
    regex_matches(&options.whitelist_patterns, candidates)
        || regex_matches(&options.whitelist_prune_dirs, candidates)
}

fn file_allowed_by_whitelist(candidates: &[String], options: &DirectoryScanOptions) -> bool {
    if options.whitelist_patterns.is_empty() {
        return true;
    }
    regex_matches(&options.whitelist_patterns, candidates)
}

fn regex_matches(regexes: &[regex::Regex], candidates: &[String]) -> bool {
    regexes
        .iter()
        .any(|regex| candidates.iter().any(|candidate| regex.is_match(candidate)))
}

fn path_candidates(path: &Path) -> Vec<String> {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = path.parent().map(path_to_string).unwrap_or_default();
    vec![
        name,
        normalize_path_separator(parent),
        normalize_path_separator(path_to_string(path)),
    ]
}

fn normalize_path_separator(path: String) -> String {
    path.replace('\\', "/")
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn metadata_mtime_ns(metadata: &fs::Metadata) -> Option<u64> {
    let modified = metadata.modified().ok()?;
    let duration = modified.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_nanos()).ok()
}
