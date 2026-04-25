use pyo3::prelude::*;
use pyo3::types::PyDict;
use regex::RegexBuilder;
use std::collections::HashSet;
use std::fs;
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
        blocked_extensions: Vec<String>,
        min_size: Option<u64>,
    ) -> PyResult<Self> {
        Ok(Self {
            patterns: compile_case_insensitive_regexes(patterns)?,
            prune_dirs: compile_case_insensitive_regexes(prune_dirs)?,
            blocked_extensions: normalize_extensions(blocked_extensions),
            min_size,
        })
    }
}

#[pyfunction]
#[pyo3(signature = (root_path, max_depth, patterns, prune_dirs, blocked_extensions, min_size))]
pub(crate) fn scan_directory_entries(
    py: Python<'_>,
    root_path: &str,
    max_depth: Option<usize>,
    patterns: Vec<String>,
    prune_dirs: Vec<String>,
    blocked_extensions: Vec<String>,
    min_size: Option<u64>,
) -> PyResult<Vec<Py<PyDict>>> {
    let options = DirectoryScanOptions::new(patterns, prune_dirs, blocked_extensions, min_size)?;
    let entries = scan_directory(root_path, max_depth, &options)?;
    entries
        .into_iter()
        .map(|entry| entry.into_py_dict(py))
        .collect()
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
    regex_matches(&options.prune_dirs, &candidates) || regex_matches(&options.patterns, &candidates)
}

fn file_rejected_by_path(path: &Path, options: &DirectoryScanOptions) -> bool {
    if let Some(ext) = path.extension().and_then(|value| value.to_str()) {
        let ext = format!(".{}", ext.to_ascii_lowercase());
        if options.blocked_extensions.contains(&ext) {
            return true;
        }
    }
    regex_matches(&options.patterns, &path_candidates(path))
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
