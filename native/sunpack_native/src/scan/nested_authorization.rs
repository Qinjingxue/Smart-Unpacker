use crate::scan::directory::NativeDirectorySnapshot;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

type CandidateTuple = (String, Vec<String>);

#[derive(Default)]
struct ScopeStats {
    file_count: usize,
    directory_count: usize,
    total_bytes: u64,
    candidate_projects: usize,
    candidate_member_keys: HashSet<String>,
    candidate_bytes: u64,
}

struct CandidateContext {
    entry_path: String,
    scope_path: String,
    scope_key: String,
    member_keys: HashSet<String>,
    candidate_bytes: u64,
    direct_child: bool,
}

#[pyfunction]
#[pyo3(signature = (
    raw_snapshot,
    root_path,
    candidates,
    minimum_archive_byte_ratio,
    maximum_other_projects
))]
pub(crate) fn authorize_nested_candidates(
    py: Python<'_>,
    raw_snapshot: PyRef<'_, NativeDirectorySnapshot>,
    root_path: &str,
    candidates: Vec<CandidateTuple>,
    minimum_archive_byte_ratio: f64,
    maximum_other_projects: usize,
) -> PyResult<Vec<Py<PyDict>>> {
    let root = PathBuf::from(root_path);
    let mut scopes: HashMap<String, ScopeStats> = HashMap::new();
    let mut file_sizes: HashMap<String, u64> = HashMap::new();

    for (path, is_dir, size, _) in raw_snapshot.records() {
        let path_value = Path::new(path);
        let Some((scope_path, _)) = semantic_scope(path_value, &root) else {
            continue;
        };
        let scope_key = path_key(&scope_path);
        let stats = scopes.entry(scope_key).or_default();
        if is_dir {
            if path_key(path_value) != path_key(&scope_path) {
                stats.directory_count += 1;
            }
        } else {
            let size = size.unwrap_or(0);
            stats.file_count += 1;
            stats.total_bytes = stats.total_bytes.saturating_add(size);
            file_sizes.insert(path_key(path_value), size);
        }
    }

    let mut contexts = Vec::with_capacity(candidates.len());
    for (entry_path, raw_members) in candidates {
        let entry = PathBuf::from(&entry_path);
        let Some((scope_path, direct_child)) = semantic_scope(&entry, &root) else {
            contexts.push(CandidateContext {
                entry_path,
                scope_path: String::new(),
                scope_key: String::new(),
                member_keys: HashSet::new(),
                candidate_bytes: 0,
                direct_child: false,
            });
            continue;
        };
        let scope_key = path_key(&scope_path);
        let members = if raw_members.is_empty() {
            vec![entry.to_string_lossy().into_owned()]
        } else {
            raw_members
        };
        let member_keys: HashSet<String> = members
            .into_iter()
            .map(|member| path_key(Path::new(&member)))
            .collect();
        let candidate_bytes = member_keys
            .iter()
            .map(|member| file_sizes.get(member).copied().unwrap_or(0))
            .fold(0u64, u64::saturating_add);
        let stats = scopes.entry(scope_key.clone()).or_default();
        stats.candidate_projects += 1;
        stats
            .candidate_member_keys
            .extend(member_keys.iter().cloned());
        contexts.push(CandidateContext {
            entry_path,
            scope_path: scope_path.to_string_lossy().into_owned(),
            scope_key,
            member_keys,
            candidate_bytes,
            direct_child,
        });
    }

    for stats in scopes.values_mut() {
        stats.candidate_bytes = stats
            .candidate_member_keys
            .iter()
            .map(|member| file_sizes.get(member).copied().unwrap_or(0))
            .fold(0u64, u64::saturating_add);
    }

    contexts
        .into_iter()
        .map(|context| {
            let result = PyDict::new(py);
            let stats = scopes.get(&context.scope_key);
            let total_bytes = stats.map(|value| value.total_bytes).unwrap_or(0);
            let scope_candidate_bytes = stats.map(|value| value.candidate_bytes).unwrap_or(0);
            let candidate_projects = stats.map(|value| value.candidate_projects).unwrap_or(0);
            let candidate_members = stats
                .map(|value| value.candidate_member_keys.len())
                .unwrap_or(0);
            let other_files = stats
                .map(|value| value.file_count.saturating_sub(candidate_members))
                .unwrap_or(0);
            let other_directories = stats.map(|value| value.directory_count).unwrap_or(0);
            let other_projects = other_files.saturating_add(other_directories);
            let candidate_byte_ratio = ratio(context.candidate_bytes, total_bytes);
            let collective_byte_ratio = ratio(scope_candidate_bytes, total_bytes);

            let (allowed, reason) = if context.scope_key.is_empty() {
                (false, "outside_scan_root")
            } else if collective_byte_ratio >= minimum_archive_byte_ratio {
                (true, "archive_bytes_dominate")
            } else if other_projects <= maximum_other_projects {
                (true, "few_other_projects")
            } else {
                (false, "nested_context_not_archive_dominant")
            };

            result.set_item("entry_path", context.entry_path)?;
            result.set_item("scope_path", context.scope_path)?;
            result.set_item("allowed", allowed)?;
            result.set_item("reason", reason)?;
            result.set_item("direct_child", context.direct_child)?;
            result.set_item("candidate_bytes", context.candidate_bytes)?;
            result.set_item("scope_candidate_bytes", scope_candidate_bytes)?;
            result.set_item("scope_total_bytes", total_bytes)?;
            result.set_item("candidate_byte_ratio", candidate_byte_ratio)?;
            result.set_item("collective_candidate_byte_ratio", collective_byte_ratio)?;
            result.set_item("candidate_project_count", candidate_projects)?;
            result.set_item("candidate_member_count", context.member_keys.len())?;
            result.set_item("other_file_count", other_files)?;
            result.set_item("other_directory_count", other_directories)?;
            result.set_item("other_project_count", other_projects)?;
            Ok(result.unbind())
        })
        .collect()
}

fn semantic_scope(path: &Path, root: &Path) -> Option<(PathBuf, bool)> {
    let relative = path.strip_prefix(root).ok()?;
    let mut components = relative.components();
    let first = components.next()?;
    if components.next().is_none() {
        return Some((root.to_path_buf(), true));
    }
    Some((root.join(first.as_os_str()), false))
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\").to_lowercase()
}

fn ratio(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_scope_uses_first_directory_below_root() {
        let root = Path::new("C:\\out");
        assert_eq!(
            semantic_scope(Path::new("C:\\out\\wrapper\\inner.zip"), root),
            Some((PathBuf::from("C:\\out\\wrapper"), false))
        );
        assert_eq!(
            semantic_scope(Path::new("C:\\out\\root.rar"), root),
            Some((PathBuf::from("C:\\out"), true))
        );
    }
}
