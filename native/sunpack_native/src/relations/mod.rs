use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::{Regex, RegexBuilder};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
struct RelationInput {
    path: String,
    name: String,
    size: Option<u64>,
}

#[derive(Debug, Clone)]
struct FileRelationNative {
    filename: String,
    logical_name: String,
    split_role: Option<String>,
    is_split_member: bool,
    has_generic_001_head: bool,
    is_plain_numeric_member: bool,
    has_split_companions: bool,
    is_split_exe_companion: bool,
    is_disguised_split_exe_companion: bool,
    is_split_related: bool,
    match_rar_disguised: bool,
    match_rar_head: bool,
    match_001_head: bool,
    split_family: String,
    split_index: u32,
}

#[derive(Debug, Clone)]
struct ParsedVolume {
    prefix: String,
    number: u32,
    style: &'static str,
    width: usize,
}

#[pyfunction]
pub(crate) fn relations_detect_split_role(filename: &str) -> Option<String> {
    detect_split_role(filename).map(str::to_string)
}

#[pyfunction]
#[pyo3(signature = (filename, is_archive=false))]
pub(crate) fn relations_logical_name(filename: &str, is_archive: bool) -> String {
    get_logical_name(filename, is_archive)
}

#[pyfunction]
pub(crate) fn relations_parse_numbered_volume(
    py: Python<'_>,
    path: &str,
) -> PyResult<Option<Py<PyDict>>> {
    Ok(parse_numbered_volume(path)
        .map(|parsed| parsed_volume_to_dict(py, &parsed))
        .transpose()?)
}

#[pyfunction]
pub(crate) fn relations_split_sort_key(path: &str) -> (u8, u32, String) {
    split_sort_key(path)
}

#[pyfunction]
pub(crate) fn relations_build_candidate_groups(
    py: Python<'_>,
    rows: Vec<Bound<'_, PyDict>>,
) -> PyResult<Vec<Py<PyDict>>> {
    let mut dir_files: HashMap<String, Vec<RelationInput>> = HashMap::new();
    let mut dir_order: Vec<String> = Vec::new();
    for row in rows {
        let is_dir = row
            .get_item("is_dir")?
            .and_then(|value| value.extract::<bool>().ok())
            .unwrap_or(false);
        if is_dir {
            continue;
        }
        let path = row
            .get_item("path")?
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("relation row missing path"))?
            .extract::<String>()?;
        let parent = row
            .get_item("parent")?
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("relation row missing parent"))?
            .extract::<String>()?;
        let name = row
            .get_item("name")?
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("relation row missing name"))?
            .extract::<String>()?;
        let size = row
            .get_item("size")?
            .and_then(|value| value.extract::<u64>().ok());
        if !dir_files.contains_key(&parent) {
            dir_order.push(parent.clone());
        }
        dir_files
            .entry(parent.clone())
            .or_default()
            .push(RelationInput { path, name, size });
    }

    let mut groups = Vec::new();
    for directory in dir_order {
        let Some(entries) = dir_files.remove(&directory) else {
            continue;
        };
        let lower_names: HashSet<String> = entries
            .iter()
            .map(|entry| entry.name.to_ascii_lowercase())
            .collect();
        let mut relations: HashMap<String, FileRelationNative> = HashMap::new();
        for entry in &entries {
            relations.insert(
                entry.name.clone(),
                build_file_relation(&entry.name, &lower_names),
            );
        }

        let mut logical_groups: HashMap<String, Vec<RelationInput>> = HashMap::new();
        let mut logical_order: Vec<String> = Vec::new();
        for entry in entries {
            if let Some(relation) = relations.get(&entry.name) {
                if !logical_groups.contains_key(&relation.logical_name) {
                    logical_order.push(relation.logical_name.clone());
                }
                logical_groups
                    .entry(relation.logical_name.clone())
                    .or_default()
                    .push(entry);
            }
        }

        for logical_name in logical_order {
            let Some(mut group_entries) = logical_groups.remove(&logical_name) else {
                continue;
            };
            if group_entries.is_empty() {
                continue;
            }
            let has_split_relation = group_entries.iter().any(|entry| {
                relations
                    .get(&entry.name)
                    .map(|relation| relation.is_split_related)
                    .unwrap_or(false)
            });
            if has_split_relation {
                group_entries.retain(|entry| {
                    relations
                        .get(&entry.name)
                        .map(|relation| relation.is_split_related)
                        .unwrap_or(false)
                });
                if group_entries.is_empty() {
                    continue;
                }
            } else if group_entries.len() > 1 {
                for entry in group_entries {
                    groups.push(native_group_to_dict(
                        py,
                        &directory,
                        &[entry],
                        &relations,
                        false,
                    )?);
                }
                continue;
            }

            groups.push(native_group_to_dict(
                py,
                &directory,
                &group_entries,
                &relations,
                true,
            )?);
        }
    }
    Ok(groups)
}

fn native_group_to_dict(
    py: Python<'_>,
    directory: &str,
    group_entries: &[RelationInput],
    relations: &HashMap<String, FileRelationNative>,
    allow_multi_split_candidate: bool,
) -> PyResult<Py<PyDict>> {
    let head_index = select_head_index(group_entries);
    let head = &group_entries[head_index];
    let mut relation = relations
        .get(&head.name)
        .cloned()
        .unwrap_or_else(|| build_file_relation(&head.name, &HashSet::new()));
    let mut expand_misnamed = false;
    let mut is_split_candidate = relation.is_split_related;

    if group_entries.len() > 1 {
        is_split_candidate = allow_multi_split_candidate;
        expand_misnamed = true;
        if detect_split_role(&head.name) == Some("first")
            || head.name.to_ascii_lowercase().ends_with(".exe")
        {
            relation.split_role = Some("first".to_string());
        }
    } else if detect_split_role(&head.name) == Some("first") {
        expand_misnamed = true;
    }

    let all_parts: Vec<String> = std::iter::once(head.path.clone())
        .chain(
            group_entries
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != head_index)
                .map(|(_, entry)| entry.path.clone()),
        )
        .collect();

    let dict = PyDict::new(py);
    dict.set_item("directory", directory)?;
    dict.set_item("head_path", &head.path)?;
    dict.set_item("head_name", &head.name)?;
    dict.set_item("logical_name", &relation.logical_name)?;
    dict.set_item("relation", relation_to_dict(py, &relation)?)?;
    dict.set_item("all_parts", PyList::new(py, &all_parts)?)?;
    dict.set_item("is_split_candidate", is_split_candidate)?;
    dict.set_item("head_size", head.size)?;
    dict.set_item("expand_misnamed", expand_misnamed)?;
    Ok(dict.unbind())
}

fn select_head_index(entries: &[RelationInput]) -> usize {
    if entries.len() <= 1 {
        return 0;
    }
    if let Some(index) = entries
        .iter()
        .position(|entry| entry.name.to_ascii_lowercase().ends_with(".exe"))
    {
        return index;
    }
    if let Some(index) = entries
        .iter()
        .position(|entry| detect_split_role(&entry.name) == Some("first"))
    {
        return index;
    }
    entries
        .iter()
        .enumerate()
        .min_by_key(|(_, entry)| entry.name.clone())
        .map(|(index, _)| index)
        .unwrap_or(0)
}

fn build_file_relation(filename: &str, lower_names: &HashSet<String>) -> FileRelationNative {
    let (base, ext) = split_ext(filename);
    let ext = ext.to_ascii_lowercase();
    let mut split_role = detect_split_role(filename).map(str::to_string);
    let parsed_volume = parse_numbered_volume(filename);
    let mut split_family = String::new();
    let mut split_index = 0;
    if let Some(parsed) = &parsed_volume {
        split_index = parsed.number;
        if parsed.style == "rar_part" {
            split_family = "rar_part".to_string();
        } else {
            let parsed_prefix = parsed.prefix.to_ascii_lowercase();
            split_family = if parsed_prefix.ends_with(".7z") {
                "7z_numbered"
            } else if parsed_prefix.ends_with(".zip") {
                "zip_numbered"
            } else if parsed_prefix.ends_with(".rar") {
                "rar_numbered"
            } else {
                "generic_numbered"
            }
            .to_string();
        }
    }
    let mut logical_name = get_logical_name(filename, false);

    let has_generic_001_head = lower_names.contains(&format!("{base}.001").to_ascii_lowercase());
    let is_plain_numeric_member = plain_numeric_member_re().is_match(filename)
        && !archive_numbered_member_re().is_match(filename);
    let mut is_split_member = split_role.is_some();
    if split_role.as_deref() == Some("member") && is_plain_numeric_member && !has_generic_001_head {
        is_split_member = false;
        split_role = None;
    }

    let mut has_split_companions = false;
    let mut is_split_exe_companion = false;
    let mut is_disguised_split_exe_companion = false;

    if ext == ".exe" {
        has_split_companions = has_split_companions_in_dir(lower_names, &base);
        is_split_exe_companion = has_split_companions;
        if has_split_companions {
            logical_name = base.clone();
            split_family = "exe_companion".to_string();
            split_index = 1;
        }
    } else if base.to_ascii_lowercase().ends_with(".exe") {
        let logical_base = base[..base.len().saturating_sub(4)].to_string();
        has_split_companions = has_split_companions_in_dir(lower_names, &logical_base);
        is_disguised_split_exe_companion = has_split_companions;
        if has_split_companions {
            logical_name = logical_base;
            split_family = "exe_companion".to_string();
            split_index = 1;
        }
    }

    let match_rar_disguised = rar_disguised_re().is_match(filename);
    let match_rar_head = rar_head_re().is_match(&base);
    let match_001_head = head_001_re().is_match(&base);
    let is_split_related =
        is_split_member || is_split_exe_companion || is_disguised_split_exe_companion;

    FileRelationNative {
        filename: filename.to_string(),
        logical_name,
        split_role,
        is_split_member,
        has_generic_001_head,
        is_plain_numeric_member,
        has_split_companions,
        is_split_exe_companion,
        is_disguised_split_exe_companion,
        is_split_related,
        match_rar_disguised,
        match_rar_head,
        match_001_head,
        split_family,
        split_index,
    }
}

fn relation_to_dict(py: Python<'_>, relation: &FileRelationNative) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("filename", &relation.filename)?;
    dict.set_item("logical_name", &relation.logical_name)?;
    dict.set_item("split_role", &relation.split_role)?;
    dict.set_item("is_split_member", relation.is_split_member)?;
    dict.set_item("has_generic_001_head", relation.has_generic_001_head)?;
    dict.set_item("is_plain_numeric_member", relation.is_plain_numeric_member)?;
    dict.set_item("has_split_companions", relation.has_split_companions)?;
    dict.set_item("is_split_exe_companion", relation.is_split_exe_companion)?;
    dict.set_item(
        "is_disguised_split_exe_companion",
        relation.is_disguised_split_exe_companion,
    )?;
    dict.set_item("is_split_related", relation.is_split_related)?;
    dict.set_item("match_rar_disguised", relation.match_rar_disguised)?;
    dict.set_item("match_rar_head", relation.match_rar_head)?;
    dict.set_item("match_001_head", relation.match_001_head)?;
    dict.set_item("split_family", &relation.split_family)?;
    dict.set_item("split_index", relation.split_index)?;
    Ok(dict.unbind())
}

fn parsed_volume_to_dict(py: Python<'_>, parsed: &ParsedVolume) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("prefix", &parsed.prefix)?;
    dict.set_item("number", parsed.number)?;
    dict.set_item("style", parsed.style)?;
    dict.set_item("width", parsed.width)?;
    Ok(dict.unbind())
}

fn detect_split_role(filename: &str) -> Option<&'static str> {
    if split_first_patterns()
        .iter()
        .any(|pattern| pattern.is_match(filename))
    {
        return Some("first");
    }
    if split_member_pattern().is_match(filename) {
        return Some("member");
    }
    None
}

fn get_logical_name(filename: &str, is_archive: bool) -> String {
    let name = rar_part_suffix_re().replace(filename, "").to_string();
    if name != filename {
        return clean_logical_name(&name);
    }

    let second = archive_numbered_suffix_re().replace(&name, "").to_string();
    if second != name {
        return clean_logical_name(&second);
    }

    let third = plain_numeric_suffix_re().replace(&second, "").to_string();
    if third != second {
        return clean_logical_name(&third);
    }

    let (base, ext) = split_ext(filename);
    let ext = ext.to_ascii_lowercase();
    if is_archive
        || matches!(
            ext.as_str(),
            ".7z" | ".rar" | ".zip" | ".gz" | ".bz2" | ".xz" | ".exe"
        )
    {
        return clean_logical_name(&base);
    }
    clean_logical_name(filename)
}

fn parse_numbered_volume(path: &str) -> Option<ParsedVolume> {
    if let Some(captures) = parse_archive_numbered_re().captures(path) {
        return Some(ParsedVolume {
            prefix: captures.name("prefix")?.as_str().to_string(),
            number: captures.name("number")?.as_str().parse().ok()?,
            style: "numeric_suffix",
            width: 3,
        });
    }
    if let Some(captures) = parse_rar_part_re().captures(path) {
        let number = captures.name("number")?.as_str();
        return Some(ParsedVolume {
            prefix: captures.name("prefix")?.as_str().to_string(),
            number: number.parse().ok()?,
            style: "rar_part",
            width: number.len(),
        });
    }
    if let Some(captures) = parse_plain_numbered_re().captures(path) {
        return Some(ParsedVolume {
            prefix: captures.name("prefix")?.as_str().to_string(),
            number: captures.name("number")?.as_str().parse().ok()?,
            style: "plain_numeric_suffix",
            width: 3,
        });
    }
    None
}

fn split_sort_key(path: &str) -> (u8, u32, String) {
    if let Some(parsed) = parse_numbered_volume(path) {
        return (0, parsed.number, path.to_ascii_lowercase());
    }
    let lower_name = basename(path).to_ascii_lowercase();
    if let Some(captures) = old_rar_member_re().captures(&lower_name) {
        if let Some(number) = captures
            .get(1)
            .and_then(|value| value.as_str().parse::<u32>().ok())
        {
            return (1, number + 2, path.to_ascii_lowercase());
        }
    }
    if lower_name.ends_with(".rar") {
        return (1, 1, path.to_ascii_lowercase());
    }
    (2, 0, path.to_ascii_lowercase())
}

fn has_split_companions_in_dir(lower_names: &HashSet<String>, base_name: &str) -> bool {
    let escaped = regex::escape(base_name);
    let patterns = [
        format!(r"^{escaped}\.(7z|zip|rar)\.\d+(?:\.[^.]+)?$"),
        format!(r"^{escaped}\.\d{{3}}(?:\.[^.]+)?$"),
        format!(r"^{escaped}\.part\d+\.(?:rar|exe)(?:\.[^.]+)?$"),
    ];
    patterns.iter().any(|pattern| {
        RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .map(|regex| {
                lower_names
                    .iter()
                    .any(|candidate| regex.is_match(candidate))
            })
            .unwrap_or(false)
    })
}

fn split_ext(filename: &str) -> (String, String) {
    let basename_start = filename
        .rfind(['\\', '/'])
        .map(|index| index + 1)
        .unwrap_or(0);
    let basename = &filename[basename_start..];
    let Some(dot_in_base) = basename.rfind('.') else {
        return (filename.to_string(), String::new());
    };
    if dot_in_base == 0 {
        return (filename.to_string(), String::new());
    }
    let dot = basename_start + dot_in_base;
    (filename[..dot].to_string(), filename[dot..].to_string())
}

fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn clean_logical_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_string()
}

fn re(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .expect("relation regex should compile")
}

fn split_first_patterns() -> &'static [Regex; 3] {
    static VALUE: OnceLock<[Regex; 3]> = OnceLock::new();
    VALUE.get_or_init(|| {
        [
            re(r"\.part0*1\.(?:rar|exe)(?:\.[^.]+)?$"),
            re(r"\.(7z|zip|rar)\.001(?:\.[^.]+)?$"),
            re(r"\.001(?:\.[^.]+)?$"),
        ]
    })
}

fn split_member_pattern() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.(part\d+\.(?:rar|exe)|\d{3})(?:\.[^.]+)?$"))
}

fn plain_numeric_member_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.\d{3}(?:\.[^.]+)?$"))
}

fn archive_numbered_member_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$"))
}

fn rar_disguised_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(.*\.part)0*1\.rar(?:\.[^.]+)?$"))
}

fn rar_head_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(.*\.part)0*1$"))
}

fn head_001_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(.*)\.001$"))
}

fn rar_part_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.part\d+\.(?:rar|exe)(?:\.[^.]+)?$"))
}

fn archive_numbered_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$"))
}

fn plain_numeric_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.\d{3}$"))
}

fn parse_archive_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+\.(?:7z|zip|rar))\.(?P<number>\d{3})$"))
}

fn parse_rar_part_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.part(?P<number>\d+)\.(?:rar|exe)$"))
}

fn parse_plain_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.(?P<number>\d{3})$"))
}

fn old_rar_member_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.r(\d{2})$"))
}
