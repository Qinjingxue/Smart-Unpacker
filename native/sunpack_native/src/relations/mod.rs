use crate::scan::directory::NativeDirectorySnapshot;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::{Regex, RegexBuilder};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;
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
    family: &'static str,
    decorated: bool,
}

#[derive(Debug, Clone)]
struct NativeSplitVolume {
    path: String,
    number: u32,
    role: &'static str,
    source: &'static str,
    style: String,
    prefix: String,
    width: usize,
}

#[derive(Debug, Clone)]
struct NativeSplitContract {
    volumes: Vec<NativeSplitVolume>,
    complete: Option<bool>,
    missing_reason: String,
    missing_indices: Vec<u32>,
    missing_ranges: Vec<(u32, u32)>,
    layout_status: &'static str,
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
pub(crate) fn relations_build_candidate_groups_from_snapshot(
    py: Python<'_>,
    snapshot: PyRef<'_, NativeDirectorySnapshot>,
) -> PyResult<Vec<Py<PyDict>>> {
    let mut dir_files: HashMap<String, Vec<RelationInput>> = HashMap::new();
    let mut dir_order: Vec<String> = Vec::new();
    for (path, size) in snapshot.file_records() {
        let path_value = Path::new(path);
        let parent = path_value
            .parent()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default();
        let name = path_value
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default();
        if !dir_files.contains_key(&parent) {
            dir_order.push(parent.clone());
        }
        dir_files.entry(parent).or_default().push(RelationInput {
            path: path.to_string(),
            name,
            size,
        });
    }
    build_candidate_groups_from_inputs(py, dir_files, dir_order)
}

fn build_candidate_groups_from_inputs(
    py: Python<'_>,
    mut dir_files: HashMap<String, Vec<RelationInput>>,
    dir_order: Vec<String>,
) -> PyResult<Vec<Py<PyDict>>> {
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
        promote_content_confirmed_plain_numeric_groups(&entries, &mut relations);

        let mut logical_groups: HashMap<String, Vec<RelationInput>> = HashMap::new();
        let mut logical_order: Vec<String> = Vec::new();
        for entry in entries {
            if let Some(relation) = relations.get(&entry.name) {
                let group_key = relation_group_key(relation);
                if !logical_groups.contains_key(&group_key) {
                    logical_order.push(group_key.clone());
                }
                logical_groups.entry(group_key).or_default().push(entry);
            }
        }

        // A canonical archive name can safely stand in for a missing numbered
        // head only inside the same declared extension family.  This preserves
        // `name.7z + name.7z.002` without allowing an unmarked or cross-format
        // sibling to enter the group.
        let plain_head_keys: Vec<String> = logical_order
            .iter()
            .filter(|key| {
                logical_groups.get(*key).is_some_and(|group| {
                    group.len() == 1
                        && relations.get(&group[0].name).is_some_and(|relation| {
                            relation.split_role.is_none()
                                && numbered_family_for_plain_extension(&relation.filename).is_some()
                        })
                })
            })
            .cloned()
            .collect();
        for plain_key in plain_head_keys {
            let Some(heads) = logical_groups.get(&plain_key).cloned() else {
                continue;
            };
            let Some(head_relation) = relations.get(&heads[0].name) else {
                continue;
            };
            let Some(expected_family) =
                numbered_family_for_plain_extension(&head_relation.filename)
            else {
                continue;
            };
            let target_keys: Vec<String> = logical_order
                .iter()
                .filter(|key| **key != plain_key)
                .filter(|key| {
                    logical_groups.get(*key).is_some_and(|group| {
                        let mut same_family = false;
                        let mut has_first = false;
                        for entry in group {
                            if let Some(relation) = relations.get(&entry.name) {
                                same_family |= relation.logical_name == head_relation.logical_name
                                    && relation.split_family == expected_family;
                                has_first |= relation.split_index == 1;
                            }
                        }
                        same_family && !has_first
                    })
                })
                .cloned()
                .collect();
            if target_keys.len() != 1 {
                continue;
            }
            if let Some(target) = logical_groups.get_mut(&target_keys[0]) {
                target.extend(heads.iter().cloned());
            }
            logical_groups.remove(&plain_key);
        }

        // Marker-numbered files whose apparent extension is only decoration
        // have an unknown format.  They may join a concrete part-numbered
        // family only when exactly one such family exists for the same stem.
        // This admits `name.part1.123 + name.part2.rar`, but refuses to guess
        // when RAR/ZIP/7z-looking part families are mixed in one directory.
        let generic_part_keys: Vec<String> = logical_order
            .iter()
            .filter(|key| {
                logical_groups.get(*key).is_some_and(|group| {
                    group.iter().any(|entry| {
                        relations
                            .get(&entry.name)
                            .is_some_and(|relation| relation.split_family == "generic_part")
                    })
                })
            })
            .cloned()
            .collect();
        for generic_key in generic_part_keys {
            let Some(generic_entries) = logical_groups.get(&generic_key).cloned() else {
                continue;
            };
            let Some(generic_relation) = generic_entries
                .iter()
                .find_map(|entry| relations.get(&entry.name))
            else {
                continue;
            };
            let generic_indices: HashSet<u32> = generic_entries
                .iter()
                .filter_map(|entry| relations.get(&entry.name))
                .map(|relation| relation.split_index)
                .filter(|index| *index > 0)
                .collect();
            let target_keys: Vec<String> = logical_order
                .iter()
                .filter(|key| **key != generic_key)
                .filter(|key| {
                    logical_groups.get(*key).is_some_and(|group| {
                        let format_matches = group.iter().any(|entry| {
                            relations.get(&entry.name).is_some_and(|relation| {
                                relation
                                    .logical_name
                                    .eq_ignore_ascii_case(&generic_relation.logical_name)
                                    && matches!(
                                        relation.split_family.as_str(),
                                        "rar_part" | "7z_part" | "zip_part"
                                    )
                            })
                        });
                        let overlaps = group.iter().any(|entry| {
                            relations.get(&entry.name).is_some_and(|relation| {
                                relation.split_index > 0
                                    && generic_indices.contains(&relation.split_index)
                            })
                        });
                        format_matches && !overlaps
                    })
                })
                .cloned()
                .collect();
            if target_keys.len() != 1 {
                continue;
            }
            if let Some(target) = logical_groups.get_mut(&target_keys[0]) {
                target.extend(generic_entries.iter().cloned());
            }
            logical_groups.remove(&generic_key);
        }

        // An executable does not declare whether it is a 7z, ZIP, or RAR SFX.
        // Attach it only when the directory contains exactly one matching
        // filename-family group.  With multiple families the executable stays
        // in its own group; duplicating it into every group would violate the
        // directory-wide single-owner invariant.
        let companion_keys: Vec<String> = logical_order
            .iter()
            .filter(|key| {
                logical_groups.get(*key).is_some_and(|group| {
                    group.iter().any(|entry| {
                        relations.get(&entry.name).is_some_and(|relation| {
                            relation.is_split_exe_companion
                                || relation.is_disguised_split_exe_companion
                        })
                    })
                })
            })
            .cloned()
            .collect();
        for companion_key in companion_keys {
            let Some(companions) = logical_groups.get(&companion_key).cloned() else {
                continue;
            };
            let logical_names: HashSet<String> = companions
                .iter()
                .filter_map(|entry| relations.get(&entry.name))
                .map(|relation| relation.logical_name.clone())
                .collect();
            let target_keys: Vec<String> = logical_order
                .iter()
                .filter(|key| **key != companion_key)
                .filter(|key| {
                    logical_groups.get(*key).is_some_and(|group| {
                        group.iter().any(|entry| {
                            relations.get(&entry.name).is_some_and(|relation| {
                                logical_names.contains(&relation.logical_name)
                                    && relation.is_split_member
                            })
                        })
                    })
                })
                .cloned()
                .collect();
            if target_keys.len() != 1 {
                continue;
            }
            if let Some(target) = logical_groups.get_mut(&target_keys[0]) {
                target.extend(companions.iter().cloned());
            }
            logical_groups.remove(&companion_key);
        }

        for logical_name in logical_order {
            let Some(group_entries) = logical_groups.remove(&logical_name) else {
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
                // Keep canonical heads and uniquely attached SFX companions.
                // They were admitted by the directory-wide same-family
                // arbitration above even though their individual filename
                // relation is not itself a numbered member.
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

fn promote_content_confirmed_plain_numeric_groups(
    entries: &[RelationInput],
    relations: &mut HashMap<String, FileRelationNative>,
) {
    let mut by_prefix: HashMap<String, Vec<(&RelationInput, ParsedVolume)>> = HashMap::new();
    for entry in entries {
        let Some(parsed) = parse_numbered_volume(&entry.path) else {
            continue;
        };
        if parsed.style != "plain_numeric_suffix" {
            continue;
        }
        by_prefix
            .entry(parsed.prefix.to_ascii_lowercase())
            .or_default()
            .push((entry, parsed));
    }

    for members in by_prefix.into_values() {
        if members.len() < 2 {
            continue;
        }
        let Some((head, _)) = members.iter().find(|(_, parsed)| parsed.number == 1) else {
            continue;
        };
        if !has_archive_or_sfx_magic(&head.path) {
            continue;
        }
        for (entry, parsed) in members {
            let Some(relation) = relations.get_mut(&entry.name) else {
                continue;
            };
            relation.split_role = Some(
                if parsed.number == 1 {
                    "first"
                } else {
                    "member"
                }
                .to_string(),
            );
            relation.is_split_member = true;
            relation.is_split_related = true;
            relation.split_family = "generic_numbered".to_string();
            relation.split_index = parsed.number;
            relation.logical_name = clean_logical_name(basename(&parsed.prefix));
        }
    }
}

fn has_archive_or_sfx_magic(path: &str) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut header = [0u8; 16];
    let Ok(read) = file.read(&mut header) else {
        return false;
    };
    let bytes = &header[..read];
    bytes.starts_with(b"7z\xBC\xAF\x27\x1C")
        || bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
        || bytes.starts_with(b"Rar!\x1A\x07\x00")
        || bytes.starts_with(b"Rar!\x1A\x07\x01\x00")
        || bytes.starts_with(b"MZ")
}

fn native_group_to_dict(
    py: Python<'_>,
    directory: &str,
    group_entries: &[RelationInput],
    relations: &HashMap<String, FileRelationNative>,
    allow_multi_split_candidate: bool,
) -> PyResult<Py<PyDict>> {
    let split_contract = build_native_split_contract(group_entries, relations);
    let head_index = split_contract
        .volumes
        .iter()
        .find(|volume| volume.number == 1)
        .and_then(|volume| {
            group_entries
                .iter()
                .position(|entry| entry.path == volume.path)
        })
        .unwrap_or_else(|| select_head_index(group_entries));
    let head = &group_entries[head_index];
    let mut relation = relations
        .get(&head.name)
        .cloned()
        .unwrap_or_else(|| build_file_relation(&head.name, &HashSet::new()));
    if relation.split_family == "generic_part" {
        let concrete_families: HashSet<String> = group_entries
            .iter()
            .filter_map(|entry| relations.get(&entry.name))
            .map(|value| value.split_family.as_str())
            .filter(|family| matches!(*family, "rar_part" | "7z_part" | "zip_part"))
            .map(str::to_string)
            .collect();
        if concrete_families.len() == 1 {
            relation.split_family = concrete_families.into_iter().next().unwrap_or_default();
        }
    }
    let mut is_split_candidate = relation.is_split_related;

    if group_entries.len() > 1 {
        is_split_candidate = allow_multi_split_candidate;
        if detect_split_role(&head.name) == Some("first")
            || head.name.to_ascii_lowercase().ends_with(".exe")
        {
            relation.split_role = Some("first".to_string());
        }
    }

    let all_parts: Vec<String> = if split_contract.volumes.is_empty() {
        std::iter::once(head.path.clone())
            .chain(
                group_entries
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != head_index)
                    .map(|(_, entry)| entry.path.clone()),
            )
            .collect()
    } else {
        split_contract
            .volumes
            .iter()
            .map(|volume| volume.path.clone())
            .collect()
    };

    let volume_dicts: Vec<Py<PyDict>> = split_contract
        .volumes
        .iter()
        .map(|volume| native_split_volume_to_dict(py, volume))
        .collect::<PyResult<_>>()?;

    let dict = PyDict::new(py);
    dict.set_item("directory", directory)?;
    dict.set_item("head_path", &head.path)?;
    dict.set_item("head_name", &head.name)?;
    dict.set_item("logical_name", &relation.logical_name)?;
    dict.set_item("relation", relation_to_dict(py, &relation)?)?;
    dict.set_item("all_parts", PyList::new(py, &all_parts)?)?;
    dict.set_item("is_split_candidate", is_split_candidate)?;
    dict.set_item("head_size", head.size)?;
    dict.set_item("split_volumes", PyList::new(py, &volume_dicts)?)?;
    dict.set_item("split_group_complete", split_contract.complete)?;
    dict.set_item("split_missing_reason", &split_contract.missing_reason)?;
    dict.set_item("split_missing_indices", &split_contract.missing_indices)?;
    dict.set_item(
        "split_observed_missing_ranges",
        &split_contract.missing_ranges,
    )?;
    dict.set_item("split_layout_status", split_contract.layout_status)?;
    let (completeness_status, completeness_confidence, completeness_basis) =
        split_completeness_assessment(&split_contract, group_entries, &relation);
    dict.set_item("split_completeness_status", completeness_status)?;
    dict.set_item("split_completeness_confidence", completeness_confidence)?;
    dict.set_item("split_completeness_basis", completeness_basis)?;
    Ok(dict.unbind())
}

fn split_completeness_assessment(
    contract: &NativeSplitContract,
    group_entries: &[RelationInput],
    relation: &FileRelationNative,
) -> (&'static str, &'static str, Vec<&'static str>) {
    let head_content_confirmed = contract
        .volumes
        .iter()
        .find(|volume| volume.number == 1)
        .is_some_and(|volume| has_archive_or_sfx_magic(&volume.path));
    let canonical_scheme = !contract.volumes.is_empty()
        && contract
            .volumes
            .iter()
            .all(|volume| volume.source == "standard")
        && !matches!(
            relation.split_family.as_str(),
            "" | "generic_part" | "generic_numbered"
        );
    let mut basis = Vec::new();
    if canonical_scheme {
        basis.push("canonical_scheme");
    }
    if head_content_confirmed {
        basis.push("archive_head_confirmed");
    }

    if contract.complete.is_none() {
        basis.push("candidate_substitution");
        return ("ambiguous", "hint", basis);
    }
    match contract.missing_reason.as_str() {
        "missing_head" => {
            basis.push("required_entry_absent");
            (
                "missing_head",
                if canonical_scheme { "strong" } else { "hint" },
                basis,
            )
        }
        "missing_middle" => {
            basis.push("bracketed_number_gap");
            let confidence = if canonical_scheme || head_content_confirmed {
                "strong"
            } else {
                "hint"
            };
            ("middle_gap", confidence, basis)
        }
        "missing_tail" => {
            basis.push("required_terminal_absent");
            let proven_zip_terminal = relation.split_family == "zip_spanned"
                && (canonical_scheme || head_content_confirmed)
                && group_entries.iter().all(|entry| {
                    !relations_name_is_zip_terminal(&entry.name, &relation.logical_name)
                });
            (
                "tail_missing",
                if proven_zip_terminal {
                    "proven"
                } else {
                    "hint"
                },
                basis,
            )
        }
        _ if contract.complete == Some(true) => (
            "coherent",
            if canonical_scheme || head_content_confirmed {
                "strong"
            } else {
                "hint"
            },
            basis,
        ),
        _ => ("ambiguous", "hint", basis),
    }
}

fn relations_name_is_zip_terminal(name: &str, logical_name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let logical = logical_name.to_ascii_lowercase();
    lower == format!("{logical}.zip")
        || disguised_zip_terminal_base(name).is_some_and(|base| {
            clean_logical_name(basename(&base)).eq_ignore_ascii_case(logical_name)
        })
}

fn native_split_volume_to_dict(py: Python<'_>, volume: &NativeSplitVolume) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("path", &volume.path)?;
    dict.set_item("number", volume.number)?;
    dict.set_item("role", volume.role)?;
    dict.set_item("source", volume.source)?;
    dict.set_item("style", &volume.style)?;
    dict.set_item("prefix", &volume.prefix)?;
    dict.set_item("width", volume.width)?;
    Ok(dict.unbind())
}

fn split_styles_compatible(left: &str, right: &str) -> bool {
    left == right
        || (matches!(left, "rar_part" | "rar_sfx_part" | "part_numbered")
            && matches!(right, "rar_part" | "rar_sfx_part" | "part_numbered"))
}

fn build_native_split_contract(
    group_entries: &[RelationInput],
    relations: &HashMap<String, FileRelationNative>,
) -> NativeSplitContract {
    let parsed: Vec<(&RelationInput, ParsedVolume)> = group_entries
        .iter()
        .filter_map(|entry| parse_numbered_volume(&entry.path).map(|parsed| (entry, parsed)))
        .collect();
    let sfx_head = group_entries.iter().find(|entry| {
        relations.get(&entry.name).is_some_and(|relation| {
            relation.is_split_exe_companion || relation.is_disguised_split_exe_companion
        })
    });

    if let (Some(head), Some((_, anchor))) = (sfx_head, parsed.first()) {
        let mut volumes = vec![NativeSplitVolume {
            path: head.path.clone(),
            number: 1,
            role: "first",
            source: "standard",
            style: "sfx_numeric_suffix".to_string(),
            prefix: anchor.prefix.clone(),
            width: anchor.width,
        }];
        for (entry, parsed) in &parsed {
            volumes.push(NativeSplitVolume {
                path: entry.path.clone(),
                number: parsed.number.saturating_add(1),
                role: "member",
                source: if parsed.decorated {
                    "candidate"
                } else {
                    "standard"
                },
                style: "sfx_numeric_suffix".to_string(),
                prefix: anchor.prefix.clone(),
                width: anchor.width,
            });
        }
        volumes.sort_by(|left, right| {
            left.number.cmp(&right.number).then_with(|| {
                left.path
                    .to_ascii_lowercase()
                    .cmp(&right.path.to_ascii_lowercase())
            })
        });
        let present: HashSet<u32> = volumes.iter().map(|volume| volume.number).collect();
        let max_number = present.iter().copied().max().unwrap_or(0);
        let (missing_ranges, missing) = observed_missing(&present, max_number);
        return NativeSplitContract {
            volumes,
            complete: Some(missing_ranges.is_empty()),
            missing_reason: if missing_ranges.is_empty() {
                String::new()
            } else {
                "missing_middle".to_string()
            },
            missing_indices: missing,
            missing_ranges,
            layout_status: if present.len() == max_number as usize {
                "coherent"
            } else {
                "observed_gap"
            },
        };
    }

    let anchor = parsed
        .first()
        .map(|(_, parsed)| parsed.clone())
        .or_else(|| {
            group_entries.iter().find_map(|entry| {
                let relation = relations.get(&entry.name)?;
                if relation.split_family == "rar_oldstyle" && relation.split_index == 1 {
                    let directory = Path::new(&entry.path)
                        .parent()
                        .map(|value| value.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let separator = if directory.is_empty() {
                        ""
                    } else {
                        std::path::MAIN_SEPARATOR_STR
                    };
                    return Some(ParsedVolume {
                        prefix: format!("{directory}{separator}{}", relation.logical_name),
                        number: 1,
                        style: "rar_oldstyle",
                        width: 2,
                        family: "rar",
                        decorated: false,
                    });
                }
                None
            })
        });
    let Some(anchor) = anchor else {
        return NativeSplitContract {
            volumes: Vec::new(),
            complete: None,
            missing_reason: String::new(),
            missing_indices: Vec::new(),
            missing_ranges: Vec::new(),
            layout_status: "ambiguous",
        };
    };

    let mut by_number: HashMap<u32, NativeSplitVolume> = HashMap::new();
    let mut substituted_indices: Vec<u32> = Vec::new();
    for (entry, parsed) in parsed {
        let compatible_part_family =
            matches!(parsed.style, "part_numbered" | "rar_part" | "rar_sfx_part")
                && matches!(anchor.style, "part_numbered" | "rar_part" | "rar_sfx_part")
                && (parsed.family == "generic" || anchor.family == "generic");
        if (parsed.family != anchor.family && !compatible_part_family)
            || !split_styles_compatible(parsed.style, anchor.style)
            || !parsed.prefix.eq_ignore_ascii_case(&anchor.prefix)
        {
            continue;
        }
        let candidate = NativeSplitVolume {
            path: entry.path.clone(),
            number: parsed.number,
            role: if parsed.number == 1 {
                "first"
            } else {
                "member"
            },
            source: if parsed.decorated {
                "candidate"
            } else {
                "standard"
            },
            style: anchor.style.to_string(),
            prefix: anchor.prefix.clone(),
            width: anchor.width,
        };
        by_number
            .entry(parsed.number)
            .and_modify(|existing| {
                if candidate.path.to_ascii_lowercase() < existing.path.to_ascii_lowercase() {
                    *existing = candidate.clone();
                }
            })
            .or_insert(candidate);
    }

    if anchor.style == "numeric_suffix" {
        if let Some(entry) = group_entries
            .iter()
            .find(|entry| entry.path.eq_ignore_ascii_case(&anchor.prefix))
        {
            by_number.insert(
                1,
                NativeSplitVolume {
                    path: entry.path.clone(),
                    number: 1,
                    role: "first",
                    source: "candidate",
                    style: anchor.style.to_string(),
                    prefix: anchor.prefix.clone(),
                    width: anchor.width,
                },
            );
            substituted_indices.push(1);
        }
    }

    if anchor.style == "rar_oldstyle" {
        if let Some(entry) = group_entries.iter().find(|entry| {
            relations.get(&entry.name).is_some_and(|relation| {
                relation.split_family == "rar_oldstyle" && relation.split_index == 1
            })
        }) {
            by_number.insert(
                1,
                NativeSplitVolume {
                    path: entry.path.clone(),
                    number: 1,
                    role: "first",
                    source: "standard",
                    style: anchor.style.to_string(),
                    prefix: anchor.prefix.clone(),
                    width: anchor.width,
                },
            );
        }
    }

    let max_number = by_number.keys().copied().max().unwrap_or(0);
    let present_numbers: HashSet<u32> = by_number.keys().copied().collect();
    let (mut missing_ranges, mut missing) = observed_missing(&present_numbers, max_number);

    if anchor.style == "zip_spanned" {
        let terminal = group_entries.iter().find(|entry| {
            relations.get(&entry.name).is_some_and(|relation| {
                relation.split_family == "zip_spanned"
                    && relation.split_role.as_deref() == Some("terminal")
            })
        });
        if let Some(entry) = terminal {
            by_number.insert(
                max_number.saturating_add(1),
                NativeSplitVolume {
                    path: entry.path.clone(),
                    number: max_number.saturating_add(1),
                    role: "terminal",
                    source: "standard",
                    style: anchor.style.to_string(),
                    prefix: anchor.prefix.clone(),
                    width: anchor.width,
                },
            );
        } else if missing_ranges.is_empty() {
            let tail = max_number.saturating_add(1);
            missing_ranges.push((tail, tail));
            missing.push(tail);
        }
    }

    let mut volumes: Vec<NativeSplitVolume> = by_number.into_values().collect();
    volumes.sort_by(|left, right| {
        left.number.cmp(&right.number).then_with(|| {
            left.path
                .to_ascii_lowercase()
                .cmp(&right.path.to_ascii_lowercase())
        })
    });
    let missing_reason = if missing.is_empty() {
        String::new()
    } else if missing.contains(&1) {
        "missing_head".to_string()
    } else if anchor.style == "zip_spanned"
        && missing.len() == 1
        && missing[0] == max_number.saturating_add(1)
    {
        "missing_tail".to_string()
    } else {
        "missing_middle".to_string()
    };
    if missing.is_empty() && !substituted_indices.is_empty() {
        return NativeSplitContract {
            volumes,
            complete: None,
            missing_reason: "candidate_substitution".to_string(),
            missing_indices: substituted_indices,
            missing_ranges: Vec::new(),
            layout_status: "ambiguous",
        };
    }
    NativeSplitContract {
        volumes,
        complete: Some(missing_ranges.is_empty()),
        missing_reason,
        missing_indices: missing,
        layout_status: if missing_ranges.is_empty() {
            "coherent"
        } else {
            "observed_gap"
        },
        missing_ranges,
    }
}

/// Return compact filename-observed gaps plus a bounded compatibility list.
/// A malicious or misleading suffix such as `.999999999` must not allocate a
/// vector proportional to the apparent volume number.
fn observed_missing(present: &HashSet<u32>, max_number: u32) -> (Vec<(u32, u32)>, Vec<u32>) {
    let mut sorted: Vec<u32> = present
        .iter()
        .copied()
        .filter(|number| *number > 0)
        .collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut ranges = Vec::new();
    let mut cursor = 1u32;
    for number in sorted {
        if number > max_number {
            break;
        }
        if number > cursor {
            ranges.push((cursor, number - 1));
        }
        cursor = number.saturating_add(1);
    }
    if cursor <= max_number {
        ranges.push((cursor, max_number));
    }
    let indices = ranges
        .iter()
        .flat_map(|(start, end)| *start..=(*end).min(start.saturating_add(255)))
        .take(256)
        .collect();
    (ranges, indices)
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
        split_family = match (parsed.family, parsed.style) {
            ("rar", "rar_part" | "rar_sfx_part") => "rar_part",
            ("7z", "part_numbered") => "7z_part",
            ("zip", "part_numbered") => "zip_part",
            (_, "part_numbered") => "generic_part",
            ("rar", "rar_oldstyle") => "rar_oldstyle",
            ("zip", "zip_spanned") => "zip_spanned",
            ("7z", _) => "7z_numbered",
            ("zip", _) => "zip_numbered",
            ("rar", _) => "rar_numbered",
            _ => "generic_numbered",
        }
        .to_string();
    }
    let mut logical_name = get_logical_name(filename, false);

    let is_plain_numeric_member = parsed_volume
        .as_ref()
        .is_some_and(|parsed| parsed.style == "plain_numeric_suffix");
    let has_generic_001_head = parsed_volume.as_ref().is_some_and(|parsed| {
        parsed.style == "plain_numeric_suffix"
            && lower_names.iter().any(|candidate| {
                parse_volume_candidates(candidate).iter().any(|other| {
                    other.style == "plain_numeric_suffix"
                        && other.number == 1
                        && other.prefix.eq_ignore_ascii_case(&parsed.prefix)
                })
            })
    });
    let mut is_split_member = split_role.is_some();
    if is_plain_numeric_member {
        let has_sfx_anchor = parsed_volume.as_ref().is_some_and(|parsed| {
            lower_names.contains(&format!("{}.exe", parsed.prefix).to_ascii_lowercase())
        });
        is_split_member = has_sfx_anchor;
        if !has_sfx_anchor {
            split_role = None;
        }
    }
    if parsed_volume.as_ref().is_some_and(|parsed| {
        parsed.style == "part_numbered"
            && parsed.family == "generic"
            && !has_matching_marker_companion(lower_names, filename, parsed)
    }) {
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

    if ext == ".rar" && has_oldstyle_rar_members(lower_names, &base) {
        logical_name = base.clone();
        split_role = Some("first".to_string());
        is_split_member = true;
        split_family = "rar_oldstyle".to_string();
        split_index = 1;
    }

    if ext == ".zip" {
        if let Some(max_member) = max_zip_segment_member(lower_names, &base) {
            logical_name = base.clone();
            split_role = Some("terminal".to_string());
            is_split_member = true;
            split_family = "zip_spanned".to_string();
            split_index = max_member.saturating_add(1);
        }
    } else if parsed_volume.is_none() {
        if let Some(zip_base) = disguised_zip_terminal_base(filename) {
            if let Some(max_member) = max_zip_segment_member(lower_names, &zip_base) {
                logical_name = zip_base;
                split_role = Some("terminal".to_string());
                is_split_member = true;
                split_family = "zip_spanned".to_string();
                split_index = max_member.saturating_add(1);
            }
        }
    }

    let parsed_as_rar = parsed_volume
        .as_ref()
        .is_some_and(|parsed| parsed.family == "rar");
    let match_rar_disguised = parsed_as_rar && rar_disguised_re().is_match(filename);
    let match_rar_head = parsed_as_rar && rar_head_re().is_match(&base);
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
    if parsed.decorated {
        dict.set_item("decorated", true)?;
    }
    Ok(dict.unbind())
}

fn detect_split_role(filename: &str) -> Option<&'static str> {
    if let Some(parsed) = parse_numbered_volume(filename) {
        return Some(if parsed.number == 1 {
            "first"
        } else {
            "member"
        });
    }
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
    if let Some(parsed) = parse_numbered_volume(filename) {
        return logical_name_from_parsed(&parsed);
    }
    let name = rar_part_suffix_re().replace(filename, "").to_string();
    if name != filename {
        return clean_logical_name(&name);
    }

    let zero_zip = zip_zero_numbered_suffix_re().replace(&name, "").to_string();
    if zero_zip != name {
        return clean_logical_name(&zero_zip);
    }

    let second = archive_numbered_suffix_re()
        .replace(&zero_zip, "")
        .to_string();
    if second != zero_zip {
        return clean_logical_name(&second);
    }

    let zip_spanned = zip_spanned_suffix_re().replace(&second, "").to_string();
    if zip_spanned != second {
        return clean_logical_name(&zip_spanned);
    }

    let third = plain_numeric_suffix_re()
        .replace(&zip_spanned, "")
        .to_string();
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

fn logical_name_from_parsed(parsed: &ParsedVolume) -> String {
    if matches!(
        parsed.style,
        "rar_part" | "rar_sfx_part" | "part_numbered" | "rar_oldstyle" | "zip_spanned"
    ) || parsed.family == "generic"
    {
        return clean_logical_name(&parsed.prefix);
    }
    let suffix = format!(".{}", parsed.family);
    let lower = parsed.prefix.to_ascii_lowercase();
    if lower.ends_with(&suffix) {
        return clean_logical_name(&parsed.prefix[..parsed.prefix.len() - suffix.len()]);
    }
    clean_logical_name(&parsed.prefix)
}

fn parse_numbered_volume(path: &str) -> Option<ParsedVolume> {
    let (directory, filename) = split_relation_path(path);
    let mut parsed = parse_numbered_volume_name(filename)?;
    if !directory.is_empty() {
        parsed.prefix = format!("{directory}{}", parsed.prefix);
    }
    Some(parsed)
}

/// Return the exact split-family identities a path can participate in.
///
/// This is the sole naming seam exposed to the filesystem scanner. The
/// scanner may retain a size-rejected row when one of these identities has a
/// normally accepted anchor; relations still decides whether the resulting
/// group is a valid archive.
#[pyfunction]
pub(crate) fn relations_size_filter_split_family_keys(path: &str) -> Vec<String> {
    if !may_have_size_deferred_split_identity(path) {
        return Vec::new();
    }
    let mut keys = Vec::new();
    if let Some(parsed) = parse_numbered_volume(path) {
        let scheme = match parsed.style {
            "rar_part" | "rar_sfx_part" => "rar:part",
            "rar_oldstyle" => "rar:oldstyle",
            "zip_spanned" => "zip:spanned",
            "zip_zero_numbered" => "zip:zero-numbered",
            "numeric_suffix" => "archive:numeric",
            "plain_numeric_suffix" => "generic:numeric",
            other => other,
        };
        keys.push(split_size_family_key(scheme, &parsed.prefix));
    }

    // Canonical heads/tails do not themselves carry a numeric suffix, but
    // they can anchor these exact filename families.
    let (base, ext) = split_ext(path);
    match ext.to_ascii_lowercase().as_str() {
        ".7z" => keys.push(split_size_family_key("archive:numeric", path)),
        ".zip" => {
            keys.push(split_size_family_key("archive:numeric", path));
            keys.push(split_size_family_key("zip:zero-numbered", path));
            keys.push(split_size_family_key("zip:spanned", &base));
        }
        ".rar" => {
            keys.push(split_size_family_key("archive:numeric", path));
            keys.push(split_size_family_key("rar:oldstyle", &base));
        }
        _ => {}
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

#[pyfunction]
pub(crate) fn relations_apply_split_size_anchors(
    paths: Vec<String>,
    size_accepted: Vec<bool>,
) -> PyResult<Vec<bool>> {
    if paths.len() != size_accepted.len() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "split size anchor paths and decisions must have equal lengths",
        ));
    }
    if size_accepted.iter().all(|accepted| *accepted)
        || size_accepted.iter().all(|accepted| !*accepted)
    {
        return Ok(size_accepted);
    }
    let accepted_families: HashSet<String> = paths
        .iter()
        .zip(&size_accepted)
        .filter(|(_, accepted)| **accepted)
        .flat_map(|(path, _)| relations_size_filter_split_family_keys(path))
        .collect();
    Ok(paths
        .iter()
        .zip(size_accepted)
        .map(|(path, accepted)| {
            accepted
                || relations_size_filter_split_family_keys(path)
                    .iter()
                    .any(|key| accepted_families.contains(key))
        })
        .collect())
}

fn may_have_size_deferred_split_identity(path: &str) -> bool {
    let name = basename(path).to_ascii_lowercase();
    if name.ends_with(".7z") || name.ends_with(".zip") || name.ends_with(".rar") {
        return true;
    }
    let suffix = name.rsplit('.').next().unwrap_or_default();
    if (suffix.len() == 3 || suffix.len() == 4) && suffix.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return true;
    }
    if suffix.len() >= 3
        && matches!(suffix.as_bytes().first(), Some(b'z' | b'r'))
        && suffix.as_bytes()[1..].iter().all(u8::is_ascii_digit)
    {
        return true;
    }
    let has_family_token = ["7z", "zip", "rar", "exe"]
        .iter()
        .any(|token| name.contains(token));
    has_family_token && (name.contains(".part") || name.contains("vol") || name.contains(".z"))
}

fn split_size_family_key(scheme: &str, prefix: &str) -> String {
    format!(
        "{}\u{001f}{}",
        scheme,
        prefix.replace('\\', "/").to_ascii_lowercase()
    )
}

fn parse_numbered_volume_name(filename: &str) -> Option<ParsedVolume> {
    parse_volume_candidates(filename).into_iter().next()
}

/// Produce every plausible filename interpretation in descending semantic
/// strength.  Callers that still expose the legacy single-result API use the
/// first candidate, while directory grouping can reason about alternatives.
///
/// A structural marker such as `part2` deliberately outranks a final numeric
/// token.  For example, `movie.part2.456` is primarily part #2 with `.456` as
/// decoration; the naked-number interpretation remains available only as a
/// weak fallback candidate.
fn parse_volume_candidates(filename: &str) -> Vec<ParsedVolume> {
    let mut candidates = Vec::new();

    if let Some(parsed) = parse_marker_numbered_volume(filename) {
        push_unique_volume_candidate(&mut candidates, parsed);
    }
    let _ = (|| -> Option<()> {
        if let Some(captures) = parse_zip_spanned_re().captures(filename) {
            let number = captures
                .name("number")
                .and_then(|value| value.as_str().parse().ok());
            if let Some(number) = number.filter(|number: &u32| *number > 0) {
                push_unique_volume_candidate(
                    &mut candidates,
                    ParsedVolume {
                        prefix: captures.name("prefix")?.as_str().to_string(),
                        number,
                        style: "zip_spanned",
                        width: captures.name("number")?.as_str().len(),
                        family: "zip",
                        decorated: false,
                    },
                );
            }
        }
        if let Some(captures) = parse_zip_zero_numbered_re().captures(filename) {
            if let Some(raw_number) = captures
                .name("number")
                .and_then(|value| value.as_str().parse::<u32>().ok())
            {
                push_unique_volume_candidate(
                    &mut candidates,
                    ParsedVolume {
                        prefix: captures.name("prefix")?.as_str().to_string(),
                        number: raw_number.saturating_add(1),
                        style: "zip_zero_numbered",
                        width: captures.name("number")?.as_str().len(),
                        family: "zip",
                        decorated: false,
                    },
                );
            }
        }
        if let Some(captures) = parse_archive_numbered_re().captures(filename) {
            if let (Some(family), Some(raw_number)) = (
                captures
                    .name("format")
                    .and_then(|value| archive_family(value.as_str())),
                captures.name("number"),
            ) {
                if let Some(number) = raw_number
                    .as_str()
                    .parse::<u32>()
                    .ok()
                    .filter(|value| *value > 0)
                {
                    push_unique_volume_candidate(
                        &mut candidates,
                        ParsedVolume {
                            prefix: format!("{}.{}", captures.name("prefix")?.as_str(), family),
                            number,
                            style: "numeric_suffix",
                            width: raw_number.as_str().len(),
                            family,
                            decorated: false,
                        },
                    );
                }
            }
        }
        if let Some(captures) = parse_rar_part_re().captures(filename) {
            let number = captures.name("number")?.as_str();
            let format = captures.name("format")?.as_str();
            if let Some(number) = number.parse::<u32>().ok().filter(|value| *value > 0) {
                push_unique_volume_candidate(
                    &mut candidates,
                    ParsedVolume {
                        prefix: captures.name("prefix")?.as_str().to_string(),
                        number,
                        style: if format.eq_ignore_ascii_case("exe") {
                            "rar_sfx_part"
                        } else {
                            "rar_part"
                        },
                        width: captures.name("number")?.as_str().len(),
                        family: "rar",
                        decorated: false,
                    },
                );
            }
        }
        if let Some(captures) = parse_old_rar_re().captures(filename) {
            let number = captures.name("number")?.as_str();
            if let Some(number) = number.parse::<u32>().ok() {
                push_unique_volume_candidate(
                    &mut candidates,
                    ParsedVolume {
                        prefix: captures.name("prefix")?.as_str().to_string(),
                        number: number.saturating_add(2),
                        style: "rar_oldstyle",
                        width: captures.name("number")?.as_str().len(),
                        family: "rar",
                        decorated: false,
                    },
                );
            }
        }

        if let Some(parsed) = parse_decorated_numbered_volume(filename) {
            push_unique_volume_candidate(&mut candidates, parsed);
        }

        // A final all-numeric token is intentionally last.  It is a discovery
        // hint, not stronger evidence than a marker or an embedded archive token.
        if let Some(captures) = parse_plain_numbered_re().captures(filename) {
            if let Some(raw_number) = captures.name("number") {
                if let Some(number) = raw_number
                    .as_str()
                    .parse::<u32>()
                    .ok()
                    .filter(|value| *value > 0)
                {
                    push_unique_volume_candidate(
                        &mut candidates,
                        ParsedVolume {
                            prefix: captures.name("prefix")?.as_str().to_string(),
                            number,
                            style: "plain_numeric_suffix",
                            width: raw_number.as_str().len(),
                            family: "generic",
                            decorated: false,
                        },
                    );
                }
            }
        }
        Some(())
    })();
    candidates
}

fn push_unique_volume_candidate(candidates: &mut Vec<ParsedVolume>, candidate: ParsedVolume) {
    if candidates.iter().any(|existing| {
        existing.prefix.eq_ignore_ascii_case(&candidate.prefix)
            && existing.number == candidate.number
            && existing.style == candidate.style
            && existing.family == candidate.family
    }) {
        return;
    }
    candidates.push(candidate);
}

fn parse_marker_numbered_volume(path: &str) -> Option<ParsedVolume> {
    let captures = parse_marker_numbered_re().captures(path)?;
    let raw_number = captures.name("number")?.as_str();
    let number = raw_number.parse::<u32>().ok()?;
    if number == 0 {
        return None;
    }

    let raw_prefix = captures.name("prefix")?.as_str();
    let tail = captures
        .name("tail")
        .map(|value| value.as_str())
        .unwrap_or_default();
    let (prefix, trailing_prefix_family) = strip_trailing_archive_token(raw_prefix);
    let mut declared_families: HashSet<&'static str> = basename(raw_prefix)
        .split('.')
        .filter_map(archive_family)
        .collect();
    declared_families.extend(
        tail.split('.')
            .filter(|token| !token.is_empty())
            .filter_map(archive_family_hint),
    );
    let family = if declared_families.len() == 1 {
        *declared_families.iter().next()?
    } else {
        "generic"
    };
    let has_exe = tail
        .split('.')
        .any(|token| token.eq_ignore_ascii_case("exe"));
    let style = if family == "rar" {
        if has_exe && number == 1 {
            "rar_sfx_part"
        } else {
            "rar_part"
        }
    } else {
        "part_numbered"
    };
    Some(ParsedVolume {
        prefix: if trailing_prefix_family.is_some() {
            prefix.to_string()
        } else {
            raw_prefix.to_string()
        },
        number,
        style,
        width: raw_number.len(),
        family,
        decorated: !tail.eq_ignore_ascii_case(".rar")
            && !(number == 1 && tail.eq_ignore_ascii_case(".exe")),
    })
}

fn strip_trailing_archive_token(value: &str) -> (&str, Option<&'static str>) {
    let Some((prefix, token)) = value.rsplit_once('.') else {
        return (value, None);
    };
    archive_family(token)
        .map(|family| (prefix, Some(family)))
        .unwrap_or((value, None))
}

fn split_relation_path(path: &str) -> (&str, &str) {
    let Some((separator_index, separator)) = path
        .char_indices()
        .rfind(|(_, character)| matches!(character, '/' | '\\'))
    else {
        return ("", path);
    };
    let filename_index = separator_index + separator.len_utf8();
    (&path[..filename_index], &path[filename_index..])
}

fn parse_decorated_numbered_volume(path: &str) -> Option<ParsedVolume> {
    if let Some(captures) = decorated_marker_format_re().captures(path) {
        let raw_number = captures.name("number")?.as_str();
        let format = captures.name("format")?.as_str();
        let family = archive_family(format)?;
        return parsed_decorated_marker(
            captures.name("prefix")?.as_str(),
            raw_number,
            family,
            format.eq_ignore_ascii_case("exe"),
        );
    }
    if let Some(captures) = decorated_format_marker_re().captures(path) {
        let raw_number = captures.name("number")?.as_str();
        let format = captures.name("format")?.as_str();
        let family = archive_family(format)?;
        return parsed_decorated_numeric(
            captures.name("prefix")?.as_str(),
            raw_number,
            family,
            true,
            format.eq_ignore_ascii_case("exe"),
        );
    }
    if let Some(captures) = decorated_numeric_format_re().captures(path) {
        let raw_number = captures.name("number")?.as_str();
        let family = archive_family(captures.name("format")?.as_str())?;
        return parsed_decorated_numeric(
            captures.name("prefix")?.as_str(),
            raw_number,
            family,
            false,
            false,
        );
    }
    if let Some(captures) = decorated_format_numeric_re().captures(path) {
        let raw_number = captures.name("number")?.as_str();
        let family = archive_family(captures.name("format")?.as_str())?;
        return parsed_decorated_numeric(
            captures.name("prefix")?.as_str(),
            raw_number,
            family,
            false,
            false,
        );
    }
    if let Some(captures) = decorated_zip_spanned_re().captures(path) {
        let number = captures.name("number")?.as_str();
        return Some(ParsedVolume {
            prefix: captures.name("prefix")?.as_str().to_string(),
            number: number.parse().ok()?,
            style: "zip_spanned",
            width: number.len(),
            family: "zip",
            decorated: true,
        });
    }
    if let Some(captures) = decorated_old_rar_re().captures(path) {
        let number = captures.name("number")?.as_str();
        return Some(ParsedVolume {
            prefix: captures.name("prefix")?.as_str().to_string(),
            number: number.parse::<u32>().ok()?.saturating_add(2),
            style: "rar_oldstyle",
            width: number.len(),
            family: "rar",
            decorated: true,
        });
    }
    None
}

fn parsed_decorated_marker(
    prefix: &str,
    raw_number: &str,
    family: &'static str,
    sfx: bool,
) -> Option<ParsedVolume> {
    let number = raw_number.parse().ok()?;
    if family == "rar" {
        return Some(ParsedVolume {
            prefix: prefix.to_string(),
            number,
            style: if sfx { "rar_sfx_part" } else { "rar_part" },
            width: raw_number.len(),
            family,
            decorated: true,
        });
    }
    Some(ParsedVolume {
        prefix: format!("{prefix}.{family}"),
        number,
        style: "numeric_suffix",
        width: 3,
        family,
        decorated: true,
    })
}

fn parsed_decorated_numeric(
    prefix: &str,
    raw_number: &str,
    family: &'static str,
    marker_numbered: bool,
    sfx: bool,
) -> Option<ParsedVolume> {
    let mut number: u32 = raw_number.parse().ok()?;
    let style = if family == "zip" && raw_number.len() == 4 && raw_number.starts_with('0') {
        number = number.saturating_add(1);
        "zip_zero_numbered"
    } else if family == "rar" && marker_numbered {
        if sfx {
            "rar_sfx_part"
        } else {
            "rar_part"
        }
    } else {
        "numeric_suffix"
    };
    let canonical_prefix = if matches!(style, "rar_part" | "rar_sfx_part") {
        prefix.to_string()
    } else {
        format!("{prefix}.{family}")
    };
    Some(ParsedVolume {
        prefix: canonical_prefix,
        number,
        style,
        width: if style == "numeric_suffix" {
            3
        } else {
            raw_number.len()
        },
        family,
        decorated: true,
    })
}

fn archive_family(value: &str) -> Option<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "7z" => Some("7z"),
        "zip" => Some("zip"),
        "rar" | "exe" => Some("rar"),
        _ => None,
    }
}

fn archive_family_hint(value: &str) -> Option<&'static str> {
    if let Some(family) = archive_family(value) {
        return Some(family);
    }
    let lower = value.to_ascii_lowercase();
    let mut families = HashSet::new();
    for (token, family) in [("7z", "7z"), ("zip", "zip"), ("rar", "rar"), ("exe", "rar")] {
        if lower.contains(token) {
            families.insert(family);
        }
    }
    (families.len() == 1).then(|| *families.iter().next().expect("one family"))
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
    let expected = clean_logical_name(base_name).to_ascii_lowercase();
    if lower_names.iter().any(|candidate| {
        parse_numbered_volume(candidate).is_some_and(|parsed| {
            logical_name_from_parsed(&parsed).to_ascii_lowercase() == expected
        })
    }) {
        return true;
    }
    let escaped = regex::escape(base_name);
    let patterns = [
        format!(r"^{escaped}\.(7z|zip|rar)\.\d+(?:\.[^.]+)?$"),
        format!(r"^{escaped}\.\d{{3}}(?:\.[^.]+)?$"),
        format!(r"^{escaped}\.part\d+\.(?:rar|exe)(?:\.[^.]+)?$"),
        format!(r"^{escaped}\.z\d{{2}}$"),
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

fn has_matching_marker_companion(
    lower_names: &HashSet<String>,
    filename: &str,
    parsed: &ParsedVolume,
) -> bool {
    let related: Vec<ParsedVolume> = lower_names
        .iter()
        .filter(|candidate| !candidate.eq_ignore_ascii_case(filename))
        .flat_map(|candidate| parse_volume_candidates(candidate))
        .filter(|other| {
            matches!(other.style, "part_numbered" | "rar_part" | "rar_sfx_part")
                && other.prefix.eq_ignore_ascii_case(&parsed.prefix)
        })
        .collect();
    if related
        .iter()
        .any(|other| other.number == parsed.number && other.family != "generic")
    {
        return false;
    }
    related.iter().any(|other| other.number != parsed.number)
}

fn has_oldstyle_rar_members(lower_names: &HashSet<String>, base_name: &str) -> bool {
    let escaped = regex::escape(base_name);
    RegexBuilder::new(&format!(r"^{escaped}\.r\d{{2}}$"))
        .case_insensitive(true)
        .build()
        .map(|pattern| {
            lower_names
                .iter()
                .any(|candidate| pattern.is_match(candidate))
        })
        .unwrap_or(false)
}

fn max_zip_segment_member(lower_names: &HashSet<String>, base_name: &str) -> Option<u32> {
    lower_names
        .iter()
        .filter_map(|candidate| parse_numbered_volume(candidate))
        .filter_map(|parsed| {
            (parsed.style == "zip_spanned" && parsed.prefix.eq_ignore_ascii_case(base_name))
                .then_some(parsed.number)
        })
        .max()
}

fn disguised_zip_terminal_base(filename: &str) -> Option<String> {
    let captures = disguised_zip_terminal_re().captures(filename)?;
    Some(captures.name("prefix")?.as_str().to_string())
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

fn split_first_patterns() -> &'static [Regex; 5] {
    static VALUE: OnceLock<[Regex; 5]> = OnceLock::new();
    VALUE.get_or_init(|| {
        [
            re(r"\.part0*1\.(?:rar|exe)(?:\.[^.]+)?$"),
            re(r"\.zip\.0000(?:\.[^.]+)?$"),
            re(r"\.(7z|zip|rar)\.001(?:\.[^.]+)?$"),
            re(r"\.001(?:\.[^.]+)?$"),
            re(r"\.z01$"),
        ]
    })
}

fn relation_group_key(relation: &FileRelationNative) -> String {
    let family_and_scheme = match relation.split_family.as_str() {
        "7z_numbered" => "7z:numeric",
        "zip_numbered" => "zip:numeric",
        "zip_spanned" => "zip:spanned",
        "rar_numbered" => "rar:numeric",
        "rar_part" => "rar:part",
        "7z_part" => "7z:part",
        "zip_part" => "zip:part",
        "generic_part" => "generic:part",
        "rar_oldstyle" => "rar:oldstyle",
        "exe_companion" => "companion:sfx",
        "generic_numbered" => "generic:numeric",
        _ => {
            if relation.split_role.is_some() {
                // Preserve an explicit archive family even when an extra suffix
                // prevented parse_numbered_volume from assigning split_family.
                // The matching executable is attached to this group separately.
                match disguised_archive_family(&relation.filename) {
                    Some("7z") => "7z:numeric",
                    Some("zip") => "zip:numeric",
                    Some("rar") => "rar:numeric",
                    _ => "companion:unknown",
                }
            } else {
                let (_, ext) = split_ext(&relation.filename);
                match ext.to_ascii_lowercase().as_str() {
                    ".7z" => "7z:plain",
                    ".zip" => "zip:plain",
                    ".rar" => "rar:plain",
                    ".exe" => "exe:plain",
                    _ => "plain:file",
                }
            }
        }
    };
    format!("{}\u{001f}{}", relation.logical_name, family_and_scheme)
}

fn numbered_family_for_plain_extension(filename: &str) -> Option<&'static str> {
    let (_, ext) = split_ext(filename);
    match ext.to_ascii_lowercase().as_str() {
        ".7z" => Some("7z_numbered"),
        ".zip" => Some("zip_numbered"),
        ".rar" => Some("rar_numbered"),
        _ => None,
    }
}

fn disguised_archive_family(filename: &str) -> Option<&'static str> {
    let captures = disguised_archive_numbered_re().captures(filename)?;
    match captures.get(1)?.as_str().to_ascii_lowercase().as_str() {
        "7z" => Some("7z"),
        "zip" => Some("zip"),
        "rar" => Some("rar"),
        _ => None,
    }
}

fn disguised_archive_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.(7z|zip|rar)\.\d+\.[^.]+$"))
}

fn disguised_zip_terminal_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.zip(?:\.[^.]+)+$"))
}

fn split_member_pattern() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.(part\d+\.(?:rar|exe)|zip\.\d{4}|\d{3}|z\d{2})(?:\.[^.]+)?$"))
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

fn zip_zero_numbered_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.zip\.\d{4}(?:\.[^.]+)?$"))
}

fn plain_numeric_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.\d{3}$"))
}

fn parse_archive_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.(?P<format>7z|zip|rar)\.(?P<number>\d+)$"))
}

fn parse_zip_zero_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+\.zip)\.(?P<number>\d{4})$"))
}

fn zip_spanned_suffix_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.z\d{2}$"))
}

fn parse_zip_spanned_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.z(?P<number>\d+)$"))
}

fn parse_rar_part_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.part(?P<number>\d+)\.(?P<format>rar|exe)$"))
}

fn parse_old_rar_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.r(?P<number>\d{2,})$"))
}

fn parse_plain_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.(?P<number>\d+)$"))
}

fn parse_marker_numbered_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.(?:part|vol(?:ume)?)[-_ ]*(?P<number>\d+)(?:[-_ ][^.]*)?(?P<tail>(?:\.[^.]+)*)$")
    })
}

// Decorated names preserve only the meaningful token order. Everything surrounding
// the marker, number, and archive-family token is intentionally treated as noise;
// downstream archive structure detection is responsible for rejecting false positives.
fn decorated_marker_format_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.[^.]*(?:part|vol(?:ume)?)[^.\d]*(?P<number>\d{1,6})[^.]*\.[^.]*(?P<format>7z|zip|rar|exe)[^.]*(?:\.[^.]+)*$")
    })
}

fn decorated_format_marker_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.[^.]*(?P<format>7z|zip|rar|exe)[^.]*\.[^.]*(?:part|vol(?:ume)?)[^.\d]*(?P<number>\d{1,6})[^.]*(?:\.[^.]+)*$")
    })
}

fn decorated_numeric_format_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.[^.]*?(?P<number>0\d{2,3})[^.]*\.[^.]*(?P<format>7z|zip|rar)[^.]*(?:\.[^.]+)*$")
    })
}

fn decorated_format_numeric_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| {
        re(r"^(?P<prefix>.+)\.[^.]*(?P<format>7z|zip|rar)[^.]*\.[^.]*?(?P<number>0\d{2,3})[^.]*(?:\.[^.]+)*$")
    })
}

fn decorated_zip_spanned_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.[^.]*z[^.\d]*(?P<number>\d+)[^.]*(?:\.[^.]+)*$"))
}

fn decorated_old_rar_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"^(?P<prefix>.+)\.[^.]*r[^.\d]*(?P<number>\d{2,})[^.]*(?:\.[^.]+)*$"))
}

fn old_rar_member_re() -> &'static Regex {
    static VALUE: OnceLock<Regex> = OnceLock::new();
    VALUE.get_or_init(|| re(r"\.r(\d{2})$"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_filter_family_keys_join_numbered_7z_parts_and_exclude_other_prefixes() {
        let first = relations_size_filter_split_family_keys(r"C:\downloads\payload.7z.001");
        let tail = relations_size_filter_split_family_keys(r"C:\downloads\payload.7z.003");
        let other = relations_size_filter_split_family_keys(r"C:\downloads\other.7z.003");

        assert!(first.iter().any(|key| tail.contains(key)));
        assert!(!first.iter().any(|key| other.contains(key)));
    }

    #[test]
    fn noisy_rar_part_names_keep_the_same_declared_family_and_prefix() {
        let first = parse_numbered_volume_name("X.AApart01tail.BBrarCC").unwrap();
        let second = parse_numbered_volume_name("X.DDpart02more.EErarFF").unwrap();

        assert_eq!(first.family, "rar");
        assert_eq!(second.family, "rar");
        assert_eq!(first.style, "rar_part");
        assert_eq!(second.style, "rar_part");
        assert_eq!(first.prefix, "X");
        assert_eq!(second.prefix, "X");
        assert_eq!((first.number, second.number), (1, 2));
        assert!(first.decorated && second.decorated);
    }

    #[test]
    fn noisy_format_tokens_remain_cross_family_incompatible() {
        let seven_zip = parse_numbered_volume_name("X.AA7zZZ.BB001CC").unwrap();
        let zip = parse_numbered_volume_name("X.DDzipYY.EE001FF").unwrap();
        let rar = parse_numbered_volume_name("X.GGpart01noise.HHrarII").unwrap();

        assert_eq!(
            (seven_zip.family, seven_zip.style),
            ("7z", "numeric_suffix")
        );
        assert_eq!((zip.family, zip.style), ("zip", "numeric_suffix"));
        assert_eq!((rar.family, rar.style), ("rar", "rar_part"));
        assert_ne!(seven_zip.family, zip.family);
        assert_ne!(seven_zip.family, rar.family);
        assert_ne!(zip.family, rar.family);
    }

    #[test]
    fn structural_part_marker_outranks_numeric_camouflage_suffix() {
        let candidates = parse_volume_candidates("payload.part2.456");
        assert_eq!(candidates[0].prefix, "payload");
        assert_eq!(candidates[0].number, 2);
        assert_eq!(candidates[0].style, "part_numbered");
        assert_eq!(candidates[0].family, "generic");
        assert!(candidates[0].decorated);
        assert!(candidates.iter().any(|candidate| {
            candidate.style == "plain_numeric_suffix" && candidate.number == 456
        }));
    }

    #[test]
    fn marker_parser_keeps_apparent_format_before_or_after_marker() {
        let before = parse_numbered_volume_name("payload.7z.part0002.photo").unwrap();
        let after = parse_numbered_volume_name("payload.part0002.7z.photo").unwrap();
        for parsed in [before, after] {
            assert_eq!(parsed.prefix, "payload");
            assert_eq!(parsed.number, 2);
            assert_eq!(parsed.style, "part_numbered");
            assert_eq!(parsed.family, "7z");
            assert_eq!(parsed.width, 4);
        }
    }

    #[test]
    fn marker_parser_does_not_treat_partition_words_as_volumes() {
        let parsed = parse_numbered_volume_name("report.partition1.2024").unwrap();
        assert_eq!(parsed.style, "plain_numeric_suffix");
        assert_eq!(parsed.number, 2024);
    }

    #[test]
    fn ordinary_prefix_substrings_do_not_become_format_evidence() {
        let parsed = parse_numbered_volume_name("example.part1.photo").unwrap();
        assert_eq!(parsed.style, "part_numbered");
        assert_eq!(parsed.family, "generic");
    }

    #[test]
    fn observed_missing_ranges_are_compact_and_compatibility_indices_are_bounded() {
        let present = HashSet::from([1, 1_000_000]);
        let (ranges, indices) = observed_missing(&present, 1_000_000);
        assert_eq!(ranges, vec![(2, 999_999)]);
        assert_eq!(indices.len(), 256);
        assert_eq!(indices[0], 2);
        assert_eq!(indices[255], 257);
    }
}
