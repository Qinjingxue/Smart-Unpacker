use super::profile::{fuzzy_binary_profile as build_fuzzy_binary_profile, BinaryProfileConfig};
use crate::io::read_fault::{FieldLocation, ReadFault};
use crate::io::reader::{ManagedReader, ReaderConfig};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::io::Read;
use xz2::read::XzDecoder;
use zstd::stream::read::Decoder as ZstdDecoder;

include!("constants.rs");
include!("types.rs");
include!("binary.rs");
include!("multivolume.rs");
include!("impls.rs");
include!("signatures.rs");
include!("tar.rs");
include!("compression.rs");

fn reader_error_to_py(error: std::io::Error) -> PyErr {
    if error.to_string() == "archive analysis read budget exceeded" {
        pyo3::exceptions::PyRuntimeError::new_err(error.to_string())
    } else {
        error.into()
    }
}

fn set_view_read_fault(
    result: &Bound<'_, PyDict>,
    fault: &ReadFault,
    legacy_error: &str,
) -> PyResult<()> {
    result.set_item("error", legacy_error)?;
    fault.write_python(result)?;
    let mut flags = result
        .get_item("damage_flags")?
        .and_then(|value| value.extract::<Vec<String>>().ok())
        .unwrap_or_default();
    let mut push_flag = |flag: &str| {
        if !flags.iter().any(|existing| existing == flag) {
            flags.push(flag.to_string());
        }
    };
    push_flag("read_error");
    if fault.code == "unexpected_eof" {
        push_flag("input_truncated");
        push_flag("probably_truncated");
    }
    if fault.possible_missing_volume() {
        push_flag("missing_volume");
    }
    result.set_item("damage_flags", PyList::new(result.py(), flags)?)
}
