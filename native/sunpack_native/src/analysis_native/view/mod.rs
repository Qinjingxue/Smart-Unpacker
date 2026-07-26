use super::profile::{fuzzy_binary_profile as build_fuzzy_binary_profile, BinaryProfileConfig};
use crate::io::reader::{ManagedReader, ReaderConfig};
use bzip2::read::BzDecoder;
use flate2::read::GzDecoder;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::io::{Cursor, Read};
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
