use crate::scan::magic::rfind_subslice;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

include!("constants.rs");
include!("api.rs");
include!("common.rs");
include!("seven_zip.rs");
include!("rar.rs");
include!("tar.rs");
include!("compression.rs");
include!("util.rs");
