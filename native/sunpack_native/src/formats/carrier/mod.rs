use flate2::read::GzDecoder;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

include!("repair.rs");
include!("../rar/repair.rs");
include!("../nested/repair.rs");
include!("types.rs");
include!("scan.rs");
include!("../rar/parse.rs");
include!("../nested/scan.rs");
include!("source.rs");
include!("write.rs");
include!("result.rs");
include!("facts.rs");
include!("util.rs");
