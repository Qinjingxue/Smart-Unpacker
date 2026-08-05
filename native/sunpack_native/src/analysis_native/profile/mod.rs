use crate::io::read_fault::FieldLocation;
use crate::io::reader::ManagedReader;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;

include!("constants.rs");
include!("api.rs");
include!("types.rs");
include!("windows.rs");
include!("anomalies.rs");
include!("py_output.rs");
include!("runs.rs");
include!("util.rs");
