use flate2::{Decompress, FlushDecompress, Status};
use memchr::memmem;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const LFH_SIG: &[u8] = b"PK\x03\x04";
const DD_SIG: &[u8] = b"PK\x07\x08";
const CD_SIG: &[u8] = b"PK\x01\x02";
const EOCD_SIG: &[u8] = b"PK\x05\x06";
const ZIP64_EOCD_SIG: &[u8] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIG: &[u8] = b"PK\x06\x07";
const LOCAL_HEADER_LEN: usize = 30;
const COPY_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_NAME_LEN: usize = 4096;

fn extract_password(source_input: &Bound<'_, PyDict>) -> Option<String> {
    source_input
        .get_item("password")
        .ok()
        .flatten()
        .and_then(|v| v.extract::<String>().ok())
}

