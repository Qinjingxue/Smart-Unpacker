use crate::io::read_fault::{read_exact_field, seek_field, FieldLocation};
use aes::{
    cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit},
    Aes256,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use lzma_rust2::{
    filter::{bcj::BcjReader, bcj2::Bcj2Reader, delta::DeltaReader},
    Lzma2Reader, LzmaReader,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use sevenz_rust2::{
    Archive, ArchiveEntry, ArchiveWriter, BlockDecoder, EncoderConfiguration, EncoderMethod,
    Password,
};
use sha2::Digest;
use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, Write};
use std::path::{Path, PathBuf};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

include!("constants.rs");
include!("types.rs");
include!("source.rs");
include!("header/parse.rs");
include!("header/encoded.rs");
include!("header/write.rs");
include!("scan.rs");
include!("repair/result.rs");
include!("repair/salvage.rs");
include!("repair/boundary.rs");
include!("repair/crc.rs");
include!("repair/next_header.rs");
include!("repair/metadata.rs");

#[pyfunction]
pub(crate) fn seven_zip_runtime_cache_stats(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("kdf_entries", seven_zip_kdf_cache_len())?;
    dict.set_item(
        "encoded_header_coder_properties_entries",
        seven_zip_encoded_header_coder_properties_cache_len(),
    )?;
    Ok(dict.unbind())
}

#[pyfunction]
pub(crate) fn clear_seven_zip_runtime_caches(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("kdf_entries", clear_seven_zip_kdf_cache())?;
    dict.set_item(
        "encoded_header_coder_properties_entries",
        clear_seven_zip_encoded_header_coder_properties_cache(),
    )?;
    Ok(dict.unbind())
}
