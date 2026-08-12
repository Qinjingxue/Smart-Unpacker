from __future__ import annotations

import pytest


ZIP_CASES = [
    pytest.param("zipcrypto", "ZipCrypto", None, id="zipcrypto"),
    pytest.param("aes128", "AES128", None, id="aes128"),
    pytest.param("aes256", "AES256", None, id="aes256"),
    pytest.param("deflate64", "ZipCrypto", "Deflate64", id="deflate64"),
    pytest.param("bzip2", "ZipCrypto", "BZip2", id="bzip2"),
    pytest.param("lzma", "ZipCrypto", "LZMA", id="lzma"),
    pytest.param("ppmd", "ZipCrypto", "PPMd", id="ppmd"),
]

RAR_CASES = [
    pytest.param("rar5-header", False, True, id="rar5-header"),
    pytest.param("rar5-data", False, False, id="rar5-data"),
    pytest.param("rar4-header", True, True, id="rar4-header"),
    pytest.param("rar4-data", True, False, id="rar4-data"),
]

SEVEN_ZIP_CASES = [
    pytest.param("header-on", True, True, None, id="header-on"),
    pytest.param("header-off", False, True, None, id="header-off"),
    pytest.param("nonsolid", True, False, None, id="nonsolid"),
    pytest.param("lzma", True, True, "LZMA", id="lzma"),
    pytest.param("ppmd", True, True, "PPMd", id="ppmd"),
    pytest.param("bzip2", True, True, "BZip2", id="bzip2"),
    pytest.param("deflate", True, True, "Deflate", id="deflate"),
]

SFX_FORMATS = ["7z", "zip", "rar"]
