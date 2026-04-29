#include "strict_archive_validation.hpp"

#include "sevenzip_sdk.hpp"

#ifdef _WIN32
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <vector>
#endif

namespace packrelic::sevenzip {

#ifdef _WIN32

UInt16 le16_at(const std::vector<unsigned char>& data, std::size_t offset) {
    if (offset + 2 > data.size()) {
        return 0;
    }
    return static_cast<UInt16>(data[offset] | (data[offset + 1] << 8));
}

UInt32 le32_at(const std::vector<unsigned char>& data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        return 0;
    }
    return static_cast<UInt32>(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
}

UInt32 crc32_bytes(const unsigned char* bytes, std::size_t size) {
    UInt32 crc = 0xFFFF'FFFFu;
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= bytes[i];
        for (int bit = 0; bit < 8; ++bit) {
            const UInt32 mask = (crc & 1u) ? 0xEDB8'8320u : 0u;
            crc = (crc >> 1) ^ mask;
        }
    }
    return ~crc;
}

bool read_file_bytes(const std::wstring& path, std::vector<unsigned char>& data) {
    try {
        const auto size = std::filesystem::file_size(path);
        data.resize(static_cast<std::size_t>(size));
    } catch (...) {
        return false;
    }
    HANDLE handle = CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD read = 0;
    const BOOL ok = data.empty() || ReadFile(handle, data.data(), static_cast<DWORD>(data.size()), &read, nullptr);
    CloseHandle(handle);
    return ok && read == data.size();
}

bool strict_zip_stored_entries_ok(const std::wstring& path) {
    std::vector<unsigned char> data;
    if (!read_file_bytes(path, data) || data.size() < 22) {
        return false;
    }
    const std::size_t min_eocd = data.size() > 65557 ? data.size() - 65557 : 0;
    std::size_t eocd = std::string::npos;
    for (std::size_t pos = data.size() - 22 + 1; pos-- > min_eocd;) {
        if (pos + 4 <= data.size() && le32_at(data, pos) == 0x06054b50u) {
            eocd = pos;
            break;
        }
        if (pos == 0) {
            break;
        }
    }
    if (eocd == std::string::npos || eocd + 22 > data.size()) {
        return false;
    }
    const UInt16 entries = le16_at(data, eocd + 10);
    const UInt16 comment_len = le16_at(data, eocd + 20);
    const UInt32 cd_size = le32_at(data, eocd + 12);
    const UInt32 cd_offset = le32_at(data, eocd + 16);
    if (entries == 0 || eocd + 22u + comment_len != data.size() || cd_offset > data.size() || static_cast<UInt64>(cd_offset) + cd_size > data.size()) {
        return false;
    }
    auto extra_ok = [&](std::size_t offset, std::size_t size) {
        const std::size_t end = offset + size;
        if (end > data.size()) {
            return false;
        }
        std::size_t cursor = offset;
        while (cursor < end) {
            if (cursor + 4 > end) {
                return false;
            }
            const UInt16 header_id = le16_at(data, cursor);
            const UInt16 data_size = le16_at(data, cursor + 2);
            if (header_id == 0 && data_size == 0) {
                return false;
            }
            cursor += 4u + data_size;
        }
        return cursor == end;
    };
    std::size_t cursor = cd_offset;
    for (UInt16 index = 0; index < entries; ++index) {
        if (cursor + 46 > data.size() || le32_at(data, cursor) != 0x02014b50u) {
            return false;
        }
        const UInt16 method = le16_at(data, cursor + 10);
        const UInt32 expected_crc = le32_at(data, cursor + 16);
        const UInt32 compressed_size = le32_at(data, cursor + 20);
        const UInt32 local_offset = le32_at(data, cursor + 42);
        const UInt16 name_len = le16_at(data, cursor + 28);
        const UInt16 extra_len = le16_at(data, cursor + 30);
        const UInt16 comment_len = le16_at(data, cursor + 32);
        if (!extra_ok(cursor + 46u + name_len, extra_len)) {
            return false;
        }
        const std::size_t cd_name_offset = cursor + 46u;
        cursor += 46u + name_len + extra_len + comment_len;
        if (cursor > data.size() || local_offset + 30u > data.size() || le32_at(data, local_offset) != 0x04034b50u) {
            return false;
        }
        const UInt16 local_name_len = le16_at(data, local_offset + 26);
        const UInt16 local_extra_len = le16_at(data, local_offset + 28);
        const std::size_t local_name_offset = local_offset + 30u;
        if (local_name_len != name_len || local_name_offset + local_name_len > data.size() ||
            !std::equal(data.begin() + cd_name_offset, data.begin() + cd_name_offset + name_len, data.begin() + local_name_offset)) {
            return false;
        }
        if (!extra_ok(local_offset + 30u + local_name_len, local_extra_len)) {
            return false;
        }
        const UInt64 payload_offset = static_cast<UInt64>(local_offset) + 30u + local_name_len + local_extra_len;
        if (payload_offset + compressed_size > data.size()) {
            return false;
        }
        if (method == 0 && crc32_bytes(data.data() + payload_offset, compressed_size) != expected_crc) {
            return false;
        }
    }
    return cursor == static_cast<std::size_t>(cd_offset) + cd_size;
}

bool strict_seven_zip_headers_ok(const std::wstring& path) {
    std::vector<unsigned char> data;
    if (!read_file_bytes(path, data) || data.size() < 32) {
        return false;
    }
    const unsigned char signature[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
    if (!std::equal(std::begin(signature), std::end(signature), data.begin())) {
        return false;
    }
    const UInt32 stored_start_crc = le32_at(data, 8);
    if (crc32_bytes(data.data() + 12, 20) != stored_start_crc) {
        return false;
    }
    const UInt64 next_offset =
        static_cast<UInt64>(le32_at(data, 12)) |
        (static_cast<UInt64>(le32_at(data, 16)) << 32);
    const UInt64 next_size =
        static_cast<UInt64>(le32_at(data, 20)) |
        (static_cast<UInt64>(le32_at(data, 24)) << 32);
    const UInt32 next_crc = le32_at(data, 28);
    const UInt64 next_start = 32u + next_offset;
    if (next_start > data.size() || next_size > data.size() || next_start + next_size > data.size()) {
        return false;
    }
    if (next_size == 0) {
        return true;
    }
    return crc32_bytes(data.data() + next_start, static_cast<std::size_t>(next_size)) == next_crc;
}

#endif

}  // namespace packrelic::sevenzip
