#include "strict_archive_validation.hpp"

#include "sevenzip_sdk.hpp"

#ifdef _WIN32
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <vector>
#endif

namespace sunpack::sevenzip {

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

class RangeFile {
public:
    explicit RangeFile(const std::wstring& path)
        : handle_(CreateFileW(
            win32_extended_path(path).c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        )) {
        LARGE_INTEGER size{};
        if (handle_ != INVALID_HANDLE_VALUE && GetFileSizeEx(handle_, &size) && size.QuadPart >= 0) {
            size_ = static_cast<UInt64>(size.QuadPart);
            valid_ = true;
        }
    }

    ~RangeFile() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    bool valid() const { return valid_; }
    UInt64 size() const { return size_; }

    bool read(UInt64 offset, std::size_t size, std::vector<unsigned char>& output) const {
        output.clear();
        if (!valid_ || offset > size_ || size > size_ - offset || size > static_cast<std::size_t>(MAXDWORD)) {
            return false;
        }
        output.resize(size);
        if (size == 0) {
            return true;
        }
        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(offset);
        if (!SetFilePointerEx(handle_, position, nullptr, FILE_BEGIN)) {
            return false;
        }
        DWORD bytes_read = 0;
        return ReadFile(handle_, output.data(), static_cast<DWORD>(size), &bytes_read, nullptr) && bytes_read == size;
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    UInt64 size_ = 0;
    bool valid_ = false;
};

bool extra_fields_ok(const std::vector<unsigned char>& data) {
    std::size_t cursor = 0;
    while (cursor < data.size()) {
        if (cursor + 4 > data.size()) {
            return false;
        }
        const UInt16 header_id = le16_at(data, cursor);
        const UInt16 field_size = le16_at(data, cursor + 2);
        if (header_id == 0 && field_size == 0) {
            return false;
        }
        cursor += 4u + field_size;
        if (cursor > data.size()) {
            return false;
        }
    }
    return cursor == data.size();
}

const ExtractOutputItemTrace* trace_item(const ExtractOutputTrace& trace, UInt32 index) {
    const auto found = std::find_if(trace.items.begin(), trace.items.end(), [index](const auto& item) {
        return item.index == index;
    });
    return found == trace.items.end() ? nullptr : &*found;
}

bool stored_payload_was_verified(
    const ExtractOutputTrace& trace,
    UInt32 index,
    UInt32 expected_crc,
    UInt64 expected_size
) {
    const auto* item = trace_item(trace, index);
    if (!item || item->is_dir) {
        return item && item->is_dir && item->done;
    }
    return item->done && item->crc_verified && item->has_source_crc32 && item->has_output_crc32 &&
        item->source_crc32 == expected_crc && item->output_crc32 == expected_crc &&
        (!item->has_expected_size || item->expected_size == expected_size) && item->bytes_written == expected_size;
}

bool strict_zip_stored_entries_ok(const std::wstring& path, const ExtractOutputTrace& output_trace) {
    RangeFile file(path);
    if (!file.valid() || file.size() < 22) {
        return false;
    }
    const std::size_t tail_size = static_cast<std::size_t>(std::min<UInt64>(file.size(), 65557));
    const UInt64 tail_offset = file.size() - tail_size;
    std::vector<unsigned char> tail;
    if (!file.read(tail_offset, tail_size, tail)) {
        return false;
    }
    std::size_t eocd = std::string::npos;
    for (std::size_t pos = tail.size() - 22 + 1; pos-- > 0;) {
        if (pos + 4 <= tail.size() && le32_at(tail, pos) == 0x06054b50u) {
            eocd = pos;
            break;
        }
        if (pos == 0) {
            break;
        }
    }
    if (eocd == std::string::npos || eocd + 22 > tail.size()) {
        return false;
    }
    const UInt16 entries = le16_at(tail, eocd + 10);
    const UInt16 comment_len = le16_at(tail, eocd + 20);
    const UInt32 cd_size = le32_at(tail, eocd + 12);
    const UInt32 cd_offset = le32_at(tail, eocd + 16);
    const UInt64 absolute_eocd = tail_offset + eocd;
    if (entries == 0 || absolute_eocd + 22u + comment_len != file.size() ||
        static_cast<UInt64>(cd_offset) + cd_size > file.size()) {
        return false;
    }
    UInt64 cursor = cd_offset;
    const UInt64 cd_end = static_cast<UInt64>(cd_offset) + cd_size;
    std::vector<unsigned char> fixed;
    std::vector<unsigned char> central_name;
    std::vector<unsigned char> central_extra;
    std::vector<unsigned char> local_name;
    std::vector<unsigned char> local_extra;
    for (UInt16 index = 0; index < entries; ++index) {
        if (cursor + 46 > cd_end || !file.read(cursor, 46, fixed) || le32_at(fixed, 0) != 0x02014b50u) {
            return false;
        }
        const UInt16 method = le16_at(fixed, 10);
        const UInt32 expected_crc = le32_at(fixed, 16);
        const UInt32 compressed_size = le32_at(fixed, 20);
        const UInt32 uncompressed_size = le32_at(fixed, 24);
        const UInt16 name_len = le16_at(fixed, 28);
        const UInt16 extra_len = le16_at(fixed, 30);
        const UInt16 entry_comment_len = le16_at(fixed, 32);
        const UInt32 local_offset = le32_at(fixed, 42);
        const UInt64 variable_size = static_cast<UInt64>(name_len) + extra_len + entry_comment_len;
        if (cursor + 46u + variable_size > cd_end ||
            !file.read(cursor + 46u, name_len, central_name) ||
            !file.read(cursor + 46u + name_len, extra_len, central_extra) ||
            !extra_fields_ok(central_extra)) {
            return false;
        }
        cursor += 46u + variable_size;
        if (static_cast<UInt64>(local_offset) + 30u > file.size() ||
            !file.read(local_offset, 30, fixed) || le32_at(fixed, 0) != 0x04034b50u) {
            return false;
        }
        const UInt16 local_name_len = le16_at(fixed, 26);
        const UInt16 local_extra_len = le16_at(fixed, 28);
        if (local_name_len != name_len ||
            !file.read(static_cast<UInt64>(local_offset) + 30u, local_name_len, local_name) ||
            central_name != local_name ||
            !file.read(static_cast<UInt64>(local_offset) + 30u + local_name_len, local_extra_len, local_extra) ||
            !extra_fields_ok(local_extra)) {
            return false;
        }
        const UInt64 payload_offset = static_cast<UInt64>(local_offset) + 30u + local_name_len + local_extra_len;
        if (payload_offset + compressed_size > file.size()) {
            return false;
        }
        if (method == 0 && !stored_payload_was_verified(output_trace, index, expected_crc, uncompressed_size)) {
            return false;
        }
    }
    return cursor == cd_end;
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

}  // namespace sunpack::sevenzip
