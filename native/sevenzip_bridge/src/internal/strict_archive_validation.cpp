#include "strict_archive_validation.hpp"

#include "sevenzip_sdk.hpp"
#include "sevenzip_paths.hpp"

#ifdef _WIN32
#include <algorithm>
#include <limits>
#include <vector>
#endif

namespace sunpack::sevenzip {

#ifdef _WIN32

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

bool seven_zip_parts_prove_missing_tail(const std::vector<std::wstring>& part_paths) {
    const auto volumes = sorted_data_volume_paths(unique_existing_paths(L"", part_paths));
    if (volumes.empty() || !has_numbered_split_head(volumes)) {
        return false;
    }

    RangeFile first(volumes.front());
    std::vector<unsigned char> header;
    if (!first.valid() || !first.read(0, 32, header)) {
        return false;
    }
    const unsigned char signature[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
    if (!std::equal(std::begin(signature), std::end(signature), header.begin())) {
        return false;
    }
    if (crc32_bytes(header.data() + 12, 20) != le32_at(header, 8)) {
        return false;
    }

    const UInt64 next_offset =
        static_cast<UInt64>(le32_at(header, 12)) |
        (static_cast<UInt64>(le32_at(header, 16)) << 32);
    const UInt64 next_size =
        static_cast<UInt64>(le32_at(header, 20)) |
        (static_cast<UInt64>(le32_at(header, 24)) << 32);
    if (next_offset > std::numeric_limits<UInt64>::max() - 32u ||
        next_size > std::numeric_limits<UInt64>::max() - (32u + next_offset)) {
        return false;
    }
    const UInt64 expected_size = 32u + next_offset + next_size;
    UInt64 available_size = 0;
    for (const auto& path : volumes) {
        const UInt64 size = file_size_or_zero(path);
        if (size > std::numeric_limits<UInt64>::max() - available_size) {
            return false;
        }
        available_size += size;
    }
    return available_size < expected_size;
}

#endif

}  // namespace sunpack::sevenzip