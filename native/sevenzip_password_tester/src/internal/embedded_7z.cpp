#include "embedded_7z.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <limits>

namespace sunpack::sevenzip {

namespace {

using UInt32 = std::uint32_t;
using UInt64 = std::uint64_t;

std::wstring win32_extended_path(const std::wstring& path) {
    if (path.empty()) {
        return path;
    }
    if (path.rfind(LR"(\\?\)", 0) == 0 || path.rfind(LR"(\\.\)", 0) == 0) {
        return path;
    }
    if (path.rfind(LR"(\\)", 0) == 0) {
        return LR"(\\?\UNC\)" + path.substr(2);
    }
    if (path.size() >= 3 && path[1] == L':' && (path[2] == L'\\' || path[2] == L'/')) {
        return LR"(\\?\)" + path;
    }
    return path;
}

std::wstring lower_text(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return value;
}

std::wstring lower_extension(const std::wstring& path) {
    return lower_text(std::filesystem::path(path).extension().wstring());
}

std::wstring filename_lower(const std::wstring& path) {
    return lower_text(std::filesystem::path(path).filename().wstring());
}

UInt64 file_size_or_zero(const std::wstring& path) {
    try {
        return static_cast<UInt64>(std::filesystem::file_size(path));
    } catch (...) {
        return 0;
    }
}

UInt32 le32_at(const std::vector<unsigned char>& data, std::size_t offset) {
    if (offset + 4 > data.size()) {
        return 0;
    }
    return static_cast<UInt32>(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
}

UInt64 le64_at(const std::vector<unsigned char>& data, std::size_t offset) {
    return static_cast<UInt64>(le32_at(data, offset)) |
        (static_cast<UInt64>(le32_at(data, offset + 4)) << 32);
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

bool read_file_range_exact(
    const std::wstring& path,
    UInt64 offset,
    UInt64 size,
    std::vector<unsigned char>& data
) {
#ifdef _WIN32
    data.clear();
    if (size > static_cast<UInt64>(std::numeric_limits<DWORD>::max())) {
        return false;
    }
    data.resize(static_cast<std::size_t>(size));
    HANDLE handle = CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER distance{};
    distance.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(handle, distance, nullptr, FILE_BEGIN)) {
        CloseHandle(handle);
        return false;
    }
    DWORD read = 0;
    const BOOL ok = data.empty() || ReadFile(handle, data.data(), static_cast<DWORD>(data.size()), &read, nullptr);
    CloseHandle(handle);
    return ok && read == data.size();
#else
    (void)path;
    (void)offset;
    (void)size;
    (void)data;
    return false;
#endif
}

bool seven_zip_header_ok_at(const std::wstring& path, UInt64 offset, UInt64 file_size) {
    if (offset + 32u > file_size) {
        return false;
    }
    std::vector<unsigned char> header;
    if (!read_file_range_exact(path, offset, 32, header)) {
        return false;
    }
    const unsigned char signature[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
    if (!std::equal(std::begin(signature), std::end(signature), header.begin())) {
        return false;
    }
    const UInt32 stored_start_crc = le32_at(header, 8);
    if (crc32_bytes(header.data() + 12, 20) != stored_start_crc) {
        return false;
    }
    const UInt64 next_offset = le64_at(header, 12);
    const UInt64 next_size = le64_at(header, 20);
    if (next_offset > file_size || next_size > file_size) {
        return false;
    }
    const UInt64 next_start = offset + 32u + next_offset;
    if (next_start < offset || next_start > file_size || next_start + next_size < next_start || next_start + next_size > file_size) {
        return false;
    }
    if (next_size == 0) {
        return true;
    }
    constexpr UInt64 kMaxNextHeaderCrcBytes = 64ull * 1024ull * 1024ull;
    if (next_size > kMaxNextHeaderCrcBytes) {
        return true;
    }
    std::vector<unsigned char> next_header;
    if (!read_file_range_exact(path, next_start, next_size, next_header)) {
        return false;
    }
    return crc32_bytes(next_header.data(), static_cast<std::size_t>(next_header.size())) == le32_at(header, 28);
}

std::vector<UInt64> find_seven_zip_signature_offsets(const std::wstring& path, std::size_t max_candidates = 16) {
    std::vector<UInt64> offsets;
#ifdef _WIN32
    const UInt64 file_size = file_size_or_zero(path);
    if (file_size <= 32) {
        return offsets;
    }
    HANDLE handle = CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return offsets;
    }

    const unsigned char signature[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
    constexpr DWORD kChunkSize = 4u * 1024u * 1024u;
    std::vector<unsigned char> carry;
    UInt64 file_offset = 0;
    while (file_offset < file_size && offsets.size() < max_candidates) {
        const UInt64 remaining = file_size - file_offset;
        const DWORD want = static_cast<DWORD>(std::min<UInt64>(remaining, kChunkSize));
        std::vector<unsigned char> buffer(carry.size() + want);
        std::copy(carry.begin(), carry.end(), buffer.begin());
        DWORD read = 0;
        const BOOL ok = ReadFile(handle, buffer.data() + carry.size(), want, &read, nullptr);
        if (!ok || read == 0) {
            break;
        }
        buffer.resize(carry.size() + read);
        const UInt64 scan_base = file_offset - carry.size();
        for (std::size_t index = 0; index + sizeof(signature) <= buffer.size(); ++index) {
            if (!std::equal(std::begin(signature), std::end(signature), buffer.begin() + index)) {
                continue;
            }
            const UInt64 absolute = scan_base + index;
            if (absolute == 0) {
                continue;
            }
            if (seven_zip_header_ok_at(path, absolute, file_size)) {
                offsets.push_back(absolute);
                if (offsets.size() >= max_candidates) {
                    break;
                }
            }
        }
        file_offset += read;
        const std::size_t keep = std::min<std::size_t>(sizeof(signature) - 1, buffer.size());
        carry.assign(buffer.end() - keep, buffer.end());
    }
    CloseHandle(handle);
#else
    (void)path;
    (void)max_candidates;
#endif
    return offsets;
}

std::vector<std::wstring> unique_paths(const std::wstring& archive_path, const std::vector<std::wstring>& part_paths) {
    std::vector<std::wstring> input = part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;
    if (std::find(input.begin(), input.end(), archive_path) == input.end()) {
        input.push_back(archive_path);
    }
    std::vector<std::wstring> result;
    std::vector<std::wstring> seen;
    for (const auto& path : input) {
        if (path.empty()) {
            continue;
        }
        const std::wstring key = lower_text(std::filesystem::path(path).wstring());
        if (std::find(seen.begin(), seen.end(), key) != seen.end()) {
            continue;
        }
        seen.push_back(key);
        result.push_back(path);
    }
    return result;
}

}  // namespace

bool is_standard_seven_zip_path(const std::wstring& path) {
    const std::wstring ext = lower_extension(path);
    if (ext == L".7z") {
        return true;
    }
    const std::wstring name = filename_lower(path);
    return name.size() >= 7 && name.compare(name.size() - 7, 7, L".7z.001") == 0;
}

std::vector<EmbeddedSevenZipCandidate> find_embedded_seven_zip_candidates(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths
) {
    std::vector<EmbeddedSevenZipCandidate> candidates;
    for (const auto& path : unique_paths(archive_path, part_paths)) {
        for (const UInt64 offset : find_seven_zip_signature_offsets(path)) {
            candidates.push_back(EmbeddedSevenZipCandidate{path, offset});
        }
    }
    return candidates;
}

}  // namespace sunpack::sevenzip
