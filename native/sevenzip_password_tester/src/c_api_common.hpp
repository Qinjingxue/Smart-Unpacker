#pragma once

#include "sevenzip_password_tester/password_tester.hpp"

#include <algorithm>
#include <cwchar>
#include <string>
#include <vector>

namespace smart_unpacker::sevenzip::capi {

inline void copy_message(wchar_t* destination, int destination_chars, const std::string& message) {
    if (!destination || destination_chars <= 0) {
        return;
    }
    std::wstring wide(message.begin(), message.end());
    const int count = static_cast<int>(std::min<std::size_t>(wide.size(), static_cast<std::size_t>(destination_chars - 1)));
    std::wmemcpy(destination, wide.c_str(), count);
    destination[count] = L'\0';
}

inline void copy_wide(wchar_t* destination, int destination_chars, const std::wstring& text) {
    if (!destination || destination_chars <= 0) {
        return;
    }
    const int count = static_cast<int>(std::min<std::size_t>(text.size(), static_cast<std::size_t>(destination_chars - 1)));
    std::wmemcpy(destination, text.c_str(), count);
    destination[count] = L'\0';
}

inline int status_code(PasswordTestStatus status) {
    return static_cast<int>(status);
}

inline std::vector<std::wstring> collect_part_paths(
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count
) {
    std::vector<std::wstring> parts;
    if (part_paths && part_count > 0) {
        for (int i = 0; i < part_count; ++i) {
            if (part_paths[i] && part_paths[i][0] != L'\0') {
                parts.emplace_back(part_paths[i]);
            }
        }
    }
    if (parts.empty() && archive_path) {
        parts.emplace_back(archive_path);
    }
    return parts;
}

}  // namespace smart_unpacker::sevenzip::capi
