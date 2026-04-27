#include "sevenzip_password_tester/password_tester.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string read_stdin() {
    std::ostringstream buffer;
    buffer << std::cin.rdbuf();
    return buffer.str();
}

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (const char ch : value) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += ch; break;
        }
    }
    return out;
}

std::wstring utf8_to_wide(const std::string& value) {
#ifdef _WIN32
    if (value.empty()) {
        return L"";
    }
    const int chars = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (chars <= 0) {
        return std::wstring(value.begin(), value.end());
    }
    std::wstring wide(static_cast<std::size_t>(chars), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), wide.data(), chars);
    return wide;
#else
    return std::wstring(value.begin(), value.end());
#endif
}

std::string wide_to_utf8(const std::wstring& value) {
#ifdef _WIN32
    if (value.empty()) {
        return "";
    }
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) {
        return "";
    }
    std::string out(static_cast<std::size_t>(bytes), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), bytes, nullptr, nullptr);
    return out;
#else
    return std::string(value.begin(), value.end());
#endif
}

std::size_t skip_ws(const std::string& json, std::size_t pos) {
    while (pos < json.size() && static_cast<unsigned char>(json[pos]) <= 0x20) {
        ++pos;
    }
    return pos;
}

std::string parse_json_string_at(const std::string& json, std::size_t quote_pos, std::size_t* out_next = nullptr) {
    std::string out;
    if (quote_pos >= json.size() || json[quote_pos] != '"') {
        return out;
    }
    for (std::size_t i = quote_pos + 1; i < json.size(); ++i) {
        const char ch = json[i];
        if (ch == '"') {
            if (out_next) {
                *out_next = i + 1;
            }
            return out;
        }
        if (ch == '\\' && i + 1 < json.size()) {
            const char escaped = json[++i];
            switch (escaped) {
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            default: out.push_back(escaped); break;
            }
            continue;
        }
        out.push_back(ch);
    }
    return out;
}

std::string json_string_field(const std::string& json, const std::string& key, const std::string& fallback = "") {
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return fallback;
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return fallback;
    }
    const std::size_t quote = skip_ws(json, colon + 1);
    if (quote >= json.size() || json[quote] != '"') {
        return fallback;
    }
    return parse_json_string_at(json, quote);
}

std::vector<std::string> json_string_array_field(const std::string& json, const std::string& key) {
    std::vector<std::string> values;
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return values;
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return values;
    }
    std::size_t pos = skip_ws(json, colon + 1);
    if (pos >= json.size() || json[pos] != '[') {
        return values;
    }
    ++pos;
    while (pos < json.size()) {
        pos = skip_ws(json, pos);
        if (pos < json.size() && json[pos] == ']') {
            break;
        }
        if (pos >= json.size() || json[pos] != '"') {
            break;
        }
        std::size_t next = pos;
        values.push_back(parse_json_string_at(json, pos, &next));
        pos = skip_ws(json, next);
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
        }
    }
    return values;
}

unsigned long long parse_uint_at(const std::string& json, std::size_t pos, bool* ok = nullptr) {
    if (ok) {
        *ok = false;
    }
    pos = skip_ws(json, pos);
    unsigned long long value = 0;
    bool any = false;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
        any = true;
        value = value * 10 + static_cast<unsigned long long>(json[pos] - '0');
        ++pos;
    }
    if (ok) {
        *ok = any;
    }
    return value;
}

bool json_uint_field_in_object(const std::string& object_json, const std::string& key, unsigned long long* value) {
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = object_json.find(needle);
    if (key_pos == std::string::npos) {
        return false;
    }
    const std::size_t colon = object_json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return false;
    }
    bool ok = false;
    const unsigned long long parsed = parse_uint_at(object_json, colon + 1, &ok);
    if (ok && value) {
        *value = parsed;
    }
    return ok;
}

std::vector<std::string> json_object_array_field(const std::string& json, const std::string& key) {
    std::vector<std::string> objects;
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return objects;
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return objects;
    }
    std::size_t pos = skip_ws(json, colon + 1);
    if (pos >= json.size() || json[pos] != '[') {
        return objects;
    }
    ++pos;
    while (pos < json.size()) {
        pos = skip_ws(json, pos);
        if (pos < json.size() && json[pos] == ']') {
            break;
        }
        if (pos >= json.size() || json[pos] != '{') {
            break;
        }
        const std::size_t start = pos;
        int depth = 0;
        bool in_string = false;
        for (; pos < json.size(); ++pos) {
            const char ch = json[pos];
            if (ch == '"' && (pos == 0 || json[pos - 1] != '\\')) {
                in_string = !in_string;
            }
            if (in_string) {
                continue;
            }
            if (ch == '{') {
                ++depth;
            } else if (ch == '}') {
                --depth;
                if (depth == 0) {
                    objects.push_back(json.substr(start, pos - start + 1));
                    ++pos;
                    break;
                }
            }
        }
        pos = skip_ws(json, pos);
        if (pos < json.size() && json[pos] == ',') {
            ++pos;
        }
    }
    return objects;
}

std::vector<smart_unpacker::sevenzip::ExtractInputRange> parse_input_ranges(const std::string& request, const std::string& archive_path) {
    using smart_unpacker::sevenzip::ExtractInputRange;
    std::vector<ExtractInputRange> ranges;
    const std::string kind = json_string_field(request, "kind", "file");
    if (kind == "file_range") {
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start = json_uint_field_in_object(request, "start", &start) || json_uint_field_in_object(request, "start_offset", &start);
        const bool has_end = json_uint_field_in_object(request, "end", &end) || json_uint_field_in_object(request, "end_offset", &end);
        const std::string path = json_string_field(request, "path", archive_path);
        ExtractInputRange range;
        range.path = utf8_to_wide(path.empty() ? archive_path : path);
        range.start = has_start ? start : 0;
        range.end = end;
        range.has_end = has_end;
        ranges.push_back(range);
        return ranges;
    }
    if (kind != "concat_ranges") {
        return ranges;
    }
    for (const auto& object_json : json_object_array_field(request, "ranges")) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start = json_uint_field_in_object(object_json, "start", &start) || json_uint_field_in_object(object_json, "start_offset", &start);
        const bool has_end = json_uint_field_in_object(object_json, "end", &end) || json_uint_field_in_object(object_json, "end_offset", &end);
        const std::string path = json_string_field(object_json, "path", archive_path);
        ExtractInputRange range;
        range.path = utf8_to_wide(path.empty() ? archive_path : path);
        range.start = has_start ? start : 0;
        range.end = end;
        range.has_end = has_end;
        ranges.push_back(range);
    }
    return ranges;
}

void print_json_line(const std::string& json) {
    std::cout << json << "\n";
    std::cout.flush();
}

std::string status_to_string(smart_unpacker::sevenzip::PasswordTestStatus status) {
    return smart_unpacker::sevenzip::status_name(status);
}

}  // namespace

int main() {
    using namespace smart_unpacker::sevenzip;

    const std::string request = read_stdin();
    const std::string job_id = json_string_field(request, "job_id", "");
    const std::wstring dll_path = utf8_to_wide(json_string_field(request, "seven_zip_dll_path", "tools\\7z.dll"));
    const std::wstring archive_path = utf8_to_wide(json_string_field(request, "archive_path", ""));
    const std::wstring output_dir = utf8_to_wide(json_string_field(request, "output_dir", ""));
    const std::wstring password = utf8_to_wide(json_string_field(request, "password", ""));
    const std::wstring format_hint = utf8_to_wide(json_string_field(request, "format_hint", ""));

    std::vector<std::wstring> part_paths;
    for (const auto& part : json_string_array_field(request, "part_paths")) {
        part_paths.push_back(utf8_to_wide(part));
    }

    if (archive_path.empty() || output_dir.empty()) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"error\",\"category\":\"invalid_request\",\"message\":\"archive_path and output_dir are required\"}");
        return 2;
    }

    auto progress = [job_id](const ExtractProgressEvent& event) {
            print_json_line(
                "{\"type\":\"progress\",\"job_id\":\"" + json_escape(job_id) +
                "\",\"event\":\"" + json_escape(event.event) +
                "\",\"completed_bytes\":" + std::to_string(event.completed_bytes) +
                ",\"total_bytes\":" + std::to_string(event.total_bytes) +
                ",\"item_index\":" + std::to_string(event.item_index) +
                ",\"item_path\":\"" + json_escape(wide_to_utf8(event.item_path)) + "\"}");
    };

    const auto input_ranges = parse_input_ranges(request, json_string_field(request, "archive_path", ""));
    const auto result = input_ranges.empty()
        ? extract_archive_with_parts(dll_path, archive_path, part_paths, password, output_dir, progress)
        : extract_archive_with_ranges(dll_path, archive_path, input_ranges, format_hint, password, output_dir, progress);

    const bool ok = result.status == PasswordTestStatus::Ok && result.command_ok;
    print_json_line(
        "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
        "\",\"status\":\"" + std::string(ok ? "ok" : "failed") +
        "\",\"native_status\":\"" + json_escape(status_to_string(result.status)) +
        "\",\"operation_result\":" + std::to_string(result.operation_result) +
        ",\"encrypted\":" + std::string(result.encrypted ? "true" : "false") +
        ",\"damaged\":" + std::string(result.damaged ? "true" : "false") +
        ",\"checksum_error\":" + std::string(result.checksum_error ? "true" : "false") +
        ",\"missing_volume\":" + std::string(result.missing_volume ? "true" : "false") +
        ",\"wrong_password\":" + std::string(result.wrong_password ? "true" : "false") +
        ",\"unsupported_method\":" + std::string(result.unsupported_method ? "true" : "false") +
        ",\"item_count\":" + std::to_string(result.item_count) +
        ",\"files_written\":" + std::to_string(result.files_written) +
        ",\"dirs_written\":" + std::to_string(result.dirs_written) +
        ",\"bytes_written\":" + std::to_string(result.bytes_written) +
        ",\"archive_type\":\"" + json_escape(wide_to_utf8(result.archive_type)) +
        "\",\"failed_item\":\"" + json_escape(wide_to_utf8(result.failed_item)) +
        "\",\"message\":\"" + json_escape(result.message) + "\"}");
    return ok ? 0 : 1;
}
