#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <filesystem>
#include <future>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <deque>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "internal/sevenzip_status.hpp"
#include "internal/archive_operations.hpp"
#include "internal/sevenzip_formats.hpp"
#include "internal/native_runtime_control.hpp"
#ifdef _WIN32
#include "internal/sevenzip_async_output.hpp"
#endif

namespace {

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (const unsigned char ch : value) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                std::ostringstream escaped;
                escaped << "\\u"
                        << std::uppercase << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(ch);
                out += escaped.str();
            } else {
                out += static_cast<char>(ch);
            }
            break;
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

bool json_bool_field(const std::string& json, const std::string& key, bool fallback = false) {
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return fallback;
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return fallback;
    }
    const std::size_t pos = skip_ws(json, colon + 1);
    if (json.compare(pos, 4, "true") == 0) {
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        return false;
    }
    if (pos < json.size() && json[pos] == '"') {
        const std::string text = parse_json_string_at(json, pos);
        return text == "true" || text == "1" || text == "yes";
    }
    return fallback;
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

std::string json_object_field(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    const std::size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) {
        return "";
    }
    const std::size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) {
        return "";
    }
    std::size_t pos = skip_ws(json, colon + 1);
    if (pos >= json.size() || json[pos] != '{') {
        return "";
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
                return json.substr(start, pos - start + 1);
            }
        }
    }
    return "";
}

struct WorkerArchiveInput {
    std::wstring archive_path;
    std::wstring format_hint;
    std::wstring open_mode;
    std::vector<std::wstring> part_paths;
    std::vector<std::wstring> canonical_names;
    std::vector<int> volume_numbers;
    std::string validation_error;
    std::vector<sunpack::sevenzip::ExtractInputRange> ranges;
    std::vector<sunpack::sevenzip::ExtractPatchOperation> patches;
};

sunpack::sevenzip::PasswordTestResult run_password_candidate_probe(
    const std::wstring& dll_path,
    const WorkerArchiveInput& archive_input,
    const std::vector<std::wstring>& candidates
) {
    using namespace sunpack::sevenzip;
    std::vector<const wchar_t*> password_ptrs;
    password_ptrs.reserve(candidates.size());
    for (const auto& password : candidates) {
        password_ptrs.push_back(password.c_str());
    }
    if (!archive_input.ranges.empty()) {
        return test_passwords_with_ranges(
            dll_path,
            archive_input.archive_path,
            archive_input.ranges,
            archive_input.format_hint,
            password_ptrs.data(),
            static_cast<int>(password_ptrs.size()));
    }
    return test_passwords_with_parts(
        dll_path,
        archive_input.archive_path,
        archive_input.part_paths,
        password_ptrs.data(),
        static_cast<int>(password_ptrs.size()),
        archive_input.canonical_names);
}

sunpack::sevenzip::ExtractArchiveResult password_candidate_failure(
    const WorkerArchiveInput& archive_input,
    const sunpack::sevenzip::PasswordTestResult& probe,
    std::size_t candidate_count
) {
    using namespace sunpack::sevenzip;
    ExtractArchiveResult result;
    result.status = probe.status;
    result.backend_available = probe.backend_available;
    result.archive_type = probe.archive_type.empty()
        ? archive_type_for_path(archive_input.archive_path)
        : probe.archive_type;
    result.password_candidate_batch = true;
    result.password_candidate_count = static_cast<unsigned int>(candidate_count);
    result.password_attempts = probe.attempts;
    result.matched_index = probe.matched_index;
    result.password_candidates_all_rejected = probe.status == PasswordTestStatus::WrongPassword;
    result.encrypted = probe.status == PasswordTestStatus::WrongPassword;
    result.wrong_password = probe.status == PasswordTestStatus::WrongPassword;
    result.password_rejected = result.wrong_password;
    result.damaged = probe.status == PasswordTestStatus::Damaged;
    result.missing_volume = probe.status == PasswordTestStatus::NeedsVolumeOrTailDamaged;
    result.unsupported_method = probe.status == PasswordTestStatus::Unsupported;
    result.failure_stage = "password_probe";
    switch (probe.status) {
    case PasswordTestStatus::WrongPassword:
        result.failure_kind = "wrong_password";
        result.operation_result = kOpWrongPassword;
        break;
    case PasswordTestStatus::Damaged:
        result.failure_kind = "data_error";
        result.operation_result = kOpDataError;
        break;
    case PasswordTestStatus::NeedsVolumeOrTailDamaged:
        result.failure_kind = "missing_volume_or_tail";
        break;
    case PasswordTestStatus::Unsupported:
        result.failure_kind = "unsupported_method";
        break;
    case PasswordTestStatus::BackendUnavailable:
        result.failure_kind = "backend_unavailable";
        break;
    default:
        result.failure_kind = "password_probe";
        break;
    }
    result.message = probe.message;
    return result;
}

std::vector<unsigned char> base64_decode(const std::string& text) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> out;
    int value = 0;
    int bits = -8;
    for (const unsigned char ch : text) {
        if (ch == '=') {
            break;
        }
        const auto index = alphabet.find(static_cast<char>(ch));
        if (index == std::string::npos) {
            continue;
        }
        value = (value << 6) + static_cast<int>(index);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<unsigned char>((value >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

std::vector<sunpack::sevenzip::ExtractInputRange> parse_input_ranges(const std::string& request, const std::string& archive_path) {
    using sunpack::sevenzip::ExtractInputRange;
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

std::vector<sunpack::sevenzip::ExtractInputRange> parse_ranges_from_objects(
    const std::vector<std::string>& objects,
    const std::string& default_path
) {
    using sunpack::sevenzip::ExtractInputRange;
    std::vector<ExtractInputRange> ranges;
    for (const auto& object_json : objects) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        const bool has_start = json_uint_field_in_object(object_json, "start", &start) || json_uint_field_in_object(object_json, "start_offset", &start);
        const bool has_end = json_uint_field_in_object(object_json, "end", &end) || json_uint_field_in_object(object_json, "end_offset", &end);
        const std::string path = json_string_field(object_json, "path", default_path);
        if (path.empty() && default_path.empty()) {
            continue;
        }
        ExtractInputRange range;
        range.path = utf8_to_wide(path.empty() ? default_path : path);
        range.start = has_start ? start : 0;
        range.end = end;
        range.has_end = has_end;
        ranges.push_back(range);
    }
    return ranges;
}

std::vector<sunpack::sevenzip::ExtractPatchOperation> parse_patch_operations_from_state(const std::string& request);

WorkerArchiveInput parse_archive_input_descriptor(
    const std::string& request,
    const std::wstring& fallback_archive_path,
    const std::wstring& fallback_format_hint,
    const std::vector<std::wstring>& fallback_part_paths
) {
    WorkerArchiveInput input;
    input.archive_path = fallback_archive_path;
    input.format_hint = fallback_format_hint;
    input.open_mode = L"file";
    input.part_paths = fallback_part_paths;

    std::string descriptor = json_object_field(request, "archive_input");
    const std::string state = json_object_field(request, "archive_state");
    if (!state.empty()) {
        const std::string state_source = json_object_field(state, "source");
        if (!state_source.empty()) {
            descriptor = state_source;
        }
    }
    if (descriptor.empty()) {
        input.ranges = parse_input_ranges(request, json_string_field(request, "archive_path", ""));
        if (!input.ranges.empty()) {
            input.open_mode = utf8_to_wide(json_string_field(request, "kind", "concat_ranges"));
        }
        input.patches = parse_patch_operations_from_state(request);
        return input;
    }

    const std::string entry_path = json_string_field(descriptor, "entry_path", json_string_field(request, "archive_path", ""));
    if (!entry_path.empty()) {
        input.archive_path = utf8_to_wide(entry_path);
    }
    const std::string mode = json_string_field(descriptor, "open_mode", json_string_field(descriptor, "kind", "file"));
    input.open_mode = utf8_to_wide(mode.empty() ? "file" : mode);
    const std::string format_hint = json_string_field(descriptor, "format_hint", json_string_field(request, "format_hint", ""));
    input.format_hint = utf8_to_wide(format_hint);

    struct ParsedPart { int number; std::wstring path; std::wstring canonical_name; };
    std::vector<ParsedPart> structured_parts;
    std::vector<std::wstring> parts;
    for (const auto& object_json : json_object_array_field(descriptor, "parts")) {
        const std::string path = json_string_field(object_json, "path", "");
        if (!path.empty()) {
            parts.push_back(utf8_to_wide(path));
            unsigned long long number = 0;
            const std::string canonical_name = json_string_field(object_json, "canonical_name", "");
            if (mode == "native_volumes" || mode == "sfx_with_volumes") {
                if (!json_uint_field_in_object(object_json, "volume_number", &number) || number == 0 || canonical_name.empty()) {
                    input.validation_error = "structured volume part requires volume_number and canonical_name";
                } else {
                    structured_parts.push_back({static_cast<int>(number), utf8_to_wide(path), utf8_to_wide(canonical_name)});
                }
            }
        }
    }
    if (mode == "native_volumes" || mode == "sfx_with_volumes") {
        std::sort(structured_parts.begin(), structured_parts.end(), [](const ParsedPart& left, const ParsedPart& right) {
            return left.number < right.number;
        });
        parts.clear();
        for (std::size_t index = 0; index < structured_parts.size(); ++index) {
            if (structured_parts[index].number != static_cast<int>(index + 1)) {
                input.validation_error = "structured volume sequence must be contiguous and start at 1";
                break;
            }
            parts.push_back(structured_parts[index].path);
            input.canonical_names.push_back(structured_parts[index].canonical_name);
            input.volume_numbers.push_back(structured_parts[index].number);
        }
        if (parts.empty()) input.validation_error = "structured volume descriptor has no parts";
    }
    if (!parts.empty()) {
        input.part_paths = parts;
    }

    if (mode == "file_range") {
        input.ranges = parse_ranges_from_objects(json_object_array_field(descriptor, "parts"), entry_path);
        if (input.ranges.empty()) {
            const std::string segment = json_object_field(descriptor, "segment");
            unsigned long long start = 0;
            unsigned long long end = 0;
            const bool has_start = json_uint_field_in_object(segment, "start", &start) || json_uint_field_in_object(segment, "start_offset", &start);
            const bool has_end = json_uint_field_in_object(segment, "end", &end) || json_uint_field_in_object(segment, "end_offset", &end);
            sunpack::sevenzip::ExtractInputRange range;
            range.path = utf8_to_wide(entry_path.empty() ? json_string_field(request, "archive_path", "") : entry_path);
            range.start = has_start ? start : 0;
            range.end = end;
            range.has_end = has_end;
            input.ranges.push_back(range);
        }
    } else if (mode == "concat_ranges") {
        input.ranges = parse_ranges_from_objects(json_object_array_field(descriptor, "ranges"), entry_path);
        if (input.ranges.empty()) {
            input.ranges = parse_ranges_from_objects(json_object_array_field(descriptor, "parts"), entry_path);
        }
    }
    input.patches = parse_patch_operations_from_state(request);
    return input;
}

std::vector<sunpack::sevenzip::ExtractPatchOperation> parse_patch_operations_from_state(const std::string& request) {
    using sunpack::sevenzip::ExtractPatchOperation;
    std::vector<ExtractPatchOperation> operations;
    const std::string state = json_object_field(request, "archive_state");
    if (state.empty()) {
        return operations;
    }
    for (const auto& patch_json : json_object_array_field(state, "patches")) {
        for (const auto& operation_json : json_object_array_field(patch_json, "operations")) {
            ExtractPatchOperation operation;
            operation.op = utf8_to_wide(json_string_field(operation_json, "op", ""));
            operation.target = utf8_to_wide(json_string_field(operation_json, "target", "logical"));
            unsigned long long offset = 0;
            if (json_uint_field_in_object(operation_json, "offset", &offset)) {
                operation.offset = offset;
            }
            unsigned long long size = 0;
            if (json_uint_field_in_object(operation_json, "size", &size)) {
                operation.size = size;
                operation.has_size = true;
            }
            operation.data = base64_decode(json_string_field(operation_json, "data_b64", ""));
            if (!operation.op.empty()) {
                operations.push_back(std::move(operation));
            }
        }
    }
    return operations;
}

std::mutex g_output_mutex;

void print_json_line(const std::string& json) {
    std::lock_guard<std::mutex> lock(g_output_mutex);
    std::cout << json << "\n";
    std::cout.flush();
}

std::string status_to_string(sunpack::sevenzip::PasswordTestStatus status) {
    return sunpack::sevenzip::status_name(status);
}

std::string hresult_hex(int value) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0')
           << static_cast<unsigned int>(value);
    return stream.str();
}

std::string bytes_hex(const std::vector<unsigned char>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const unsigned char value : bytes) {
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 0x0f]);
    }
    return result;
}

std::string input_trace_json(const sunpack::sevenzip::ExtractInputTrace& trace) {
    return std::string("{") +
        "\"mode\":\"" + json_escape(wide_to_utf8(trace.mode)) +
        "\",\"virtual_size\":" + std::to_string(trace.virtual_size) +
        ",\"position\":" + std::to_string(trace.position) +
        ",\"max_position_seen\":" + std::to_string(trace.max_position_seen) +
        ",\"total_bytes_returned\":" + std::to_string(trace.total_bytes_returned) +
        ",\"read_error\":" + std::string(trace.read_error ? "true" : "false") +
        ",\"last_hresult\":" + std::to_string(trace.last_hresult) +
        ",\"last_hresult_hex\":\"" + hresult_hex(trace.last_hresult) +
        "\",\"last_win32_error\":" + std::to_string(trace.last_win32_error) +
        ",\"last_read\":{\"virtual_offset\":" + std::to_string(trace.last_read_virtual_offset) +
        ",\"source_path\":\"" + json_escape(wide_to_utf8(trace.last_source_path)) +
        "\",\"source_offset\":" + std::to_string(trace.last_read_source_offset) +
        ",\"range_index\":" + std::to_string(trace.last_range_index) +
        ",\"requested\":" + std::to_string(trace.last_read_requested) +
        ",\"returned\":" + std::to_string(trace.last_read_returned) +
        "},\"last_seek\":{\"origin\":" + std::to_string(trace.last_seek_origin) +
        ",\"offset\":" + std::to_string(trace.last_seek_offset) +
        ",\"new_position\":" + std::to_string(trace.last_seek_new_position) +
        "}}";
}

std::string output_item_traces_json(const std::vector<sunpack::sevenzip::ExtractOutputItemTrace>& items) {
    std::string out = "[";
    for (std::size_t index = 0; index < items.size(); ++index) {
        const auto& item = items[index];
        if (index) {
            out += ",";
        }
        out += "{\"index\":" + std::to_string(item.index) +
            ",\"path\":\"" + json_escape(wide_to_utf8(item.path)) +
            "\",\"output_path\":\"" + json_escape(wide_to_utf8(item.output_path)) +
            "\",\"is_dir\":" + std::string(item.is_dir ? "true" : "false") +
            ",\"encrypted\":" + std::string(item.encrypted ? "true" : "false") +
            ",\"bytes_written\":" + std::to_string(item.bytes_written) +
            ",\"expected_size\":" + std::to_string(item.expected_size) +
            ",\"has_expected_size\":" + std::string(item.has_expected_size ? "true" : "false") +
            ",\"source_crc32\":" + std::to_string(item.source_crc32) +
            ",\"has_source_crc32\":" + std::string(item.has_source_crc32 ? "true" : "false") +
            ",\"output_crc32\":" + std::to_string(item.output_crc32) +
            ",\"has_output_crc32\":" + std::string(item.has_output_crc32 ? "true" : "false") +
            ",\"crc_verified\":" + std::string(item.crc_verified ? "true" : "false") +
            ",\"operation_result\":" + std::to_string(item.operation_result) +
            ",\"operation_result_name\":\"" + json_escape(sunpack::sevenzip::operation_result_name(item.operation_result)) +
            "\",\"hresult\":" + std::to_string(item.hresult) +
            ",\"hresult_hex\":\"" + hresult_hex(item.hresult) +
            "\",\"win32_error\":" + std::to_string(item.win32_error) +
            ",\"done\":" + std::string(item.done ? "true" : "false") +
            ",\"failed\":" + std::string(item.failed ? "true" : "false") +
            "}";
    }
    out += "]";
    return out;
}

std::string output_trace_json(const sunpack::sevenzip::ExtractOutputTrace& trace) {
    return std::string("{") +
        "\"total_bytes_written\":" + std::to_string(trace.total_bytes_written) +
        ",\"current_item_index\":" + std::to_string(trace.current_item_index) +
        ",\"current_item_path\":\"" + json_escape(wide_to_utf8(trace.current_item_path)) +
        "\",\"current_item_bytes_written\":" + std::to_string(trace.current_item_bytes_written) +
        ",\"last_write_size\":" + std::to_string(trace.last_write_size) +
        ",\"last_hresult\":" + std::to_string(trace.last_hresult) +
        ",\"last_hresult_hex\":\"" + hresult_hex(trace.last_hresult) +
        "\",\"last_win32_error\":" + std::to_string(trace.last_win32_error) +
        ",\"items\":" + output_item_traces_json(trace.items) +
        "}";
}

std::string verified_manifest_json(const sunpack::sevenzip::ExtractArchiveResult& result, bool validated) {
    std::string rows = "[";
    rows.reserve(result.output_trace.items.size() * 96);
    bool first = true;
    unsigned int file_count = 0;
    unsigned long long total_size = 0;
    bool identity_paths = true;
    std::unordered_set<std::wstring> directories;
    for (const auto& item : result.output_trace.items) {
        const std::filesystem::path output_path(item.output_path);
        if (item.is_dir) {
            if (!item.output_path.empty()) {
                directories.insert(output_path.lexically_normal().generic_wstring());
            }
            continue;
        }
        for (auto parent = output_path.parent_path(); !parent.empty(); parent = parent.parent_path()) {
            directories.insert(parent.lexically_normal().generic_wstring());
        }
        if (!first) {
            rows += ",";
        }
        first = false;
        ++file_count;
        total_size += item.bytes_written;
        const bool identity_path =
            std::filesystem::path(item.path).lexically_normal().generic_wstring() == output_path.lexically_normal().generic_wstring();
        identity_paths = identity_paths && identity_path;
        rows += "[" + std::to_string(item.index) +
            ",\"" + json_escape(wide_to_utf8(item.path)) +
            "\",\"" + (identity_path ? std::string() : json_escape(wide_to_utf8(item.output_path))) +
            "\"," + std::to_string(item.has_expected_size ? item.expected_size : item.bytes_written) +
            "," + std::to_string(item.bytes_written) +
            "," + std::string(item.has_source_crc32 ? "1" : "0") +
            "," + std::to_string(item.source_crc32) +
            "," + std::string(item.has_output_crc32 ? "1" : "0") +
            "," + std::to_string(item.output_crc32) +
            "," + std::string(item.crc_verified ? "1" : "0") +
            "," + std::string(item.done ? "1" : item.failed ? "2" : "0") +
            "," + std::string(item.has_mtime_ns ? "1" : "0") +
            "," + std::to_string(item.mtime_ns) +
            ",\"" + bytes_hex(item.magic) + "\"]";
    }
    rows += "]";
    const bool inventory_complete = validated && result.output_inventory_complete && file_count == result.files_written;
    return std::string("{") +
        "\"version\":3,\"source\":\"sevenzip_worker_extract\"" +
        ",\"validated\":" + std::string(validated ? "true" : "false") +
        ",\"item_count\":" + std::to_string(result.item_count) +
        ",\"file_count\":" + std::to_string(file_count) +
        ",\"inventory\":[" + std::string(inventory_complete ? "1" : "0") +
        "," + std::to_string(file_count) +
        "," + std::to_string(directories.size()) +
        "," + std::to_string(total_size) +
        "," + std::string(identity_paths ? "1" : "0") + "]" +
        ",\"rows\":" + rows + "}";
}

std::string handler_attempts_json(const std::vector<sunpack::sevenzip::ExtractHandlerAttempt>& attempts) {
    std::string out = "[";
    for (std::size_t index = 0; index < attempts.size(); ++index) {
        const auto& attempt = attempts[index];
        if (index) {
            out += ",";
        }
        out += "{\"format\":\"" + json_escape(wide_to_utf8(attempt.format)) +
            "\",\"created\":" + std::string(attempt.created ? "true" : "false") +
            ",\"opened\":" + std::string(attempt.opened ? "true" : "false") +
            ",\"create_hresult\":" + std::to_string(attempt.create_hresult) +
            ",\"create_hresult_hex\":\"" + hresult_hex(attempt.create_hresult) +
            "\",\"open_hresult\":" + std::to_string(attempt.open_hresult) +
            ",\"open_hresult_hex\":\"" + hresult_hex(attempt.open_hresult) + "\"}";
    }
    out += "]";
    return out;
}

std::string failed_item_json(const sunpack::sevenzip::ExtractArchiveResult& result) {
    return std::string("{") +
        "\"index\":" + std::to_string(result.failed_item_index) +
        ",\"path\":\"" + json_escape(wide_to_utf8(result.failed_item)) +
        "\",\"bytes_written\":" + std::to_string(result.failed_item_bytes_written) +
        ",\"operation_result\":" + std::to_string(result.operation_result) +
        ",\"operation_result_name\":\"" + json_escape(sunpack::sevenzip::operation_result_name(result.operation_result)) +
        "\"}";
}

std::string diagnostics_json(const sunpack::sevenzip::ExtractArchiveResult& result) {
    return std::string("{") +
        "\"failure_stage\":\"" + json_escape(result.failure_stage) +
        "\",\"failure_kind\":\"" + json_escape(result.failure_kind) +
        "\",\"hresult\":" + std::to_string(result.hresult) +
        ",\"hresult_hex\":\"" + hresult_hex(result.hresult) +
        "\",\"operation_result\":" + std::to_string(result.operation_result) +
        ",\"operation_result_name\":\"" + json_escape(sunpack::sevenzip::operation_result_name(result.operation_result)) +
        "\",\"missing_volume_suspected\":" + std::string(result.missing_volume_suspected ? "true" : "false") +
        ",\"missing_volume_evidence\":\"" + json_escape(result.missing_volume_evidence) +
        "\",\"missing_volume_name\":\"" + json_escape(wide_to_utf8(result.missing_volume_name)) +
        "\",\"password_candidate_batch\":" + std::string(result.password_candidate_batch ? "true" : "false") +
        ",\"password_candidates_all_rejected\":" + std::string(result.password_candidates_all_rejected ? "true" : "false") +
        ",\"password_candidate_count\":" + std::to_string(result.password_candidate_count) +
        ",\"password_attempts\":" + std::to_string(result.password_attempts) +
        ",\"matched_index\":" + std::to_string(result.matched_index) +
        ",\"handler_attempts\":" + handler_attempts_json(result.handler_attempts) +
        ",\"input_trace\":" + input_trace_json(result.input_trace) +
        ",\"output_trace\":" + output_trace_json(result.output_trace) +
        ",\"failed_item\":" + failed_item_json(result) +
        "}";
}

}  // namespace

int run_request(
    const std::string& request,
    const std::shared_ptr<sunpack::sevenzip::AsyncFileWriter>& shared_writer = nullptr,
    const std::shared_ptr<std::atomic<bool>>& cancel_token = nullptr,
    std::uint64_t* actual_output_bytes = nullptr
) {
    using namespace sunpack::sevenzip;

    const std::string job_id = json_string_field(request, "job_id", "");
    const std::string command = json_string_field(request, "worker_command", "");
    if (command == "shutdown") {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"ok\",\"native_status\":\"ok\",\"message\":\"worker shutdown\"}");
        return 0;
    }
    if (cancel_token && cancel_token->load(std::memory_order_acquire)) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"failed\",\"native_status\":\"cancelled\","
            "\"failure_stage\":\"native_cancel\",\"failure_kind\":\"cancelled\","
            "\"message\":\"native job was cancelled before extraction started\"}");
        return -101;
    }

    const std::wstring dll_path = utf8_to_wide(json_string_field(request, "seven_zip_dll_path", "tools\\7z.dll"));
    const std::wstring archive_path = utf8_to_wide(json_string_field(request, "archive_path", ""));
    const std::wstring output_dir = utf8_to_wide(json_string_field(request, "output_dir", ""));
    const std::wstring password = utf8_to_wide(json_string_field(request, "password", ""));
    const std::wstring format_hint = utf8_to_wide(json_string_field(request, "format_hint", ""));
    const std::wstring codepage = utf8_to_wide(json_string_field(request, "codepage", ""));
    const bool dry_run = json_bool_field(request, "dry_run", false);
    unsigned long long job_buffer_budget = 0;
    json_uint_field_in_object(request, "job_buffer_budget_bytes", &job_buffer_budget);

    std::vector<std::wstring> password_candidates;
    for (const auto& candidate : json_string_array_field(request, "password_candidates")) {
        password_candidates.push_back(utf8_to_wide(candidate));
    }

    std::vector<std::wstring> part_paths;
    for (const auto& part : json_string_array_field(request, "part_paths")) {
        part_paths.push_back(utf8_to_wide(part));
    }
    std::vector<std::wstring> decoded_names;
    for (const auto& name : json_string_array_field(request, "decoded_names")) {
        decoded_names.push_back(utf8_to_wide(name));
    }
    if (!codepage.empty() && decoded_names.empty()) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"error\",\"category\":\"invalid_request\","
            "\"failure_stage\":\"filename_encoding\",\"failure_kind\":\"decoded_names_required\","
            "\"message\":\"decoded_names is required when codepage is set\"}");
        return 2;
    }

    if (archive_path.empty() || (!dry_run && output_dir.empty())) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"error\",\"category\":\"invalid_request\",\"message\":\"archive_path is required; output_dir is required unless dry_run is true\"}");
        return 2;
    }

    auto last_progress_emit = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    unsigned int coalesced_progress_events = 0;
    auto progress_mutex = std::make_shared<std::mutex>();
    auto progress = [job_id, last_progress_emit, coalesced_progress_events, progress_mutex](const ExtractProgressEvent& event) mutable {
            std::lock_guard<std::mutex> lock(*progress_mutex);
            const auto now = std::chrono::steady_clock::now();
            const bool failure = event.event == "item_failed";
            const bool boundary = event.event == "total" ||
                (event.event == "item_start" && event.item_index == 0) ||
                (event.event == "item_done" && event.item_index % 128 == 0);
            const bool interval_elapsed = now - last_progress_emit >= std::chrono::milliseconds(100);
            if (!failure && !boundary && !interval_elapsed) {
                ++coalesced_progress_events;
                return;
            }
            print_json_line(
                "{\"type\":\"progress\",\"job_id\":\"" + json_escape(job_id) +
                "\",\"event\":\"" + json_escape(event.event) +
                "\",\"completed_bytes\":" + std::to_string(event.completed_bytes) +
                ",\"total_bytes\":" + std::to_string(event.total_bytes) +
                ",\"item_index\":" + std::to_string(event.item_index) +
                ",\"item_path\":\"" + json_escape(wide_to_utf8(event.item_path)) +
                "\",\"coalesced_events\":" + std::to_string(coalesced_progress_events) + "}");
            last_progress_emit = now;
            coalesced_progress_events = 0;
    };

    const auto archive_input = parse_archive_input_descriptor(request, archive_path, format_hint, part_paths);
    if (!archive_input.validation_error.empty()) {
        print_json_line(
            "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"status\":\"error\",\"category\":\"invalid_request\",\"message\":\"" +
            json_escape(archive_input.validation_error) + "\"}");
        return 2;
    }
    auto extract_with_password = [&](const std::wstring& selected_password) {
        return !archive_input.patches.empty()
            ? extract_archive_with_patches(dll_path, archive_input.archive_path, archive_input.part_paths, archive_input.ranges, archive_input.patches, archive_input.format_hint, selected_password, output_dir, codepage, decoded_names, progress, dry_run, shared_writer, static_cast<std::size_t>(job_buffer_budget), cancel_token)
            : archive_input.ranges.empty()
            ? extract_archive_with_parts(dll_path, archive_input.archive_path, archive_input.part_paths, archive_input.format_hint, selected_password, output_dir, codepage, decoded_names, progress, dry_run, archive_input.canonical_names, shared_writer, static_cast<std::size_t>(job_buffer_budget), cancel_token)
            : extract_archive_with_ranges(dll_path, archive_input.archive_path, archive_input.ranges, archive_input.format_hint, selected_password, output_dir, codepage, decoded_names, progress, dry_run, shared_writer, static_cast<std::size_t>(job_buffer_budget), cancel_token);
    };

    ExtractArchiveResult result;
    if (password_candidates.empty()) {
        result = extract_with_password(password);
    } else if (!archive_input.patches.empty()) {
        result.status = PasswordTestStatus::Error;
        result.failure_stage = "password_probe";
        result.failure_kind = "patched_input_candidates_unsupported";
        result.message = "password candidate batches are not supported for patched input";
    } else {
        const auto probe = run_password_candidate_probe(dll_path, archive_input, password_candidates);
        if (probe.status != PasswordTestStatus::Ok ||
            probe.matched_index < 0 ||
            static_cast<std::size_t>(probe.matched_index) >= password_candidates.size()) {
            result = password_candidate_failure(archive_input, probe, password_candidates.size());
        } else {
            result = extract_with_password(password_candidates[probe.matched_index]);
            result.password_candidate_batch = true;
            result.password_candidate_count = static_cast<unsigned int>(password_candidates.size());
            result.password_attempts = probe.attempts;
            result.matched_index = probe.matched_index;
        }
    }

    const bool ok = result.status == PasswordTestStatus::Ok && result.command_ok;
    if (actual_output_bytes) {
        *actual_output_bytes = result.bytes_written;
    }
    const std::string failure_fields = ok ? "" :
        ",\"failure_stage\":\"" + json_escape(result.failure_stage) +
        "\",\"failure_kind\":\"" + json_escape(result.failure_kind) +
        "\",\"hresult\":" + std::to_string(result.hresult) +
        ",\"hresult_hex\":\"" + hresult_hex(result.hresult) + "\"";
    const std::string diagnostic_fields = (!ok || dry_run) ?
        ",\"diagnostics\":" + diagnostics_json(result) : "";
    print_json_line(
        "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
        "\",\"status\":\"" + std::string(ok ? "ok" : "failed") +
        "\",\"native_status\":\"" + json_escape(status_to_string(result.status)) +
        "\",\"operation_result\":" + std::to_string(result.operation_result) +
        ",\"operation_result_name\":\"" + json_escape(operation_result_name(result.operation_result)) +
        "\"" +
        ",\"encrypted\":" + std::string(result.encrypted ? "true" : "false") +
        ",\"damaged\":" + std::string(result.damaged ? "true" : "false") +
        ",\"checksum_error\":" + std::string(result.checksum_error ? "true" : "false") +
        ",\"missing_volume\":" + std::string(result.missing_volume ? "true" : "false") +
        ",\"missing_volume_suspected\":" + std::string(result.missing_volume_suspected ? "true" : "false") +
        ",\"missing_volume_evidence\":\"" + json_escape(result.missing_volume_evidence) +
        "\",\"missing_volume_name\":\"" + json_escape(wide_to_utf8(result.missing_volume_name)) +
        "\",\"wrong_password\":" + std::string(result.wrong_password ? "true" : "false") +
        ",\"password_rejected\":" + std::string(result.password_rejected ? "true" : "false") +
        ",\"password_crc_proven\":" + std::string(result.password_crc_proven ? "true" : "false") +
        ",\"password_crc_proven_items\":" + std::to_string(result.password_crc_proven_items) +
        ",\"password_candidate_batch\":" + std::string(result.password_candidate_batch ? "true" : "false") +
        ",\"password_candidates_all_rejected\":" + std::string(result.password_candidates_all_rejected ? "true" : "false") +
        ",\"password_candidate_count\":" + std::to_string(result.password_candidate_count) +
        ",\"password_attempts\":" + std::to_string(result.password_attempts) +
        ",\"matched_index\":" + std::to_string(result.matched_index) +
        ",\"unsupported_method\":" + std::string(result.unsupported_method ? "true" : "false") +
        ",\"item_count\":" + std::to_string(result.item_count) +
        ",\"files_written\":" + std::to_string(result.files_written) +
        ",\"dirs_written\":" + std::to_string(result.dirs_written) +
        ",\"bytes_written\":" + std::to_string(result.bytes_written) +
        ",\"dry_run\":" + std::string(dry_run ? "true" : "false") +
        ",\"open_mode\":\"" + json_escape(wide_to_utf8(archive_input.open_mode)) +
        "\",\"archive_type\":\"" + json_escape(wide_to_utf8(result.archive_type)) +
        "\",\"requested_codepage\":\"" + json_escape(wide_to_utf8(result.requested_codepage)) +
        "\",\"applied_codepage\":\"" + json_escape(wide_to_utf8(result.applied_codepage)) +
        "\",\"filename_decoder\":\"" + json_escape(wide_to_utf8(result.filename_decoder)) +
        "\",\"verified_manifest\":" + verified_manifest_json(result, ok && !dry_run) +
        ",\"failed_item\":\"" + json_escape(wide_to_utf8(result.failed_item)) +
        "\",\"message\":\"" + json_escape(result.message) + "\"" +
        failure_fields + diagnostic_fields + "}");
    return ok ? 0 : 1;
}

std::size_t configured_native_memory_budget() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_MEMORY_BUDGET_BYTES");
    if (value && *value) {
        char* end = nullptr;
        const unsigned long long configured = std::strtoull(value, &end, 10);
        if (end != value && *end == '\0' && configured > 0) {
            return static_cast<std::size_t>(configured);
        }
    }
#ifdef _WIN32
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status) && status.ullAvailPhys > 0) {
        const unsigned long long budget = status.ullAvailPhys * 7ULL / 10ULL;
        return static_cast<std::size_t>((std::min)(
            budget,
            static_cast<unsigned long long>((std::numeric_limits<std::size_t>::max)())));
    }
#endif
    return (std::numeric_limits<std::size_t>::max)();
}

bool configured_native_profile_cache_enabled() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_PROFILE_CACHE_ENABLED");
    if (!value || !*value) {
        return true;
    }
    return std::string(value) != "0" && std::string(value) != "false" && std::string(value) != "False";
}

std::string configured_native_profile_cache_path() {
    const char* value = std::getenv("SUNPACK_NATIVE_PROFILE_CACHE_PATH");
    if (value && *value) {
        return value;
    }
#ifdef _WIN32
    const char* local_app_data = std::getenv("LOCALAPPDATA");
    if (local_app_data && *local_app_data) {
        return (std::filesystem::path(local_app_data) / "Sunpack" / "native_profile_calibration.tsv").string();
    }
#endif
    return (std::filesystem::path(".sunpack_cache") / "native_profile_calibration.tsv").string();
}

std::size_t configured_native_queue_capacity() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_MAX_QUEUE_JOBS");
    if (!value || !*value) {
        return 0;
    }
    char* end = nullptr;
    const unsigned long long configured = std::strtoull(value, &end, 10);
    if (end == value || *end != '\0') {
        return 0;
    }
    return (std::min)(static_cast<std::size_t>(configured), std::size_t{1'000'000});
}

std::size_t configured_native_priority_aging_quantum() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_PRIORITY_AGING_QUANTUM");
    if (!value || !*value) {
        return 32;
    }
    char* end = nullptr;
    const unsigned long configured = std::strtoul(value, &end, 10);
    if (end == value || *end != '\0' || configured == 0) {
        return 32;
    }
    return (std::max)(1UL, (std::min)(configured, 100000UL));
}

bool configured_native_adaptive_enabled() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_ADAPTIVE_ENABLED");
    if (!value || !*value) {
        return true;
    }
    return std::string(value) != "0" && std::string(value) != "false" && std::string(value) != "False";
}

std::size_t configured_native_initial_active_jobs() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_INITIAL_ACTIVE_JOBS");
    if (!value || !*value) {
        return 0;
    }
    char* end = nullptr;
    const unsigned long configured = std::strtoul(value, &end, 10);
    if (end == value || *end != '\0' || configured == 0) {
        return 0;
    }
    return static_cast<std::size_t>(configured);
}

std::size_t configured_native_size(
    const char* name,
    std::size_t fallback,
    std::size_t minimum = 1,
    std::size_t maximum = (std::numeric_limits<std::size_t>::max)()
) noexcept {
    const char* value = std::getenv(name);
    if (!value || !*value) {
        return fallback;
    }
    char* end = nullptr;
    const unsigned long long configured = std::strtoull(value, &end, 10);
    if (end == value || *end != '\0') {
        return fallback;
    }
    const auto bounded = (std::min)(
        configured,
        static_cast<unsigned long long>(maximum));
    return (std::max)(minimum, static_cast<std::size_t>(bounded));
}

double configured_native_double(
    const char* name,
    double fallback,
    double minimum,
    double maximum
) noexcept {
    const char* value = std::getenv(name);
    if (!value || !*value) {
        return fallback;
    }
    char* end = nullptr;
    const double configured = std::strtod(value, &end);
    if (end == value || *end != '\0' || !std::isfinite(configured)) {
        return fallback;
    }
    return (std::max)(minimum, (std::min)(maximum, configured));
}

unsigned native_cpu_count() noexcept {
    const unsigned hardware = std::thread::hardware_concurrency();
    return hardware == 0 ? 2U : hardware;
}

unsigned long long native_total_memory_bytes() noexcept {
#ifdef _WIN32
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status) && status.ullTotalPhys > 0) {
        return status.ullTotalPhys;
    }
#endif
    return 0;
}

std::string native_worker_profile() {
    const char* configured = std::getenv("SUNPACK_NATIVE_WORKER_PROFILE");
    if (configured && *configured &&
        (std::string(configured) == "aggressive" || std::string(configured) == "conservative")) {
        return configured;
    }
    const unsigned long long total_memory = native_total_memory_bytes();
    return native_cpu_count() >= 12 && total_memory >= (24ULL << 30)
        ? "aggressive"
        : "conservative";
}

std::string requested_native_process_mode() {
    const char* configured = std::getenv("SUNPACK_NATIVE_PROCESS_MODE");
    return configured && std::string(configured) == "background" ? "background" : "normal";
}

bool apply_native_process_mode(const std::string& mode) noexcept {
#ifdef _WIN32
    return mode != "background" || SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN) != 0;
#else
    return mode != "background";
#endif
}

sunpack::sevenzip::NativeRuntimeConfig configured_native_runtime_config(
    std::size_t max_active_jobs
) noexcept {
    sunpack::sevenzip::NativeRuntimeConfig config;
    const bool aggressive = native_worker_profile() == "aggressive";
    config.adaptive_enabled = configured_native_adaptive_enabled();
    config.initial_active_jobs = configured_native_initial_active_jobs();
    if (config.initial_active_jobs == 0) {
        const bool background = requested_native_process_mode() == "background";
        config.initial_active_jobs = (std::min)(
            max_active_jobs,
            background ? (aggressive ? std::size_t{3} : std::size_t{2})
                       : (aggressive ? std::size_t{8} : std::size_t{4}));
    }
    config.throughput_window_size = configured_native_size(
        "SUNPACK_NATIVE_THROUGHPUT_WINDOW_SIZE", config.throughput_window_size, 4);
    config.throughput_regression_ratio = configured_native_double(
        "SUNPACK_NATIVE_THROUGHPUT_REGRESSION_RATIO",
        config.throughput_regression_ratio,
        0.01,
        1.0);
    config.scale_up_streak_required = configured_native_size(
        "SUNPACK_NATIVE_SCALE_UP_STREAK_REQUIRED", config.scale_up_streak_required);
    config.scale_down_streak_required = configured_native_size(
        "SUNPACK_NATIVE_SCALE_DOWN_STREAK_REQUIRED", config.scale_down_streak_required);
    config.cpu_scale_up_percent = configured_native_double(
        "SUNPACK_NATIVE_CPU_SCALE_UP_PERCENT", config.cpu_scale_up_percent, 0.0, 100.0);
    config.cpu_scale_down_percent = configured_native_double(
        "SUNPACK_NATIVE_CPU_SCALE_DOWN_PERCENT", config.cpu_scale_down_percent, 0.0, 100.0);
    config.medium_backlog_threshold = configured_native_size(
        "SUNPACK_NATIVE_MEDIUM_BACKLOG_THRESHOLD", config.medium_backlog_threshold);
    config.high_backlog_threshold = configured_native_size(
        "SUNPACK_NATIVE_HIGH_BACKLOG_THRESHOLD", config.high_backlog_threshold);
    config.medium_floor_jobs = configured_native_size(
        "SUNPACK_NATIVE_MEDIUM_FLOOR_JOBS",
        aggressive ? std::size_t{4} : std::size_t{2});
    config.high_floor_jobs = configured_native_size(
        "SUNPACK_NATIVE_HIGH_FLOOR_JOBS",
        aggressive ? std::size_t{6} : std::size_t{3});
    config.idle_decay_seconds = configured_native_double(
        "SUNPACK_NATIVE_WORKER_IDLE_DECAY_SECONDS",
        config.idle_decay_seconds,
        0.0,
        86400.0);
    config.profile_calibration_min_parallel = configured_native_size(
        "SUNPACK_NATIVE_PROFILE_MIN_PARALLEL", config.profile_calibration_min_parallel);
    config.memory_scale_down_available = configured_native_size(
        "SUNPACK_NATIVE_MEMORY_SCALE_DOWN_AVAILABLE_BYTES", config.memory_scale_down_available);
    config.memory_scale_up_available = configured_native_size(
        "SUNPACK_NATIVE_MEMORY_SCALE_UP_AVAILABLE_BYTES", config.memory_scale_up_available);
    config.profile_window_size = configured_native_size(
        "SUNPACK_NATIVE_PROFILE_WINDOW_SIZE", config.profile_window_size, 4);
    config.profile_calibration_max_delta = static_cast<int>(configured_native_size(
        "SUNPACK_NATIVE_PROFILE_MAX_DELTA",
        static_cast<std::size_t>(config.profile_calibration_max_delta),
        0,
        32));
    config.profile_regression_ratio = configured_native_double(
        "SUNPACK_NATIVE_PROFILE_REGRESSION_RATIO", config.profile_regression_ratio, 0.01, 1.0);
    config.profile_improvement_ratio = configured_native_double(
        "SUNPACK_NATIVE_PROFILE_IMPROVEMENT_RATIO", config.profile_improvement_ratio, 1.0, 100.0);
    return config;
}

class NativeJobExecutor final {
public:
    explicit NativeJobExecutor(std::size_t worker_count)
        : shared_writer_(make_shared_writer()),
          worker_count_((std::max)(std::size_t{1}, worker_count)),
          memory_budget_(configured_native_memory_budget()),
          queue_capacity_(configured_native_queue_capacity()),
          priority_aging_quantum_(configured_native_priority_aging_quantum()),
          profile_cache_path_(configured_native_profile_cache_path()),
          profile_cache_enabled_(configured_native_profile_cache_enabled()),
          runtime_controller_(
              worker_count_,
              memory_budget_,
              configured_native_runtime_config(worker_count_)) {
        if (profile_cache_enabled_) {
            const std::filesystem::path cache_path(profile_cache_path_);
            if (cache_path.has_parent_path()) {
                std::error_code error;
                std::filesystem::create_directories(cache_path.parent_path(), error);
            }
            runtime_controller_.load_profile_cache(profile_cache_path_);
        }
        workers_.reserve(worker_count_);
        for (std::size_t index = 0; index < worker_count_; ++index) {
            workers_.emplace_back([this] { worker_loop(); });
        }
        controller_thread_ = std::thread([this] { controller_loop(); });
    }

    ~NativeJobExecutor() { stop(); }

    NativeJobExecutor(const NativeJobExecutor&) = delete;
    NativeJobExecutor& operator=(const NativeJobExecutor&) = delete;

    std::future<int> submit(std::string request) {
        auto promise = std::make_shared<std::promise<int>>();
        auto future = promise->get_future();
        auto cancel_token = std::make_shared<std::atomic<bool>>(false);
        const std::string job_id = json_string_field(request, "job_id", "");
        JobMetadata metadata = metadata_from_request(request);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                promise->set_value(-100);
                return future;
            }
            const sunpack::sevenzip::NativeProfileAdjustment adjustment = runtime_controller_.profile_adjustment(
                metadata.profile_key);
            metadata.cpu_weight = adjusted_weight(metadata.cpu_weight, adjustment.cpu);
            metadata.memory_reserve = adjusted_memory(metadata.memory_reserve, adjustment.memory);
            if (memory_budget_ != 0 && metadata.memory_reserve > memory_budget_) {
                any_job_failed_ = true;
                promise->set_value(-1);
                print_json_line(
                    "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
                    "\",\"status\":\"failed\",\"native_status\":\"resource_limit\","
                    "\"failure_stage\":\"native_admission\",\"failure_kind\":\"memory_budget\","
                    "\"message\":\"job memory reservation exceeds native hard budget\"}");
                print_worker_event(job_id, "job_finished", metadata);
                return future;
            }
            if (queue_capacity_ != 0 && queue_.size() >= queue_capacity_) {
                any_job_failed_ = true;
                promise->set_value(-2);
                print_json_line(
                    "{\"type\":\"result\",\"job_id\":\"" + json_escape(job_id) +
                    "\",\"status\":\"failed\",\"native_status\":\"backpressure\","
                    "\"retryable\":true,\"failure_stage\":\"native_admission\","
                    "\"failure_kind\":\"queue_capacity\",\"message\":\"native job queue is full\"}");
                print_worker_event(job_id, "job_finished", metadata);
                return future;
            }
            FairnessState& fairness = fairness_[metadata.request_id];
            fairness.weight = metadata.fairness_weight;
            fairness.queued += 1;
            if (!job_id.empty()) {
                cancel_tokens_[job_id] = cancel_token;
            }
            queue_.push_back(Job{
                std::move(request),
                std::move(promise),
                std::move(cancel_token),
                metadata,
                next_sequence_++,
            });
            controller_recheck_ = true;
        }
        print_worker_event(job_id, "job_queued", metadata);
        condition_.notify_one();
        controller_condition_.notify_one();
        return future;
    }

    bool cancel(const std::string& job_id) noexcept {
        std::shared_ptr<std::atomic<bool>> token;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto found = cancel_tokens_.find(job_id);
            if (found == cancel_tokens_.end()) {
                return false;
            }
            token = found->second;
        }
        token->store(true, std::memory_order_release);
#ifdef _WIN32
        if (shared_writer_) {
            shared_writer_->wake_waiters();
        }
#endif
        condition_.notify_all();
        return true;
    }

    bool had_job_failure() const noexcept { return any_job_failed_; }

    void stop() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stopping_) {
                return;
            }
            stopping_ = true;
        }
        condition_.notify_all();
        controller_condition_.notify_all();
        if (controller_thread_.joinable()) {
            controller_thread_.join();
        }
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers_.clear();
        if (profile_cache_enabled_ && runtime_controller_.profile_adjustments_dirty()) {
            runtime_controller_.save_profile_cache(profile_cache_path_);
        }
#ifdef _WIN32
        if (shared_writer_) {
            shared_writer_->finish();
            shared_writer_.reset();
        }
#endif
    }

private:
    struct JobMetadata {
        int priority = 0;
        std::string request_id;
        std::size_t fairness_weight = 1;
        std::size_t cpu_weight = 1;
        std::size_t memory_reserve = 64U << 20;
        std::size_t dictionary_reserve = 0;
        bool solid_archive = false;
        std::uint64_t expected_output_bytes = 0;
        std::string profile_key;
    };

    struct Job {
        std::string request;
        std::shared_ptr<std::promise<int>> promise;
        std::shared_ptr<std::atomic<bool>> cancel_token;
        JobMetadata metadata;
        std::uint64_t sequence = 0;
    };

    struct FairnessState {
        std::uint64_t virtual_finish = 0;
        std::size_t weight = 1;
        std::size_t queued = 0;
        std::size_t active = 0;
    };

    static JobMetadata metadata_from_request(const std::string& request) noexcept {
        JobMetadata metadata;
        unsigned long long value = 0;
        if (json_uint_field_in_object(request, "native_priority", &value)) {
            metadata.priority = static_cast<int>((std::min)(value, 1000ULL));
        }
        metadata.request_id = json_string_field(request, "request_id", "");
        if (metadata.request_id.empty()) {
            metadata.request_id = json_string_field(request, "job_id", "");
        }
        if (json_uint_field_in_object(request, "native_fairness_weight", &value)) {
            metadata.fairness_weight = (std::max)(std::size_t{1}, static_cast<std::size_t>(
                (std::min)(value, 1024ULL)));
        }
        if (json_uint_field_in_object(request, "native_cpu_weight", &value)) {
            metadata.cpu_weight = (std::max)(std::size_t{1}, static_cast<std::size_t>(value));
        }
        if (json_uint_field_in_object(request, "native_memory_reserve_bytes", &value)) {
            metadata.memory_reserve = (std::max)(
                std::size_t{1}, static_cast<std::size_t>((std::min)(
                    value,
                    static_cast<unsigned long long>((std::numeric_limits<std::size_t>::max)()))));
        }
        if (json_uint_field_in_object(request, "native_dictionary_reserve_bytes", &value)) {
            metadata.dictionary_reserve = static_cast<std::size_t>((std::min)(
                value,
                static_cast<unsigned long long>((std::numeric_limits<std::size_t>::max)())));
            constexpr std::size_t decoder_scratch = 32U << 20;
            const std::size_t dictionary_memory = metadata.dictionary_reserve >
                    (std::numeric_limits<std::size_t>::max)() - decoder_scratch
                ? (std::numeric_limits<std::size_t>::max)()
                : metadata.dictionary_reserve + decoder_scratch;
            metadata.memory_reserve = (std::max)(metadata.memory_reserve, dictionary_memory);
        }
        metadata.solid_archive = json_bool_field(request, "native_solid_archive", false);
        if (json_uint_field_in_object(request, "native_expected_output_bytes", &value)) {
            metadata.expected_output_bytes = value;
        }
        metadata.profile_key = json_string_field(request, "native_profile_key", "");
        return metadata;
    }

    static std::size_t adjusted_weight(std::size_t value, int adjustment) noexcept {
        if (adjustment >= 0) {
            return value + static_cast<std::size_t>(adjustment);
        }
        const std::size_t delta = static_cast<std::size_t>(-adjustment);
        return value > delta ? value - delta : std::size_t{1};
    }

    static std::size_t adjusted_memory(std::size_t value, int adjustment) noexcept {
        if (adjustment <= 0) {
            return value;
        }
        const std::size_t increment = static_cast<std::size_t>(adjustment) * (32U << 20);
        if (value > (std::numeric_limits<std::size_t>::max)() - increment) {
            return (std::numeric_limits<std::size_t>::max)();
        }
        return value + increment;
    }

    bool can_admit_locked(const Job& job) const noexcept {
        if (!runtime_controller_.can_admit(
                active_jobs_,
                active_cpu_weight_,
                active_memory_,
                job.metadata.cpu_weight,
                job.metadata.memory_reserve)) {
            return false;
        }
        if (job.metadata.solid_archive && active_solid_jobs_ > 0) {
            return false;
        }
        return true;
    }

    std::size_t select_job_locked() const noexcept {
        std::size_t selected = queue_.size();
        const auto effective_priority = [this](const Job& job) {
            const std::uint64_t age = next_sequence_ >= job.sequence
                ? next_sequence_ - job.sequence : 0;
            const std::uint64_t aging = age / (std::max)(std::size_t{1}, priority_aging_quantum_);
            return static_cast<std::uint64_t>(job.metadata.priority) + (std::min)(aging, std::uint64_t{1000});
        };
        const auto virtual_finish = [this](const Job& job) {
            const auto found = fairness_.find(job.metadata.request_id);
            return found == fairness_.end() ? std::uint64_t{0} : found->second.virtual_finish;
        };
        for (std::size_t index = 0; index < queue_.size(); ++index) {
            const Job& candidate = queue_[index];
            if (!can_admit_locked(candidate)) {
                continue;
            }
            if (selected == queue_.size()) {
                selected = index;
                continue;
            }
            const Job& current = queue_[selected];
            const std::uint64_t candidate_priority = effective_priority(candidate);
            const std::uint64_t current_priority = effective_priority(current);
            if (candidate_priority > current_priority ||
                (candidate_priority == current_priority &&
                 (virtual_finish(candidate) < virtual_finish(current) ||
                  (virtual_finish(candidate) == virtual_finish(current) &&
                   candidate.sequence < current.sequence)))) {
                selected = index;
            }
        }
        return selected;
    }

    void print_worker_event(
        const std::string& job_id,
        const char* event,
        const JobMetadata& metadata,
        std::size_t active_jobs = 0,
        std::size_t active_cpu_weight = 0,
        std::size_t active_memory = 0
    ) const noexcept {
        if (job_id.empty()) {
            return;
        }
        print_json_line(
            "{\"type\":\"native_event\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"event\":\"" + event +
            "\",\"request_id\":\"" + json_escape(metadata.request_id) +
            "\",\"priority\":" + std::to_string(metadata.priority) +
            ",\"fairness_weight\":" + std::to_string(metadata.fairness_weight) +
            ",\"cpu_weight\":" + std::to_string(metadata.cpu_weight) +
            ",\"memory_reserve_bytes\":" + std::to_string(metadata.memory_reserve) +
             ",\"dictionary_reserve_bytes\":" + std::to_string(metadata.dictionary_reserve) +
            ",\"active_jobs\":" + std::to_string(active_jobs) +
             ",\"active_cpu_weight\":" + std::to_string(active_cpu_weight) +
             ",\"active_memory_bytes\":" + std::to_string(active_memory) +
            "}");
    }

    void print_active_event(
        const Job& job,
        const char* event,
        std::size_t active_jobs,
        std::size_t active_cpu_weight,
        std::size_t active_memory
    ) const noexcept {
        print_worker_event(
            json_string_field(job.request, "job_id", ""),
            event,
            job.metadata,
            active_jobs,
            active_cpu_weight,
            active_memory);
    }

    static void print_controller_event(
        const sunpack::sevenzip::NativeRuntimeSnapshot& snapshot,
        std::size_t queued_jobs,
        unsigned sampled_interval_ms,
        unsigned next_interval_ms
    ) noexcept {
        print_json_line(
            "{\"type\":\"native_controller\",\"queued_jobs\":" + std::to_string(queued_jobs) +
            ",\"active_limit\":" + std::to_string(snapshot.active_limit) +
            ",\"cpu_limit\":" + std::to_string(snapshot.cpu_limit) +
            ",\"memory_limit\":" + std::to_string(snapshot.memory_limit) +
            ",\"active_jobs\":" + std::to_string(snapshot.active_jobs) +
            ",\"sampled_interval_ms\":" + std::to_string(sampled_interval_ms) +
            ",\"next_sample_interval_ms\":" + std::to_string(next_interval_ms) + "}");
    }

#ifdef _WIN32
    static std::uint64_t filetime_ticks(const FILETIME& value) noexcept {
        ULARGE_INTEGER combined{};
        combined.LowPart = value.dwLowDateTime;
        combined.HighPart = value.dwHighDateTime;
        return combined.QuadPart;
    }
#endif

    static unsigned native_sample_interval_ms() noexcept {
        const char* value = std::getenv("SUNPACK_NATIVE_SAMPLE_INTERVAL_MS");
        if (!value || !*value) {
            return 500;
        }
        char* end = nullptr;
        const unsigned long configured = std::strtoul(value, &end, 10);
        if (end == value || *end != '\0' || configured == 0) {
            return 500;
        }
        return static_cast<unsigned>((std::max)(100UL, (std::min)(configured, 5000UL)));
    }

    sunpack::sevenzip::NativeRuntimeSample read_runtime_sample(double elapsed_seconds) noexcept {
        sunpack::sevenzip::NativeRuntimeSample sample;
#ifdef _WIN32
        MEMORYSTATUSEX memory_status{};
        memory_status.dwLength = sizeof(memory_status);
        if (GlobalMemoryStatusEx(&memory_status)) {
            sample.available_memory = static_cast<std::size_t>(
                (std::min)(
                    memory_status.ullAvailPhys,
                    static_cast<unsigned long long>((std::numeric_limits<std::size_t>::max)())));
        }

        FILETIME idle_time{}, kernel_time{}, user_time{};
        if (GetSystemTimes(&idle_time, &kernel_time, &user_time)) {
            const std::uint64_t idle = filetime_ticks(idle_time);
            const std::uint64_t kernel = filetime_ticks(kernel_time);
            const std::uint64_t user = filetime_ticks(user_time);
            if (has_system_cpu_sample_) {
                const std::uint64_t idle_delta = idle >= previous_idle_time_
                    ? idle - previous_idle_time_ : 0;
                const std::uint64_t total_delta =
                    (kernel >= previous_kernel_time_ ? kernel - previous_kernel_time_ : 0) +
                    (user >= previous_user_time_ ? user - previous_user_time_ : 0);
                if (total_delta > 0 && idle_delta <= total_delta) {
                    sample.cpu_percent = 100.0 * static_cast<double>(total_delta - idle_delta) /
                        static_cast<double>(total_delta);
                }
            }
            previous_idle_time_ = idle;
            previous_kernel_time_ = kernel;
            previous_user_time_ = user;
            has_system_cpu_sample_ = true;
        }
#endif
        return sample;
    }

    unsigned controller_interval_ms(
        const sunpack::sevenzip::NativeRuntimeSnapshot& snapshot,
        std::size_t queued_jobs
    ) const noexcept {
        const unsigned configured = native_sample_interval_ms();
        if (queued_jobs == 0) {
            return (std::min)(5000U, (std::max)(1000U, configured));
        }
        if (queued_jobs > (std::max)(std::size_t{1}, snapshot.active_limit) * 2 &&
            snapshot.active_limit < worker_count_) {
            return 100;
        }
        return (std::min)(configured, 250U);
    }

    void controller_loop() noexcept {
        constexpr unsigned minimum_sample_interval_ms = 100;
        unsigned next_interval_ms = native_sample_interval_ms();
        auto last_sample_at = std::chrono::steady_clock::now();
        while (true) {
            std::unique_lock<std::mutex> wait_lock(mutex_);
            controller_condition_.wait_for(
                wait_lock,
                std::chrono::milliseconds(next_interval_ms),
                [this] { return stopping_ || controller_recheck_; });
            if (stopping_) {
                break;
            }
            controller_recheck_ = false;
            wait_lock.unlock();
            const auto now = std::chrono::steady_clock::now();
            const double elapsed_seconds = std::chrono::duration<double>(now - last_sample_at).count();
            if (elapsed_seconds * 1000.0 < minimum_sample_interval_ms) {
                next_interval_ms = (std::max)(
                    1U,
                    minimum_sample_interval_ms - static_cast<unsigned>(elapsed_seconds * 1000.0));
                std::unique_lock<std::mutex> cooldown_lock(mutex_);
                if (controller_condition_.wait_for(
                        cooldown_lock,
                        std::chrono::milliseconds(next_interval_ms),
                        [this] { return stopping_; })) {
                    break;
                }
                continue;
            }
            const unsigned sampled_interval_ms = static_cast<unsigned>(elapsed_seconds * 1000.0);
            last_sample_at = now;
            const auto sample = read_runtime_sample(elapsed_seconds);
            bool changed = false;
            std::size_t queued_jobs = 0;
            sunpack::sevenzip::NativeRuntimeSnapshot snapshot;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stopping_) {
                    break;
                }
                queued_jobs = queue_.size();
                changed = runtime_controller_.observe(
                    sample,
                    queued_jobs,
                    active_jobs_,
                active_cpu_weight_,
                active_memory_,
                elapsed_seconds);
            snapshot = runtime_controller_.snapshot(
                    active_jobs_, active_cpu_weight_, active_memory_);
            }
            next_interval_ms = controller_interval_ms(snapshot, queued_jobs);
            if (changed) {
                print_controller_event(snapshot, queued_jobs, sampled_interval_ms, next_interval_ms);
                condition_.notify_all();
            }
        }
    }

    static std::shared_ptr<sunpack::sevenzip::AsyncFileWriter> make_shared_writer() {
#ifdef _WIN32
        return std::make_shared<sunpack::sevenzip::AsyncFileWriter>();
#else
        return nullptr;
#endif
    }

    void worker_loop() noexcept {
#ifdef _WIN32
        const HRESULT com_status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
#endif
        for (;;) {
            Job job;
            std::size_t admitted_jobs = 0;
            std::size_t admitted_cpu = 0;
            std::size_t admitted_memory = 0;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                condition_.wait(lock, [this] {
                    return select_job_locked() < queue_.size() || (stopping_ && queue_.empty());
                });
                const std::size_t selected = select_job_locked();
                if (selected == queue_.size()) {
                    if (stopping_ && queue_.empty()) {
                        break;
                    }
                    continue;
                }
                auto iterator = queue_.begin() + static_cast<std::ptrdiff_t>(selected);
                job = std::move(*iterator);
                queue_.erase(iterator);
                auto fairness_iterator = fairness_.find(job.metadata.request_id);
                if (fairness_iterator != fairness_.end()) {
                    FairnessState& fairness = fairness_iterator->second;
                    fairness.queued = fairness.queued > 0 ? fairness.queued - 1 : 0;
                    fairness.active += 1;
                    fairness.virtual_finish += (std::max)(
                        std::uint64_t{1},
                        std::uint64_t{1024} / (std::max)(std::size_t{1}, fairness.weight));
                }
                active_jobs_ += 1;
                active_cpu_weight_ += job.metadata.cpu_weight;
                active_memory_ += job.metadata.memory_reserve;
                if (job.metadata.solid_archive) {
                    active_solid_jobs_ += 1;
                }
                admitted_jobs = active_jobs_;
                admitted_cpu = active_cpu_weight_;
                admitted_memory = active_memory_;
            }
            print_active_event(job, "job_admitted", admitted_jobs, admitted_cpu, admitted_memory);
            print_active_event(job, "job_started", admitted_jobs, admitted_cpu, admitted_memory);
            const auto started_at = std::chrono::steady_clock::now();
            std::uint64_t actual_output_bytes = 0;
            int code = -100;
            try {
                code = run_request(job.request, shared_writer_, job.cancel_token, &actual_output_bytes);
            } catch (...) {
                code = -100;
            }
            const std::string job_id = json_string_field(job.request, "job_id", "");
            std::size_t remaining_jobs = 0;
            std::size_t remaining_cpu = 0;
            std::size_t remaining_memory = 0;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!job_id.empty()) {
                    cancel_tokens_.erase(job_id);
                }
                active_jobs_ = active_jobs_ > 0 ? active_jobs_ - 1 : 0;
                active_cpu_weight_ = active_cpu_weight_ >= job.metadata.cpu_weight
                    ? active_cpu_weight_ - job.metadata.cpu_weight : 0;
                active_memory_ = active_memory_ >= job.metadata.memory_reserve
                    ? active_memory_ - job.metadata.memory_reserve : 0;
                if (job.metadata.solid_archive && active_solid_jobs_ > 0) {
                    active_solid_jobs_ -= 1;
                }
                auto fairness_iterator = fairness_.find(job.metadata.request_id);
                if (fairness_iterator != fairness_.end()) {
                    FairnessState& fairness = fairness_iterator->second;
                    fairness.active = fairness.active > 0 ? fairness.active - 1 : 0;
                    if (fairness.queued == 0 && fairness.active == 0) {
                        fairness_.erase(fairness_iterator);
                    }
                }
                remaining_jobs = active_jobs_;
                remaining_cpu = active_cpu_weight_;
                remaining_memory = active_memory_;
                const double duration_seconds = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - started_at).count();
                runtime_controller_.record_job(
                    job.metadata.profile_key,
                    actual_output_bytes != 0 ? actual_output_bytes : job.metadata.expected_output_bytes,
                    duration_seconds,
                    admitted_jobs,
                    code == 0,
                    job.metadata.cpu_weight,
                    job.metadata.memory_reserve);
                any_job_failed_ = any_job_failed_ || code != 0;
                controller_recheck_ = true;
            }
            condition_.notify_all();
            controller_condition_.notify_one();
            print_active_event(job, "job_finished", remaining_jobs, remaining_cpu, remaining_memory);
            try {
                job.promise->set_value(code);
            } catch (...) {
            }
        }
#ifdef _WIN32
        if (com_status == S_OK || com_status == S_FALSE) {
            CoUninitialize();
        }
#endif
    }

    std::shared_ptr<sunpack::sevenzip::AsyncFileWriter> shared_writer_;
    std::vector<std::thread> workers_;
    std::thread controller_thread_;
    std::deque<Job> queue_;
    std::unordered_map<std::string, std::shared_ptr<std::atomic<bool>>> cancel_tokens_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::condition_variable controller_condition_;
    const std::size_t worker_count_;
    const std::size_t memory_budget_;
    const std::size_t queue_capacity_;
    const std::size_t priority_aging_quantum_;
    const std::string profile_cache_path_;
    const bool profile_cache_enabled_;
    sunpack::sevenzip::NativeRuntimeControl runtime_controller_;
    std::size_t active_jobs_ = 0;
    std::size_t active_cpu_weight_ = 0;
    std::size_t active_memory_ = 0;
    std::size_t active_solid_jobs_ = 0;
    std::uint64_t next_sequence_ = 0;
    std::unordered_map<std::string, FairnessState> fairness_;
    bool controller_recheck_ = false;
    bool any_job_failed_ = false;
    bool stopping_ = false;
#ifdef _WIN32
    bool has_system_cpu_sample_ = false;
    std::uint64_t previous_idle_time_ = 0;
    std::uint64_t previous_kernel_time_ = 0;
    std::uint64_t previous_user_time_ = 0;
#endif
};

std::size_t auto_native_worker_count() noexcept {
    const unsigned hardware = std::thread::hardware_concurrency();
    std::size_t detected = hardware == 0 ? std::size_t{2} : static_cast<std::size_t>(hardware);
    detected = (std::max)(std::size_t{1}, (std::min)(detected, std::size_t{32}));
#ifdef _WIN32
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status) && status.ullAvailPhys > 0) {
        constexpr unsigned long long memory_per_thread = 512ULL << 20;
        const std::size_t memory_slots = static_cast<std::size_t>(
            (std::max)(1ULL, status.ullAvailPhys / memory_per_thread));
        detected = (std::min)(detected, (std::max)(std::size_t{1}, memory_slots));
    }
#endif
    return detected;
}

std::size_t configured_native_worker_count() noexcept {
    const char* value = std::getenv("SUNPACK_NATIVE_WORKER_THREAD_CAPACITY");
    if (!value || !*value) {
        return auto_native_worker_count();
    }
    char* end = nullptr;
    const unsigned long configured = std::strtoul(value, &end, 10);
    if (end == value || *end != '\0') {
        return auto_native_worker_count();
    }
    if (configured == 0) {
        return auto_native_worker_count();
    }
    return (std::min)(static_cast<std::size_t>(configured), std::size_t{32});
}

int run_message(
    const std::string& request,
    NativeJobExecutor& executor
) {
    const std::string command = json_string_field(request, "worker_command", "");
    if (command == "cancel") {
        const std::string job_id = json_string_field(request, "job_id", "");
        const bool accepted = executor.cancel(job_id);
        print_json_line("{\"type\":\"cancel_ack\",\"job_id\":\"" + json_escape(job_id) +
            "\",\"accepted\":" + std::string(accepted ? "true" : "false") + "}");
        return accepted ? 0 : 1;
    }
    if (command == "shutdown") {
        return 0;
    }
    // Native owns queued work. Keeping one future per accepted message would
    // reintroduce a Python-independent caller-side queue in the worker main.
    executor.submit(request);
    return 0;
}

int main() {
    const std::string requested_process_mode = requested_native_process_mode();
    const bool process_mode_applied = apply_native_process_mode(requested_process_mode);
    const std::size_t worker_count = configured_native_worker_count();
    const auto runtime_config = configured_native_runtime_config(worker_count);
    NativeJobExecutor executor(worker_count);
    print_json_line(
        "{\"type\":\"worker_ready\",\"profile\":\"" + json_escape(native_worker_profile()) +
        "\",\"thread_capacity\":" + std::to_string(worker_count) +
        ",\"initial_active_limit\":" + std::to_string(runtime_config.initial_active_jobs) +
        ",\"process_mode\":\"" + requested_process_mode +
        "\",\"process_mode_applied\":" + (process_mode_applied ? "true" : "false") + "}");
    std::string line;
    while (std::getline(std::cin, line)) {
        line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) {
            return ch > 0x20;
        }));
        if (line.empty()) {
            continue;
        }
        const bool shutdown = json_string_field(line, "worker_command", "") == "shutdown";
        const int code = run_message(line, executor);
        if (shutdown) {
            executor.stop();
            return code;
        }
    }
    executor.stop();
    return executor.had_job_failure() ? 1 : 0;
}
