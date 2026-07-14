#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr char kRequestMagic[] = "SPK1";
constexpr char kStreamMagic[] = "SPS1";
constexpr std::size_t kMaxFieldBytes = 16u * 1024u * 1024u;

std::wstring executable_directory() {
    std::vector<wchar_t> buffer(32768);
    const DWORD size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    std::wstring path(buffer.data(), size);
    const auto slash = path.find_last_of(L"\\/");
    path.resize(slash == std::wstring::npos ? 0 : slash);
    CharLowerBuffW(path.data(), static_cast<DWORD>(path.size()));
    return path;
}

std::string utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring current_directory() {
    std::vector<wchar_t> buffer(32768);
    const DWORD size = GetCurrentDirectoryW(static_cast<DWORD>(buffer.size()), buffer.data());
    if (size == 0 || size >= buffer.size()) return {};
    return std::wstring(buffer.data(), size);
}

std::wstring wide_utf8(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                         static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) return {};
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
                        result.data(), size);
    return result;
}

std::wstring state_path() {
    const std::wstring directory = executable_directory();
    const std::string encoded = utf8(directory);
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    for (const unsigned char byte : encoded) {
        hash ^= byte;
        hash *= 0x100000001b3ULL;
    }
    std::array<wchar_t, 32768> local{};
    DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", local.data(), static_cast<DWORD>(local.size()));
    if (length == 0 || length >= local.size()) {
        length = GetTempPathW(static_cast<DWORD>(local.size()), local.data());
    }
    wchar_t suffix[64]{};
    swprintf_s(suffix, L"\\SunPack\\runtime-%016llx.state", static_cast<unsigned long long>(hash));
    return std::wstring(local.data(), length) + suffix;
}

bool parse_state(std::uint16_t& port, std::array<unsigned char, 32>& token) {
    std::ifstream stream(state_path());
    std::string port_text;
    std::string token_text;
    if (!std::getline(stream, port_text) || !std::getline(stream, token_text) || token_text.size() != 64) return false;
    try {
        const unsigned long value = std::stoul(port_text);
        if (value == 0 || value > 65535) return false;
        port = static_cast<std::uint16_t>(value);
        for (std::size_t index = 0; index < token.size(); ++index) {
            token[index] = static_cast<unsigned char>(std::stoul(token_text.substr(index * 2, 2), nullptr, 16));
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool send_all(SOCKET socket, const char* data, std::size_t size) {
    while (size != 0) {
        const int chunk = send(socket, data, static_cast<int>(std::min<std::size_t>(size, INT_MAX)), 0);
        if (chunk <= 0) return false;
        data += chunk;
        size -= static_cast<std::size_t>(chunk);
    }
    return true;
}

bool recv_all(SOCKET socket, char* data, std::size_t size) {
    while (size != 0) {
        const int chunk = recv(socket, data, static_cast<int>(std::min<std::size_t>(size, INT_MAX)), 0);
        if (chunk <= 0) return false;
        data += chunk;
        size -= static_cast<std::size_t>(chunk);
    }
    return true;
}

void append_u32(std::string& target, std::uint32_t value) {
    value = htonl(value);
    target.append(reinterpret_cast<const char*>(&value), sizeof(value));
}

std::uint32_t read_u32(const char* source) {
    std::uint32_t value = 0;
    memcpy(&value, source, sizeof(value));
    return ntohl(value);
}

void write_stream(DWORD handle_id, const std::string& text);

std::string read_input_line() {
    HANDLE handle = GetStdHandle(STD_INPUT_HANDLE);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) return {};
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode)) {
        std::array<wchar_t, 4096> buffer{};
        DWORD read = 0;
        if (!ReadConsoleW(handle, buffer.data(), static_cast<DWORD>(buffer.size() - 1), &read, nullptr)) return {};
        return utf8(std::wstring(buffer.data(), read));
    }
    std::array<char, 4096> buffer{};
    DWORD read = 0;
    if (!ReadFile(handle, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) return {};
    return std::string(buffer.data(), read);
}

bool request(const std::vector<std::wstring>& arguments, bool shutdown, int& exit_code,
             const std::wstring& request_cwd) {
    std::uint16_t port = 0;
    std::array<unsigned char, 32> token{};
    if (!parse_state(port, token)) return false;
    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == INVALID_SOCKET) return false;
    const DWORD timeout_ms = 2000;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        closesocket(socket);
        return false;
    }

    const std::string cwd = utf8(request_cwd);
    std::string wire(kRequestMagic, 4);
    wire.append(reinterpret_cast<const char*>(token.data()), token.size());
    DWORD console_mode = 0;
    const bool stdout_tty = GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &console_mode) != 0;
    DWORD input_mode = 0;
    const bool stdin_tty = GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &input_mode) != 0;
    append_u32(wire, (shutdown ? 1u : 0u) | (stdout_tty ? 2u : 0u) | (stdin_tty ? 4u : 0u));
    append_u32(wire, static_cast<std::uint32_t>(cwd.size()));
    append_u32(wire, static_cast<std::uint32_t>(arguments.size()));
    wire.append(cwd);
    for (const auto& argument : arguments) {
        const std::string encoded = utf8(argument);
        append_u32(wire, static_cast<std::uint32_t>(encoded.size()));
        wire.append(encoded);
    }
    if (!send_all(socket, wire.data(), wire.size())) {
        closesocket(socket);
        return false;
    }
    const DWORD no_timeout = 0;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&no_timeout), sizeof(no_timeout));
    std::array<char, 4> magic{};
    if (!recv_all(socket, magic.data(), magic.size()) || memcmp(magic.data(), kStreamMagic, 4) != 0) {
        closesocket(socket);
        return false;
    }
    while (true) {
        std::array<char, 5> header{};
        if (!recv_all(socket, header.data(), header.size())) break;
        const unsigned char kind = static_cast<unsigned char>(header[0]);
        const std::uint32_t size = read_u32(header.data() + 1);
        if (size > kMaxFieldBytes) break;
        std::string payload(size, '\0');
        if (!recv_all(socket, payload.data(), payload.size())) break;
        if (kind == 0) {
            if (size != 4) break;
            exit_code = static_cast<std::int32_t>(read_u32(payload.data()));
            closesocket(socket);
            return true;
        }
        if (kind == 1) write_stream(STD_OUTPUT_HANDLE, payload);
        else if (kind == 2) write_stream(STD_ERROR_HANDLE, payload);
        else if (kind == 3) {
            const std::string input = read_input_line();
            std::string response;
            append_u32(response, static_cast<std::uint32_t>(input.size()));
            response.append(input);
            if (!send_all(socket, response.data(), response.size())) break;
        }
    }
    closesocket(socket);
    return false;
}

std::wstring quote_argument(const std::wstring& value) {
    if (value.find_first_of(L" \t\"") == std::wstring::npos) return value;
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') {
            ++slashes;
        } else if (ch == L'\"') {
            result.append(slashes * 2 + 1, L'\\');
            result.push_back(ch);
            slashes = 0;
        } else {
            result.append(slashes, L'\\');
            slashes = 0;
            result.push_back(ch);
        }
    }
    result.append(slashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

bool spawn_runtime(const std::vector<std::wstring>& arguments, bool detached, DWORD* exit_code = nullptr,
                   const std::wstring& working_directory = {}) {
    const std::wstring runtime = executable_directory() + L"\\sunpack-runtime.exe";
    std::wstring command = quote_argument(runtime);
    for (const auto& argument : arguments) command += L" " + quote_argument(argument);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const DWORD flags = detached ? CREATE_NO_WINDOW : 0;
    const wchar_t* child_cwd = working_directory.empty() ? nullptr : working_directory.c_str();
    if (!CreateProcessW(runtime.c_str(), command.data(), nullptr, nullptr, detached ? FALSE : TRUE, flags, nullptr,
                        child_cwd,
                        &startup, &process)) return false;
    CloseHandle(process.hThread);
    if (detached) {
        CloseHandle(process.hProcess);
        return true;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hProcess);
    if (exit_code) *exit_code = code;
    return true;
}

void write_stream(DWORD handle_id, const std::string& text) {
    if (text.empty()) return;
    HANDLE handle = GetStdHandle(handle_id);
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode)) {
        const std::wstring wide = wide_utf8(text);
        DWORD written = 0;
        WriteConsoleW(handle, wide.data(), static_cast<DWORD>(wide.size()), &written, nullptr);
    } else {
        DWORD written = 0;
        WriteFile(handle, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    }
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const std::wstring invocation_cwd = current_directory();
    const std::wstring launcher_cwd = executable_directory();
    if (!launcher_cwd.empty()) SetCurrentDirectoryW(launcher_cwd.c_str());
    const bool extract = argc >= 2 && wcscmp(argv[1], L"extract") == 0;
    const bool shutdown_request = argc >= 2 && wcscmp(argv[1], L"--persistent-shutdown") == 0;
    if (!extract && !shutdown_request) {
        std::vector<std::wstring> forwarded;
        for (int index = 1; index < argc; ++index) forwarded.emplace_back(argv[index]);
        DWORD code = 1;
        if (!spawn_runtime(forwarded, false, &code, invocation_cwd)) return 1;
        return static_cast<int>(code);
    }

    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return 1;
    const bool shutdown = shutdown_request;
    bool pause = false;
    std::vector<std::wstring> request_arguments;
    const int first_request_argument = extract ? 1 : 2;
    for (int index = first_request_argument; index < argc; ++index) {
        if (wcscmp(argv[index], L"--pause") == 0) {
            pause = true;
        } else {
            request_arguments.emplace_back(argv[index]);
        }
    }
    if (pause && std::find(request_arguments.begin(), request_arguments.end(), L"--no-pause") == request_arguments.end()) {
        request_arguments.emplace_back(L"--no-pause");
    }
    int code = 1;
    bool ok = request(request_arguments, shutdown, code, invocation_cwd);
    if (!ok && !shutdown) {
        spawn_runtime({L"--persistent-server"}, true, nullptr, launcher_cwd);
        for (int attempt = 0; attempt < 400 && !ok; ++attempt) {
            Sleep(25);
            ok = request(request_arguments, false, code, invocation_cwd);
            if (!ok && attempt != 0 && attempt % 40 == 0) {
                spawn_runtime({L"--persistent-server"}, true, nullptr, launcher_cwd);
            }
        }
    }
    if (!ok && shutdown) code = 0;
    if (!ok && !shutdown) write_stream(STD_ERROR_HANDLE, "SunPack persistent process did not start in time.\n");
    if (pause && GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_CHAR) {
        write_stream(STD_OUTPUT_HANDLE, "Press Enter to continue...");
        wchar_t buffer[2]{};
        DWORD read = 0;
        ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), buffer, 1, &read, nullptr);
    }
    WSACleanup();
    return code;
}

#endif
