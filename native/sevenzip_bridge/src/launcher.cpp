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
constexpr char kResponseMagic[] = "SPR1";
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

bool request(const std::vector<std::wstring>& arguments, bool shutdown,
             int& exit_code, std::string& stdout_text, std::string& stderr_text) {
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

    std::array<wchar_t, 32768> cwd_buffer{};
    const DWORD cwd_size = GetCurrentDirectoryW(static_cast<DWORD>(cwd_buffer.size()), cwd_buffer.data());
    const std::string cwd = utf8(std::wstring(cwd_buffer.data(), cwd_size));
    std::string wire(kRequestMagic, 4);
    wire.append(reinterpret_cast<const char*>(token.data()), token.size());
    append_u32(wire, shutdown ? 1u : 0u);
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
    std::array<char, 16> header{};
    if (!recv_all(socket, header.data(), header.size()) || memcmp(header.data(), kResponseMagic, 4) != 0) {
        closesocket(socket);
        return false;
    }
    exit_code = static_cast<std::int32_t>(read_u32(header.data() + 4));
    const std::uint32_t stdout_size = read_u32(header.data() + 8);
    const std::uint32_t stderr_size = read_u32(header.data() + 12);
    if (stdout_size > kMaxFieldBytes || stderr_size > kMaxFieldBytes) {
        closesocket(socket);
        return false;
    }
    stdout_text.resize(stdout_size);
    stderr_text.resize(stderr_size);
    const bool ok = recv_all(socket, stdout_text.data(), stdout_text.size()) &&
                    recv_all(socket, stderr_text.data(), stderr_text.size());
    closesocket(socket);
    return ok;
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

bool spawn_runtime(const std::vector<std::wstring>& arguments, bool detached, DWORD* exit_code = nullptr) {
    const std::wstring runtime = executable_directory() + L"\\sunpack-runtime.exe";
    std::wstring command = quote_argument(runtime);
    for (const auto& argument : arguments) command += L" " + quote_argument(argument);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const DWORD flags = detached ? CREATE_NO_WINDOW : 0;
    if (!CreateProcessW(runtime.c_str(), command.data(), nullptr, nullptr, detached ? FALSE : TRUE, flags, nullptr, nullptr,
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
    if (argc < 2 || (wcscmp(argv[1], L"--reuse") != 0 && wcscmp(argv[1], L"--persistent-shutdown") != 0)) {
        std::vector<std::wstring> forwarded;
        for (int index = 1; index < argc; ++index) forwarded.emplace_back(argv[index]);
        DWORD code = 1;
        if (!spawn_runtime(forwarded, false, &code)) return 1;
        return static_cast<int>(code);
    }

    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return 1;
    const bool shutdown = wcscmp(argv[1], L"--persistent-shutdown") == 0;
    bool pause = false;
    std::vector<std::wstring> request_arguments;
    for (int index = 2; index < argc; ++index) {
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
    std::string stdout_text;
    std::string stderr_text;
    bool ok = request(request_arguments, shutdown, code, stdout_text, stderr_text);
    if (!ok && !shutdown) {
        spawn_runtime({L"--persistent-server"}, true);
        for (int attempt = 0; attempt < 400 && !ok; ++attempt) {
            Sleep(25);
            ok = request(request_arguments, false, code, stdout_text, stderr_text);
            if (!ok && attempt != 0 && attempt % 40 == 0) {
                spawn_runtime({L"--persistent-server"}, true);
            }
        }
    }
    if (!ok && shutdown) code = 0;
    if (!ok && !shutdown) stderr_text = "SunPack persistent process did not start in time.\n";
    write_stream(STD_OUTPUT_HANDLE, stdout_text);
    write_stream(STD_ERROR_HANDLE, stderr_text);
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
