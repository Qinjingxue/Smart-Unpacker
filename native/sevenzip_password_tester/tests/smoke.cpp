#include "sevenzip_password_tester/password_tester.hpp"

#include <iostream>
#include <string>

int wmain(int argc, wchar_t** argv) {
    std::wstring dll_path = L"tools\\7z.dll";
    if (argc > 1) {
        dll_path = argv[1];
    }

    const bool available = packrelic::sevenzip::is_backend_available(dll_path);
    const auto result = packrelic::sevenzip::test_password(dll_path, L"", L"");

    std::cout << "backend_available=" << (available ? "true" : "false") << "\n";
    std::cout << "status=" << packrelic::sevenzip::status_name(result.status) << "\n";
    std::cout << "message=" << result.message << "\n";

    return available == result.backend_available ? 0 : 1;
}
