cmake_minimum_required(VERSION 3.20)

project(sevenzip_password_tester LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(sevenzip_password_tester STATIC
    src/internal/sevenzip_engine.cpp
)

target_include_directories(sevenzip_password_tester
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_compile_definitions(sevenzip_password_tester PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX SUP7Z_BUILD_DLL)
    target_link_libraries(sevenzip_password_tester PUBLIC OleAut32)
endif()

add_library(sevenzip_password_tester_capi SHARED
    src/archive_probe.cpp
    src/archive_test.cpp
    src/c_api_health.cpp
    src/c_api_passwords.cpp
    src/c_api_resources.cpp
    src/internal/sevenzip_engine.cpp
)

target_include_directories(sevenzip_password_tester_capi
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_compile_definitions(sevenzip_password_tester_capi PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX SUP7Z_BUILD_DLL)
    target_link_libraries(sevenzip_password_tester_capi PRIVATE OleAut32)
endif()

add_executable(sevenzip_password_tester_smoke
    tests/smoke.cpp
)

target_link_libraries(sevenzip_password_tester_smoke
    PRIVATE sevenzip_password_tester
)

enable_testing()
add_test(NAME sevenzip_password_tester_smoke COMMAND sevenzip_password_tester_smoke)
