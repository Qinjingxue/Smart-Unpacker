cmake_minimum_required(VERSION 3.20)

project(sevenzip_password_tester LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

function(apply_release_optimizations target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:/O2 /Oi /Ot /GL /Gy /Gw /GF>
        )
        target_link_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF>
        )
    else()
        target_compile_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:-O3 -flto -ffunction-sections -fdata-sections>
        )
        target_link_options(${target_name} PRIVATE
            $<$<CONFIG:Release>:-flto -Wl,--gc-sections>
        )
    endif()
endfunction()

set(SUP7Z_INTERNAL_SOURCES
    src/internal/archive_extract.cpp
    src/internal/archive_crc_manifest.cpp
    src/internal/archive_health.cpp
    src/internal/archive_open_plan.cpp
    src/internal/archive_resources.cpp
    src/internal/embedded_7z.cpp
    src/internal/operation_dispatch.cpp
    src/internal/password_testing.cpp
    src/internal/sevenzip_engine.cpp
    src/internal/sevenzip_formats.cpp
    src/internal/sevenzip_paths.cpp
    src/internal/sevenzip_properties.cpp
    src/internal/sevenzip_sdk.cpp
    src/internal/sevenzip_status.cpp
    src/internal/sevenzip_streams.cpp
    src/internal/strict_archive_validation.cpp
)

add_library(sevenzip_password_tester STATIC
    ${SUP7Z_INTERNAL_SOURCES}
)
apply_release_optimizations(sevenzip_password_tester)

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
    src/c_api_operation.cpp
    src/c_api_passwords.cpp
    src/c_api_crc_manifest.cpp
    src/c_api_resources.cpp
    ${SUP7Z_INTERNAL_SOURCES}
)
apply_release_optimizations(sevenzip_password_tester_capi)

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
apply_release_optimizations(sevenzip_password_tester_smoke)

target_link_libraries(sevenzip_password_tester_smoke
    PRIVATE sevenzip_password_tester
)

add_executable(sevenzip_worker
    src/sevenzip_worker.cpp
)
apply_release_optimizations(sevenzip_worker)

target_link_libraries(sevenzip_worker
    PRIVATE sevenzip_password_tester
)

if(WIN32)
    target_compile_definitions(sevenzip_worker PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

enable_testing()
add_test(NAME sevenzip_password_tester_smoke COMMAND sevenzip_password_tester_smoke)
