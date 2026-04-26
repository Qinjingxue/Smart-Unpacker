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

add_library(sevenzip_password_tester STATIC
    src/internal/sevenzip_engine.cpp
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
    src/c_api_passwords.cpp
    src/c_api_crc_manifest.cpp
    src/c_api_resources.cpp
    src/internal/sevenzip_engine.cpp
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

enable_testing()
add_test(NAME sevenzip_password_tester_smoke COMMAND sevenzip_password_tester_smoke)
