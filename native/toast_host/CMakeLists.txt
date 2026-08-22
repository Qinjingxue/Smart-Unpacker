cmake_minimum_required(VERSION 3.20)

project(sunpack_toast_host LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "sunpack_toast_host is Windows-only")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

add_executable(sunpack_toast_host WIN32 src/main.cpp)
target_compile_definitions(sunpack_toast_host PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)
if(MSVC)
    set_property(TARGET sunpack_toast_host PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
    target_compile_options(sunpack_toast_host PRIVATE
        /utf-8 /permissive- /W4
        $<$<CONFIG:Release>:/O2 /Oi /Ot /GL /Gy /Gw /GF>
    )
    target_link_options(sunpack_toast_host PRIVATE
        $<$<CONFIG:Release>:/LTCG /OPT:REF /OPT:ICF>
    )
endif()
target_link_libraries(sunpack_toast_host PRIVATE
    windowsapp
    runtimeobject
    ole32
    shell32
    propsys
    advapi32
)

enable_testing()
add_test(NAME sunpack_toast_host_self_test COMMAND sunpack_toast_host --self-test)
