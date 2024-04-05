cmake_minimum_required(VERSION 3.21.0)
project(dfi-scanner
    VERSION "0.1"
    DESCRIPTION "A library and tools for interacting with DFI"
    HOMEPAGE_URL "https://github.com/SpecterOps/dfi-scanner"
    LANGUAGES CXX
)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})
include(requirements.cmake)

add_library(dfi)
target_sources(dfi PRIVATE include/libdfi.hpp dfi.cpp)
target_include_directories(dfi PUBLIC include)
target_compile_definitions(dfi PUBLIC NOMINMAX)
target_link_libraries(dfi PUBLIC magic_enum::magic_enum)
target_link_libraries(dfi PUBLIC pybind11::pybind11)

pybind11_add_module(pydfi module.cpp)

add_executable(scan_file)
target_sources(scan_file PRIVATE examples/scan_file.cpp)
target_link_libraries(scan_file PRIVATE dfi)