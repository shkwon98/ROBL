cmake_minimum_required(VERSION 3.14)

project(ROBL
    LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(ROBL SHARED)
target_sources(ROBL
    PRIVATE src/robl.cc
            src/robl_base.cc
            src/impl/robl_base_pkt.cc)
target_include_directories(ROBL
    PRIVATE include)
target_compile_features(ROBL
    PRIVATE cxx_std_17)
add_library(ROBL::ROBL ALIAS ROBL)

# add_subdirectory(examples)