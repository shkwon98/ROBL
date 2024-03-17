cmake_minimum_required(VERSION 3.14)

project(ROBL
    LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)

find_package(Threads REQUIRED)

add_library(ROBL SHARED)
target_sources(ROBL
    PRIVATE src/robl.cc
            src/robl_base.cc
            src/impl/robl_base_pkt.cc)
target_link_libraries(ROBL
    PRIVATE Threads::Threads)
target_include_directories(ROBL
    PUBLIC include)
target_compile_features(ROBL
    PUBLIC cxx_std_17)
add_library(ROBL::ROBL ALIAS ROBL)

add_subdirectory(examples)