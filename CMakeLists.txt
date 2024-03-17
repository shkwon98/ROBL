cmake_minimum_required(VERSION 3.14)

project(ROBL
    LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(ROBL INTERFACE)
target_include_directories(ROBL
    INTERFACE include)
add_library(ROBL::ROBL ALIAS ROBL)

# add_subdirectory(examples)