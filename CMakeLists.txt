cmake_minimum_required(VERSION 3.14)

project(ROBL
    LANGUAGES CXX)

add_library(ROBL SHARED)
target_include_directories(ROBL
    PUBLIC include)
add_library(ROBL::ROBL ALIAS ROBL)

# add_subdirectory(examples)