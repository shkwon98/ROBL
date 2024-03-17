add_executable(example_1)
target_sources(example_1
    PRIVATE example_1.cpp)
target_link_libraries(example_1
    PRIVATE ROBL::ROBL)