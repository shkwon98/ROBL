add_executable(receiver)
target_sources(receiver
    PRIVATE receiver.cpp)
target_link_libraries(receiver
    PRIVATE ROBL::ROBL)

add_executable(sender)
target_sources(sender
    PRIVATE sender.cpp)
target_link_libraries(sender
    PRIVATE ROBL::ROBL)