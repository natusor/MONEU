add_library(moneu_net STATIC
    addrman.cpp
    net.cpp
)

target_include_directories(moneu_net PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(moneu_net
    moneu_primitives
    ${Boost_LIBRARIES}
    Threads::Threads
    moneu_log
)
