add_library(moneu_net STATIC
    addrman.cpp
    socks5.cpp
    torcontrol.cpp
    net.cpp
    portmap.cpp
)

target_include_directories(moneu_net PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(moneu_net
    moneu_primitives
    moneu_crypto
    ${Boost_LIBRARIES}
    Threads::Threads
    moneu_log
)
