# Logging has no dependencies of its own, so every other library can link
# it without creating a cycle. That matters: the miner, the network layer
# and the chain state all need to log, and they sit in different libraries
# that already depend on one another.
add_library(moneu_log STATIC
    log.cpp
)

target_include_directories(moneu_log PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(moneu_log
    ${Boost_LIBRARIES}
)
