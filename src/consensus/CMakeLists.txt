# Proof-of-work consensus and mempool.

add_library(moneu_consensus STATIC
    pow.cpp
    mempool.cpp
)
target_include_directories(moneu_consensus PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
target_link_libraries(moneu_consensus
    moneu_crypto
    moneu_primitives
    moneu_log
)
