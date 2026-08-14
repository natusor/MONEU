add_library(moneu_validation STATIC
    tx_validation.cpp
    reveal_validation.cpp
    block_validation.cpp
)

target_include_directories(moneu_validation PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(moneu_validation
    moneu_primitives
    moneu_consensus
    moneu_wallet
    moneu_log
)
