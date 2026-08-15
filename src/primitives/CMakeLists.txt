add_library(moneu_primitives STATIC
    keys.cpp
    script.cpp
    transaction.cpp
    block.cpp
)

target_include_directories(moneu_primitives PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(moneu_primitives
    moneu_crypto
    moneu_wallet
    moneu_log
)
