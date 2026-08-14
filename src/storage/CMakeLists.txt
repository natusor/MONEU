add_library(moneu_storage STATIC
    block_data.cpp
    block_undo.cpp
    utxo_set.cpp
    chain_state.cpp
    db_wrapper.cpp
)

target_include_directories(moneu_storage PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(moneu_storage
    moneu_primitives
    moneu_crypto
    moneu_wallet
    ${LEVELDB_LIBRARY}
    moneu_log
)
