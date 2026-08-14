add_library(moneu_node STATIC
    data_dir.cpp
    config.cpp
    wallet_manager.cpp
    node_identity.cpp
)
target_include_directories(moneu_node PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
target_link_libraries(moneu_node
    moneu_primitives
    moneu_wallet
    moneu_storage
    moneu_crypto
    ${Boost_LIBRARIES}
    moneu_log
)
