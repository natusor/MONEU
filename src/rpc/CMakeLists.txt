find_package(nlohmann_json 3.2.0 REQUIRED)

add_library(moneu_rpc STATIC
    rpc_server.cpp
)

target_include_directories(moneu_rpc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(moneu_rpc
    moneu_primitives
    moneu_storage
    moneu_validation
    moneu_consensus
    moneu_net
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
    Threads::Threads
    moneu_log
)
