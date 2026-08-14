add_subdirectory(log)
add_subdirectory(util)
add_subdirectory(crypto)
add_subdirectory(wallet)
add_subdirectory(primitives)
add_subdirectory(consensus)
add_subdirectory(storage)
add_subdirectory(validation)
add_subdirectory(net)
add_subdirectory(rpc)
add_subdirectory(node)
# Network constants (NetParams). Several libraries reference these, so
# chainparams must be a library of its own rather than a source compiled
# into one executable. The file stays at src/chainparams.cpp so it can be
# swapped for the genesis-mining variant without touching the build.
add_library(moneu_chainparams STATIC
    chainparams.cpp
)
target_include_directories(moneu_chainparams PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(moneu_chainparams
    moneu_primitives
    moneu_consensus
    moneu_crypto
)

add_executable(moneud
    main.cpp
    miner.cpp
)
target_link_libraries(moneud
    -Wl,--start-group
    moneu_rpc
    moneu_node
    moneu_net
    moneu_validation
    moneu_storage
    moneu_consensus
    moneu_primitives
    moneu_wallet
    moneu_crypto
    moneu_chainparams
    ${LEVELDB_LIBRARY}
    -Wl,--end-group
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)
add_executable(moneu-cli
    moneu-cli.cpp
)
target_include_directories(moneu-cli PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/crypto
)
target_link_libraries(moneu-cli
    -Wl,--start-group
    moneu_wallet
    moneu_primitives
    moneu_chainparams
    moneu_consensus
    moneu_storage
    moneu_crypto
    ${LEVELDB_LIBRARY}
    -Wl,--end-group
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# Self-test for the anti-quantum noise shield: proof creation, binding to a
# transaction hash, rejection of a rebound or replayed proof, and pool
# exhaustion. Built as its own executable so it can be run directly.
add_executable(moneu-test-noise
    test_noise_shield.cpp
)
target_include_directories(moneu-test-noise PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/crypto
)
target_link_libraries(moneu-test-noise
    -Wl,--start-group
    moneu_validation
    moneu_storage
    moneu_primitives
    moneu_wallet
    moneu_chainparams
    moneu_consensus
    moneu_crypto
    ${LEVELDB_LIBRARY}
    -Wl,--end-group
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    Threads::Threads
    moneu_net
    moneu_util
)
