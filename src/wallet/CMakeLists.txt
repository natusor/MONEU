add_library(moneu_wallet STATIC
    bip32.c
    bip39.c
    bip39_english.c
    noise_otp.cpp
    noise_generator.cpp
    noise_tree.cpp
    noise_store.cpp
)
target_include_directories(moneu_wallet PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
target_link_libraries(moneu_wallet
    moneu_crypto
    moneu_primitives
    Threads::Threads
    moneu_log
)
