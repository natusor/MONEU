add_library(moneu_crypto STATIC
    arith_uint256.cpp
    sha2.c
    base58.c
    ripemd160.c
    hmac.c
    pbkdf2.c
    secure_enc.cpp
    memzero.c
    rand.c
    ed25519-donna/ed25519.c
    ed25519-donna/ed25519-donna-impl-base.c
    ed25519-donna/ed25519-donna-basepoint-table.c
    ed25519-donna/curve25519-donna-32bit.c
    ed25519-donna/curve25519-donna-helpers.c
    ed25519-donna/curve25519-donna-scalarmult-base.c
    ed25519-donna/modm-donna-32bit.c
    ed25519-donna/ed25519-donna-32bit-tables.c
)

target_include_directories(moneu_crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(moneu_crypto PRIVATE
    -DED25519_CUSTOMHASH
    -DED25519_CUSTOMRANDOM
)

# OpenSSL provides AES-256-CBC for secure_enc.cpp. PUBLIC so every library
# and executable that links moneu_crypto inherits it.
target_link_libraries(moneu_crypto PUBLIC
    ${OPENSSL_CRYPTO_LIBRARY}
    moneu_log
)
