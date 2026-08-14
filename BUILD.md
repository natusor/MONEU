# MONEU — building

## Dependencies

Ubuntu 24.04 / Debian:

    apt-get install -y build-essential cmake \
        libboost-filesystem-dev libboost-system-dev \
        libboost-thread-dev libboost-program-options-dev \
        libssl-dev libleveldb-dev nlohmann-json3-dev

`nlohmann-json3-dev` is required by `src/rpc` and `libssl-dev` by
`src/crypto/secure_enc.cpp` (AES-256-CBC).

## Build

The short way, from the directory holding CMakeLists.txt:

    ./build.sh

It wipes any previous build directory first. That matters: a build/
directory left over from an earlier extraction keeps a CMakeCache pointing
at wherever it was configured, and cmake then complains about a source
directory that no longer exists rather than using the one in front of it.

By hand:

    rm -rf build
    mkdir build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc)

Run these from the directory that contains CMakeLists.txt. 
Unpacking the archive already puts you one level above it so if `ls` shows CMakeLists.txt
you are in the right place and there is nothing further to cd into.

Produces `moneud`, `moneu-cli` and `moneu-test-noise`.

## Self-test

    ./src/moneu-test-noise

Runs the whole suite: 
consensus rules, storage, wallet, networking and money arithmetic. 
It must end with

    ALL TESTS PASSED

Anything else means the build is not fit to run and the output names the
check that failed.

## Running a node

    ./moneud -daemon

The node detaches and writes to `moneu.log` in the logs directory of the
data directory. 
Without `-daemon` it stays in the foreground and logs to the terminal which holds the terminal until the node stops.

    ./moneu-cli getinfo
    ./moneu-cli stop

## Mining

Mining is built in so No separate software is needed.

    ./moneu-cli createwallet <passphrase>
    ./moneu-cli makenoise <passphrase>
    ./moneu-cli walletunlock <passphrase>
    ./moneu-cli getnewaddress
    ./moneu-cli startmining <address> [threads]

Write down the recovery phrase `createwallet` prints and keep a copy of the wallet directory. 
Both the wallet file and the noise file are needed to spend neither is enough on its own.



