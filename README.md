# MONEU

Electronic system for transferring and holding value.
The wallet is protected by a file of entropy from physical events.

It is not a hardfork.

Built on SHA-256 Proof-of-Work and the UTXO model with a hard cap of 30
million coins.

Every wallet generates a local 32 MiB entropy file, harvested from timing
measurements on the machine that made it.
Each spend consumes a single-use leaf from that file cryptographically
bound to the transaction it authorises.
If you make a consolidation transaction then first check your leaf counter.
The leaf is spent for every input so consolidating many outputs consumes
many leaves at once.

**Key security model:**
The private key alone cannot authorise a transaction.
Without the entropy file funds cannot be moved.
Whoever holds the key but not the file cannot spend.

Registered in SLIP-0044 as coin type 8328.

## Build and run

```
git clone https://github.com/natusor/MONEU.git
cd MONEU
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/src/moneu-test-noise
./build/src/moneud -daemon
```

The node ships with built-in mining software. 
No separate miner and no pool required.

### Requirements

Ubuntu 22.04 or newer or Debian. 
Boost 1.74 or newer is required, so it will not build on older systems.

```
apt install -y build-essential cmake \
    libboost-filesystem-dev libboost-system-dev \
    libboost-thread-dev libboost-program-options-dev \
    libssl-dev libleveldb-dev nlohmann-json3-dev
```

If an old build directory is left over from a previous attempt, remove it
first. CMake keeps old paths in its cache and the build will fail with a
confusing error.

See [BUILD.md](BUILD.md) for more detail.

## After the first start

Create a wallet, then generate its entropy file. Only then can you unlock
the wallet and create addresses.

```
./build/src/moneu-cli createwallet "your-passphrase"
./build/src/moneu-cli makenoise "your-passphrase"
./build/src/moneu-cli walletunlock "your-passphrase"
./build/src/moneu-cli getnewaddress
```

Copy the whole wallet folder including the entropy file to at least two
separate drives and encrypt them. 
Losing the entropy file means losing access to the coins even with the recovery words.

Do not create two different wallets on the same machine.

## Documentation

Full specification available in
[MONEU-White-Paper_EN.md](MONEU-White-Paper_EN.md)

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
