# MONEU

Electronic system for transferring and holding value.

The wallet is protected by a file of entropy from physical events.

Built on SHA-256 Proof-of-Work and the UTXO model with a hard cap of 30 million coins.

Every wallet generates a local 32 MiB entropy file, harvested from timing
measurements on the machine that made it.

Each spend consumes a single-use leaf from that file, cryptographically bound to the transaction it authorises.

**Key security model:**

The private key alone cannot authorise a transaction.
Without the entropy file funds cannot be moved.
Whoever holds the key but not the file cannot spend.

## Building

Refer to [BUILD.md](BUILD.md) for build instructions and prerequisites.

## Documentation

Full specification available in
[MONEU-White-Paper_EN.md](MONEU-White-Paper_EN.md), also published at
[github.com/natusor/MONEU-White-Paper_EN.md](https://github.com/natusor/MONEU-White-Paper_EN.md/blob/main/MONEU-White-Paper_EN.md).

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
