// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_NODE_WALLET_MANAGER_H
#define MONEU_NODE_WALLET_MANAGER_H

#include "data_dir.h"
#include "config.h"
#include "../primitives/keys.h"
#include "../primitives/transaction.h"
#include "../storage/utxo_set.h"
#include "../chainparams.h"
#include "../wallet/noise_otp.h"
#include "../wallet/noise_store.h"
#include "../crypto/secure_enc.h"

extern "C" {
    #include "../wallet/bip32.h"
    #include "../wallet/bip39.h"
    #include "../crypto/pbkdf2.h"
    #include "../crypto/sha2.h"
    #include "../crypto/memzero.h"
    #include "../crypto/rand.h"
}

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <mutex>
#include <cstdint>

#include <boost/filesystem.hpp>

namespace MONEU {
namespace node {

namespace fs = boost::filesystem;

class WalletError : public std::runtime_error {
public:
    explicit WalletError(const std::string& msg)
        : std::runtime_error(msg) {}
};

struct WalletAddress {
    std::string address;
    bytes32     pubkeyHash;
    uint32_t    keyIndex;
    std::string label;
    uint64_t    balance;
    bool        isChange;

    WalletAddress()
        : keyIndex(0)
        , balance(0)
        , isChange(false)
    {
        pubkeyHash.fill(0);
    }
};

struct WalletTxRecord {
    bytes32  txHash;
    int64_t  amount;
    uint32_t height;
    uint64_t timestamp;
    bool     isConfirmed;
    std::string description;

    WalletTxRecord()
        : amount(0)
        , height(0)
        , timestamp(0)
        , isConfirmed(false)
    {
        txHash.fill(0);
    }
};

class WalletManager {
private:
    fs::path               mWalletFile;
    mutable std::mutex     mMutex;
    bool                   mLocked;
    bool                   mInitialized;

    // The wallet's secret at rest is the BIP-39 ENTROPY, not the seed derived
    // from it. mnemonic -> seed runs through PBKDF2 and is one-way, so a
    // stored seed cannot produce the recovery phrase back; a stored entropy
    // reproduces both the phrase and the seed exactly. Encrypted with
    // authenticated encryption: mTag authenticates mEncryptedEntropy, so a
    // wrong passphrase or a tampered file is detected before anything derived
    // from it is used.
    std::vector<uint8_t>   mEncryptedEntropy;
    std::vector<uint8_t>   mSalt;   // PBKDF2 salt, fresh on every save
    std::vector<uint8_t>   mIV;     // AES-CBC IV, fresh on every save
    std::vector<uint8_t>   mTag;
    bytes32                mMasterPubkey;

    // Decrypted 64-byte seed, held in memory only while the wallet is
    // unlocked so it can derive per-address keys for addresses and signing.
    // Filled by Unlock, wiped by Lock and on destruction. Empty when locked.
    std::vector<uint8_t>   mUnlockedSeed;

    std::vector<WalletAddress>   mAddresses;
    std::vector<WalletTxRecord>  mTxHistory;

    uint32_t mNextKeyIndex;
    uint32_t mNextChangeIndex;

    // Noise (anti-quantum OTP) state. The wallet's single noise file is the
    // secret that authorises spending; its public root (KPS) is folded into
    // every address this wallet produces. Loaded on demand from the same
    // wallet directory makenoise wrote it to.
    bool                       mNoiseLoaded;
    bytes32                    mNoiseKps;
    std::unique_ptr<NoiseFile> mNoiseFile;

    // First leaf of the noise pool that has not been spent yet.
    //
    // The noise file itself cannot answer this: it holds the same bytes
    // before and after a spend. Kept here so it survives a restart, and
    // corrected against the chain by SyncNoiseLeafPointer, which is what
    // covers a wallet whose noise file came back from a backup copy.
    uint32_t                   mNoiseNextLeaf;

    // Outpoint -> id of the pending transaction that took it. Cleared for
    // one transaction by ReleaseOutpointsFor when it confirms or is
    // dropped, so an output is never held after the spend that claimed it
    // has gone.
    std::map<std::string, bytes32> mHeldOutpoints;

    // Key for the map above: the 32-byte hash followed by the index.
    static std::string OutpointKey(const bytes32& txid, uint32_t index);

    // Proofs made for a transaction that has been signed but whose leaves
    // are not published yet.
    //
    // In the two-block model a transaction reaches its block carrying no
    // proof; the leaves follow in a later block. The wallet therefore has
    // to hold the proofs from the moment it signs until the transaction is
    // seen in a block, and then hand them over as a reveal.
    //
    // They are written to the wallet file, not merely kept in memory. The
    // window is six blocks, about an hour, and a node restarted inside it
    // would otherwise lose the proofs - the leaves would already be
    // consumed, so they could not be made again, and the payment would sit
    // held until it expired.
    // On-disk format version. Version 2 carries the AES-CBC IV and holds
    // an AES-encrypted entropy field; version 1 files are not readable.
    // Version 4 stores proofs prepared for transactions awaiting their
    // reveal; version 3 stored the leaf pointer; version 2 neither.
    static const uint32_t WALLET_VERSION    = 4;
    static const uint32_t PBKDF2_ITERATIONS =
        crypto::ENC_PBKDF2_ITERATIONS;
    static const uint32_t SALT_SIZE         = 32;
    static const uint32_t IV_SIZE           =
        static_cast<uint32_t>(crypto::ENC_IV_SIZE);
    static const uint32_t TAG_SIZE          =
        static_cast<uint32_t>(crypto::ENC_TAG_SIZE);
    // Largest BIP-39 entropy this wallet stores (256 bits).
    static const uint32_t MAX_ENTROPY_SIZE  = 32;
    // PKCS#7 padding makes the ciphertext one to sixteen bytes longer than
    // the entropy, so the stored field is bounded by entropy + one block.
    static const uint32_t MAX_ENCRYPTED_ENTROPY_SIZE =
        MAX_ENTROPY_SIZE + static_cast<uint32_t>(crypto::ENC_BLOCK_SIZE);
    static const uint32_t MAX_ADDRESSES     = 100000;

    // Encrypts `entropy` under `passphrase`, filling mSalt with a fresh random
    // salt, mEncryptedEntropy with the ciphertext and mTag with its
    // authentication tag.
    void EncryptEntropy(const std::string& passphrase,
                        const uint8_t* entropy,
                        size_t len);

    // Authenticates and decrypts the stored entropy. Returns false on a wrong
    // passphrase or a tampered file, leaving entropyOut empty.
    bool DecryptEntropy(const std::string& passphrase,
                        std::vector<uint8_t>& entropyOut) const;

    // Derives the 64-byte BIP-39 seed from entropy, via the recovery phrase
    // the entropy encodes. This is the only path from stored secret to keys,
    // so the phrase GetMnemonic hands out is guaranteed to be the one that
    // reproduces this wallet.
    static bool EntropyToSeed(const std::vector<uint8_t>& entropy,
                              uint8_t seedOut[64]);

    bool SaveToFile() const;
    bool LoadFromFile();

    SecretKey DeriveKeyAtIndex(
        const std::vector<uint8_t>& seed,
        uint32_t index,
        bool isChange) const;

    fs::path GetNoiseFilePath() const;

    // Called by CreateTransaction while mMutex is already held. Private
    // because it takes no lock of its own: reaching it from outside would
    // race on mAddresses and mNextChangeIndex.
    WalletAddress GetChangeAddress();

public:
    explicit WalletManager(const DataDir& dataDir);
    ~WalletManager();

    WalletManager(const WalletManager&) = delete;
    WalletManager& operator=(const WalletManager&) = delete;

    bool Create(const std::string& passphrase,
                std::string& mnemonicOut);

    bool Load(const std::string& passphrase);

    bool ImportMnemonic(const std::string& mnemonic,
                        const std::string& passphrase);

    bool Lock();
    bool Unlock(const std::string& passphrase);
    bool IsLocked() const { return mLocked; }
    bool IsInitialized() const { return mInitialized; }

    WalletAddress GetNewAddress(const std::string& label = "");

    std::vector<WalletAddress> GetAllAddresses() const;
    bool GetAddress(const std::string& address,
                    WalletAddress& addrOut) const;

    int64_t GetTotalBalance(
        const storage::UTXOSet& utxoSet) const;

    int64_t GetAddressBalance(
        const std::string& address,
        const storage::UTXOSet& utxoSet) const;

    // Outputs this wallet can actually spend right now.
    //
    // `chainHeight` is the height of the current tip. It is needed because a
    // mining reward cannot be spent until COINBASE_MATURITY blocks have been
    // built on top of the block that paid it, and an output that is not yet
    // spendable must never be offered to coin selection.
    //
    // Leaving the check to block validation, as this once did, meant the
    // wallet would pick an immature reward, build a transaction around it and
    // only then be told the transaction was invalid. The owner saw a balance
    // they could not spend and an error that named the cause without saying
    // which coins were at fault.
    std::vector<std::pair<storage::OutPoint, storage::Coin>>
    GetSpendableUTXOs(const storage::UTXOSet& utxoSet,
                      uint32_t chainHeight) const;

    Transaction CreateTransaction(
        const std::string& toAddress,
        int64_t amount,
        int64_t fee,
        const storage::UTXOSet& utxoSet,
        uint32_t chainHeight,
        const std::vector<Transaction>* poolTxs = NULL);

    // Outputs this wallet has committed to a transaction that has not been
    // confirmed yet.
    //
    // The unspent set describes the chain, and the chain knows nothing of a
    // transfer still waiting in the pool. Selecting from it alone meant a
    // second transfer reached for an output the first had already taken,
    // and the pool refused it as a conflict - correctly, but the wallet
    // should never have built it. Sending twice inside one block interval
    // was therefore impossible.
    //
    // Two halves fix that. Outputs handed to a pending transaction are held
    // back so nothing reaches for them twice. Change those transactions pay
    // back to this wallet is offered as spendable, which is what lets
    // several transfers follow one another between blocks.
    //
    // None of this is what stops a double spend. The pool refuses a
    // conflicting spend and applying a block refuses an input already
    // marked spent, whatever any wallet believes. This only keeps the
    // wallet from building a transfer that was going to be thrown away.
    void ReleaseOutpointsFor(const bytes32& txid);
    size_t HeldOutpointCount() const;

    // Whether this output can be spent at the given chain height.
    //
    // Only mining rewards have to wait. An ordinary output can be spent as
    // soon as the block carrying it is on the chain, while a reward needs
    // COINBASE_MATURITY blocks built on top of the one that paid it.
    //
    // Defined here rather than in the .cpp so that anything holding a Coin
    // can ask the question without linking the whole wallet.
    static bool IsSpendableNow(const storage::Coin& coin,
                               uint32_t chainHeight) {
        if (!coin.isCoinbase) return true;
        return chainHeight >= coin.height + NetParams::COINBASE_MATURITY;
    }

    bool SignTransaction(Transaction& tx);

    // Noise file (anti-quantum OTP) access.
    // HasNoiseFile reports whether a noise.dat exists in the wallet dir.
    // LoadNoiseFile decrypts it with the passphrase, rebuilds the leaf pool
    // and computes the KPS; it must be called before addresses bound to the
    // noise file can be produced or spent. GetNoiseKps returns the loaded
    // public root. GetNoiseRemaining reports unused single-use leaves left.
    bool HasNoiseFile() const;
    bool LoadNoiseFile(const std::string& passphrase);

    // Move the noise leaf pointer past every leaf this wallet's KPS has
    // already consumed on the chain, and save the wallet if it moved.
    //
    // Call once the chain is loaded and after any reorg. Without it a
    // wallet that restarted, or that restored its noise file from a copy
    // on a USB stick, would offer leaves the chain has already seen and
    // every spend it signed would be rejected as reuse.
    //
    // Returns the number of leaves the pointer moved forward.
    uint32_t SyncNoiseLeafPointer(const storage::UTXOSet& utxoSet);

    // Assemble the reveal for a transaction now known to sit at height.
    // False when nothing was prepared for it.
    bool IsNoiseLoaded() const { return mNoiseLoaded; }
    const bytes32& GetNoiseKps() const;
    uint32_t GetNoiseRemaining() const;

    void AddTxRecord(const WalletTxRecord& record);
    std::vector<WalletTxRecord> GetTxHistory() const;

    bool Exists() const;

    // Returns the BIP-39 recovery phrase for this wallet. The phrase is
    // reconstructed from the stored entropy, so it is exactly the phrase that
    // restores this wallet - anyone backing it up and restoring from it gets
    // these keys and these addresses back.
    //
    // Note for the holder: the phrase alone does NOT recover spendable funds.
    // Every address is bound to the wallet's noise file (KPS), and spending
    // needs a single-use proof from it, so the noise file must be backed up
    // separately. That is the point of the second layer.
    std::string GetMnemonic(const std::string& passphrase) const;

    // Export the private key of a single address as hex. Requires the
    // passphrase; the key is derived from the passphrase-protected seed, so a
    // locked wallet cannot leak it. Note that on MONEU the private key alone
    // does not grant spending power - spending also requires the noise (OTP)
    // file, which this never exports.
    std::string DumpPrivKey(const std::string& address,
                            const std::string& passphrase) const;
};

} // namespace node
} // namespace MONEU

#endif // MONEU_NODE_WALLET_MANAGER_H
