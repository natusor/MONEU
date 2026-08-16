// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "wallet_manager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <cerrno>

#ifndef WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

extern "C" {
    #include "../crypto/hmac.h"
}

namespace MONEU {
namespace node {

namespace {

std::vector<uint8_t> BuildAuthHeader(const std::vector<uint8_t>& salt,
                                     const std::vector<uint8_t>& iv) {
    std::vector<uint8_t> header;
    header.reserve(salt.size() + iv.size());
    header.insert(header.end(), salt.begin(), salt.end());
    header.insert(header.end(), iv.begin(), iv.end());
    return header;
}

}

WalletManager::WalletManager(const DataDir& dataDir)
    : mWalletFile(dataDir.GetWalletFilePath())
    , mLocked(true)
    , mInitialized(false)
    , mNextKeyIndex(0)
    , mNextChangeIndex(0)
    , mNoiseLoaded(false)
    , mNoiseNextLeaf(0)
{
    mSalt.resize(SALT_SIZE, 0);
    mIV.resize(IV_SIZE, 0);
    mTag.resize(TAG_SIZE, 0);
    mEncryptedEntropy.clear();
    mMasterPubkey.fill(0);
    mNoiseKps.fill(0);
}

WalletManager::~WalletManager() {
    memzero(mEncryptedEntropy.data(), mEncryptedEntropy.size());
    memzero(mSalt.data(), mSalt.size());
    memzero(mIV.data(), mIV.size());
    memzero(mTag.data(), mTag.size());
    memzero(mMasterPubkey.data(), mMasterPubkey.size());
    if (!mUnlockedSeed.empty()) {
        memzero(mUnlockedSeed.data(), mUnlockedSeed.size());
    }
}

void WalletManager::EncryptEntropy(
    const std::string& passphrase,
    const uint8_t* entropy,
    size_t len)
{
    mSalt.resize(SALT_SIZE);
    mIV.resize(IV_SIZE);
    random_buffer(mSalt.data(), SALT_SIZE);
    random_buffer(mIV.data(), IV_SIZE);

    crypto::SecureKeys keys;
    if (!keys.Derive(passphrase, mSalt.data(), mSalt.size(),
                     PBKDF2_ITERATIONS)) {
        throw WalletError("Could not derive wallet encryption key");
    }

    std::vector<uint8_t> cipher;
    if (!crypto::EncryptCBC(entropy, len, keys, mIV.data(), cipher)) {
        throw WalletError("Wallet entropy encryption failed");
    }

    const std::vector<uint8_t> header = BuildAuthHeader(mSalt, mIV);
    mTag.resize(TAG_SIZE);
    crypto::ComputeTag(keys,
                       header.data(), header.size(),
                       cipher.data(), cipher.size(),
                       mTag.data());

    mEncryptedEntropy.swap(cipher);
}

bool WalletManager::DecryptEntropy(
    const std::string& passphrase,
    std::vector<uint8_t>& entropyOut) const
{
    entropyOut.clear();

    if (mEncryptedEntropy.empty() ||
        mSalt.size() != SALT_SIZE ||
        mIV.size()   != IV_SIZE ||
        mTag.size()  != TAG_SIZE) {
        return false;
    }

    crypto::SecureKeys keys;
    if (!keys.Derive(passphrase, mSalt.data(), mSalt.size(),
                     PBKDF2_ITERATIONS)) {
        return false;
    }

    const std::vector<uint8_t> header = BuildAuthHeader(mSalt, mIV);
    uint8_t expectTag[TAG_SIZE];
    crypto::ComputeTag(keys,
                       header.data(), header.size(),
                       mEncryptedEntropy.data(), mEncryptedEntropy.size(),
                       expectTag);

    const bool tagOk = crypto::ConstantTimeEqual(expectTag, mTag.data(),
                                                 TAG_SIZE);
    memzero(expectTag, sizeof(expectTag));
    if (!tagOk) {
        return false;
    }

    return crypto::DecryptCBC(mEncryptedEntropy.data(),
                              mEncryptedEntropy.size(),
                              keys, mIV.data(), entropyOut);
}

bool WalletManager::EntropyToSeed(
    const std::vector<uint8_t>& entropy,
    uint8_t seedOut[64])
{
    const char* mnemonic =
        mnemonic_from_data(entropy.data(),
                           static_cast<int>(entropy.size()));
    if (!mnemonic) {
        return false;
    }
    mnemonic_to_seed(mnemonic, "", seedOut, nullptr);
    mnemonic_clear();
    return true;
}

SecretKey WalletManager::DeriveKeyAtIndex(
    const std::vector<uint8_t>& seed,
    uint32_t index,
    bool isChange) const
{
    HDNode node;
    hdnode_from_seed(seed.data(), seed.size(),
                     "ed25519 seed", &node);

    hdnode_private_ckd_prime(&node, 44);
    hdnode_private_ckd_prime(&node, 8328);
    hdnode_private_ckd_prime(&node, 0);
    hdnode_private_ckd(&node, isChange ? 1 : 0);
    hdnode_private_ckd(&node, index);

    bytes32 keyBytes;
    std::memcpy(keyBytes.data(), node.private_key, 32);
    memzero(&node, sizeof(node));

    return SecretKey::FromSeed(keyBytes);
}

static std::string BuildAddress(const bytes32& pubkeyHash) {
    uint8_t payload[33];
    payload[0] = NetParams::PUBKEY_ADDRESS_PREFIX;
    std::memcpy(payload + 1, pubkeyHash.data(), 32);

    SHA256_CTX ctx;
    uint8_t hash1[32], hash2[32];
    sha256_Init(&ctx);
    sha256_Update(&ctx, payload, 33);
    sha256_Final(&ctx, hash1);
    sha256_Init(&ctx);
    sha256_Update(&ctx, hash1, 32);
    sha256_Final(&ctx, hash2);

    uint8_t full[37];
    std::memcpy(full, payload, 33);
    std::memcpy(full + 33, hash2, 4);

    char b58[64];
    size_t b58len = sizeof(b58);
    b58enc(b58, &b58len, full, 37);
    return std::string(b58);
}

bool WalletManager::Create(const std::string& passphrase,
                            std::string& mnemonicOut)
{
    std::lock_guard<std::mutex> lock(mMutex);

    if (mInitialized) {
        throw WalletError("Wallet already exists!");
    }

    const fs::path noisePath = mWalletFile.parent_path() / "noise.dat";
    if (fs::exists(noisePath)) {
        throw WalletError(
            "A noise file already exists in this data directory and it "
            "belongs to a previous wallet. A new wallet must have its own "
            "noise file, or its addresses would share the old wallet's "
            "single-use leaves and both wallets would stop being able to "
            "spend at the same moment. Start the new wallet in a separate "
            "data directory with -datadir, or remove the old wallet and "
            "its noise file if the old wallet is finished with.");
    }

    std::vector<uint8_t> entropy(32);
    random_buffer(entropy.data(), 32);

    const char* mnemonic =
        mnemonic_from_data(entropy.data(), 32);
    if (!mnemonic) {
        memzero(entropy.data(), entropy.size());
        throw WalletError("Failed to generate mnemonic");
    }
    mnemonicOut = std::string(mnemonic);
    mnemonic_clear();

    uint8_t seed[64];
    if (!EntropyToSeed(entropy, seed)) {
        memzero(entropy.data(), entropy.size());
        throw WalletError("Failed to derive seed from entropy");
    }

    HDNode masterNode;
    hdnode_from_seed(seed, 64, "ed25519 seed", &masterNode);
    std::memcpy(mMasterPubkey.data(),
                masterNode.public_key + 1, 32);
    memzero(&masterNode, sizeof(masterNode));
    memzero(seed, 64);

    EncryptEntropy(passphrase, entropy.data(), entropy.size());
    memzero(entropy.data(), entropy.size());

    mLocked      = false;
    mInitialized = true;

    if (!SaveToFile()) {
        throw WalletError("Failed to save wallet to disk");
    }

    std::cerr << "WalletManager: wallet created successfully\n";
    return true;
}

bool WalletManager::Load(const std::string& passphrase) {
    std::lock_guard<std::mutex> lock(mMutex);

    if (!LoadFromFile()) {
        return false;
    }

    std::vector<uint8_t> entropy;
    if (!DecryptEntropy(passphrase, entropy)) {
        std::cerr << "WalletManager: wrong passphrase "
                     "or wallet file tampered with\n";
        return false;
    }

    uint8_t seed[64];
    if (!EntropyToSeed(entropy, seed)) {
        memzero(entropy.data(), entropy.size());
        std::cerr << "WalletManager: stored entropy is not "
                     "a valid BIP-39 entropy\n";
        return false;
    }
    memzero(entropy.data(), entropy.size());

    HDNode masterNode;
    hdnode_from_seed(seed, 64, "ed25519 seed", &masterNode);
    bytes32 derivedPubkey;
    std::memcpy(derivedPubkey.data(),
                masterNode.public_key + 1, 32);
    memzero(&masterNode, sizeof(masterNode));
    memzero(seed, 64);

    if (derivedPubkey != mMasterPubkey) {
        std::cerr << "WalletManager: wallet file is inconsistent\n";
        return false;
    }

    mLocked      = false;
    mInitialized = true;

    std::cerr << "WalletManager: wallet loaded successfully\n";
    return true;
}

bool WalletManager::ImportMnemonic(
    const std::string& mnemonic,
    const std::string& passphrase)
{
    std::lock_guard<std::mutex> lock(mMutex);

    if (!mnemonic_check(mnemonic.c_str())) {
        throw WalletError("Invalid mnemonic phrase");
    }

    uint8_t bits[33];
    std::memset(bits, 0, sizeof(bits));
    int bitCount = mnemonic_to_bits(mnemonic.c_str(), bits);
    if (bitCount <= 0) {
        memzero(bits, sizeof(bits));
        throw WalletError("Invalid mnemonic phrase");
    }

    int words = bitCount / 11;
    size_t entropyLen = static_cast<size_t>(words) * 4 / 3;
    if (entropyLen == 0 || entropyLen > MAX_ENTROPY_SIZE) {
        memzero(bits, sizeof(bits));
        throw WalletError("Unsupported mnemonic length");
    }

    std::vector<uint8_t> entropy(bits, bits + entropyLen);
    memzero(bits, sizeof(bits));

    uint8_t seed[64];
    if (!EntropyToSeed(entropy, seed)) {
        memzero(entropy.data(), entropy.size());
        throw WalletError("Failed to derive seed from mnemonic");
    }

    HDNode masterNode;
    hdnode_from_seed(seed, 64, "ed25519 seed", &masterNode);
    std::memcpy(mMasterPubkey.data(),
                masterNode.public_key + 1, 32);
    memzero(&masterNode, sizeof(masterNode));
    memzero(seed, 64);

    EncryptEntropy(passphrase, entropy.data(), entropy.size());
    memzero(entropy.data(), entropy.size());

    mLocked      = false;
    mInitialized = true;

    if (!SaveToFile()) {
        throw WalletError("Failed to save wallet to disk");
    }

    return true;
}

bool WalletManager::Lock() {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mUnlockedSeed.empty()) {
        memzero(mUnlockedSeed.data(), mUnlockedSeed.size());
        mUnlockedSeed.clear();
    }
    mLocked = true;
    std::cerr << "WalletManager: wallet locked\n";
    return true;
}

bool WalletManager::Unlock(const std::string& passphrase) {
    std::lock_guard<std::mutex> lock(mMutex);

    if (!mInitialized) {
        throw WalletError("Wallet not initialized");
    }

    std::vector<uint8_t> entropy;
    if (!DecryptEntropy(passphrase, entropy)) {
        std::cerr << "WalletManager: wrong passphrase\n";
        return false;
    }

    std::vector<uint8_t> seed(64);
    if (!EntropyToSeed(entropy, seed.data())) {
        memzero(entropy.data(), entropy.size());
        memzero(seed.data(), seed.size());
        std::cerr << "WalletManager: stored entropy is not "
                     "a valid BIP-39 entropy\n";
        return false;
    }
    memzero(entropy.data(), entropy.size());

    HDNode masterNode;
    hdnode_from_seed(seed.data(), 64,
                     "ed25519 seed", &masterNode);
    bytes32 derivedPubkey;
    std::memcpy(derivedPubkey.data(),
                masterNode.public_key + 1, 32);
    memzero(&masterNode, sizeof(masterNode));

    if (derivedPubkey != mMasterPubkey) {
        memzero(seed.data(), 64);
        std::cerr << "WalletManager: wallet file is inconsistent\n";
        return false;
    }

    mUnlockedSeed = seed;
    memzero(seed.data(), 64);

    mLocked = false;
    std::cerr << "WalletManager: wallet unlocked\n";
    return true;
}

WalletAddress WalletManager::GetNewAddress(
    const std::string& label)
{
    std::lock_guard<std::mutex> lock(mMutex);

    if (mAddresses.size() >= MAX_ADDRESSES) {
        throw WalletError(
            "Maximum number of addresses reached");
    }

    if (mLocked || mUnlockedSeed.size() != 64) {
        throw WalletError(
            "Wallet must be unlocked to create an address");
    }

    if (!mNoiseLoaded) {
        throw WalletError(
            "Noise file must be loaded before creating an address");
    }

    WalletAddress addr;
    addr.keyIndex = mNextKeyIndex++;
    addr.label    = label;
    addr.isChange = false;

    SecretKey sk = DeriveKeyAtIndex(mUnlockedSeed, addr.keyIndex, false);
    PublicKey pub = sk.GetPublicKey();

    addr.pubkeyHash = NoiseBoundHash(pub, mNoiseKps);
    addr.address = BuildAddress(addr.pubkeyHash);

    mAddresses.push_back(addr);
    SaveToFile();

    return addr;
}

WalletAddress WalletManager::GetChangeAddress() {
    if (mLocked || mUnlockedSeed.size() != 64) {
        throw WalletError(
            "Wallet must be unlocked to create a change address");
    }

    if (!mNoiseLoaded) {
        throw WalletError(
            "Noise file must be loaded before creating a change address");
    }

    WalletAddress addr;
    addr.keyIndex = mNextChangeIndex++;
    addr.isChange = true;
    addr.label    = "change";

    SecretKey sk = DeriveKeyAtIndex(mUnlockedSeed, addr.keyIndex, true);
    PublicKey pub = sk.GetPublicKey();

    addr.pubkeyHash = NoiseBoundHash(pub, mNoiseKps);
    addr.address = BuildAddress(addr.pubkeyHash);

    mAddresses.push_back(addr);
    SaveToFile();

    return addr;
}

std::vector<WalletAddress>
WalletManager::GetAllAddresses() const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mAddresses;
}

bool WalletManager::GetAddress(
    const std::string& address,
    WalletAddress& addrOut) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    for (const auto& addr : mAddresses) {
        if (addr.address == address) {
            addrOut = addr;
            return true;
        }
    }
    return false;
}

int64_t WalletManager::GetTotalBalance(
    const storage::UTXOSet& utxoSet) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    int64_t total = 0;
    for (const auto& addr : mAddresses) {
        total += utxoSet.GetBalance(addr.pubkeyHash);
    }
    return total;
}

int64_t WalletManager::GetAddressBalance(
    const std::string& address,
    const storage::UTXOSet& utxoSet) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    for (const auto& addr : mAddresses) {
        if (addr.address == address) {
            return utxoSet.GetBalance(addr.pubkeyHash);
        }
    }
    return 0;
}

std::vector<std::pair<storage::OutPoint, storage::Coin>>
WalletManager::GetSpendableUTXOs(
    const storage::UTXOSet& utxoSet,
    uint32_t chainHeight) const
{
    std::lock_guard<std::mutex> lock(mMutex);
    std::vector<std::pair<storage::OutPoint,
                          storage::Coin>> result;

    for (const auto& addr : mAddresses) {
        auto utxos =
            utxoSet.GetUTXOsForAddress(addr.pubkeyHash);
        for (auto& utxo : utxos) {
            if (!IsSpendableNow(utxo.second, chainHeight)) continue;
            result.push_back(utxo);
        }
    }

    return result;
}

std::string WalletManager::OutpointKey(const bytes32& txid, uint32_t index) {
    std::string key(reinterpret_cast<const char*>(txid.data()), 32);
    for (int b = 0; b < 4; ++b) {
        key.push_back(static_cast<char>((index >> (8 * b)) & 0xFF));
    }
    return key;
}

void WalletManager::ReleaseOutpointsFor(const bytes32& txid) {
    std::lock_guard<std::mutex> lock(mMutex);
    for (std::map<std::string, bytes32>::iterator it = mHeldOutpoints.begin();
         it != mHeldOutpoints.end(); ) {
        if (it->second == txid) mHeldOutpoints.erase(it++);
        else ++it;
    }
}

size_t WalletManager::HeldOutpointCount() const {
    std::lock_guard<std::mutex> lock(mMutex);
    return mHeldOutpoints.size();
}

Transaction WalletManager::CreateTransaction(
    const std::string& toAddress,
    int64_t amount,
    int64_t fee,
    const storage::UTXOSet& utxoSet,
    uint32_t chainHeight,
    const std::vector<Transaction>* poolTxs,
    const std::vector<uint8_t>* message)
{
    if (message != NULL && message->size() > NetParams::MAX_OP_RETURN_SIZE) {
        throw WalletError(
            "Message is " + std::to_string(message->size()) +
            " bytes; the limit is " +
            std::to_string(NetParams::MAX_OP_RETURN_SIZE));
    }

    std::lock_guard<std::mutex> lock(mMutex);

    if (mLocked || mUnlockedSeed.size() != 64) {
        throw WalletError("Wallet is locked");
    }

    if (!mNoiseLoaded) {
        throw WalletError(
            "Noise file must be loaded before spending");
    }

    if (amount <= 0) {
        throw WalletError("Invalid amount");
    }

    if (fee < NetParams::MIN_TX_FEE) {
        throw WalletError("Fee too low");
    }

    uint8_t decoded[37];
    size_t decodedLen = 37;
    if (!b58tobin(decoded, &decodedLen,
                  toAddress.c_str()) ||
        decodedLen != 37) {
        throw WalletError("Invalid destination address");
    }

    uint8_t hash1[32], hash2[32];
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, decoded, 33);
    sha256_Final(&ctx, hash1);
    sha256_Init(&ctx);
    sha256_Update(&ctx, hash1, 32);
    sha256_Final(&ctx, hash2);

    if (std::memcmp(decoded + 33, hash2, 4) != 0) {
        throw WalletError("Invalid address checksum");
    }

    bytes32 toPubkeyHash;
    std::memcpy(toPubkeyHash.data(), decoded + 1, 32);

    std::vector<std::pair<storage::OutPoint, storage::Coin>> spendable;
    int64_t immatureHeld = 0;

    for (const auto& a : mAddresses) {
        auto utxos = utxoSet.GetUTXOsForAddress(a.pubkeyHash);
        for (auto& u : utxos) {
            if (!IsSpendableNow(u.second, chainHeight)) {
                immatureHeld += u.second.value;
                continue;
            }
            if (mHeldOutpoints.count(
                    OutpointKey(u.first.txHash, u.first.index)) > 0) {
                continue;
            }
            spendable.push_back(u);
        }
    }

    if (poolTxs != NULL) {
        std::set<std::string> spentInPool;
        for (size_t t = 0; t < poolTxs->size(); ++t) {
            const Transaction& p = (*poolTxs)[t];
            for (size_t i = 0; i < p.GetInputCount(); ++i) {
                spentInPool.insert(OutpointKey(
                    p.GetInputs()[i].GetPrevTxHash(),
                    p.GetInputs()[i].GetOutputIndex()));
            }
        }

        for (size_t t = 0; t < poolTxs->size(); ++t) {
            const Transaction& p = (*poolTxs)[t];
            const bytes32 ptxid = p.GetHash();
            for (size_t o = 0; o < p.GetOutputCount(); ++o) {
                const TxOutput& out = p.GetOutputs()[o];
                if (out.GetValue() <= 0) continue;

                bool mine = false;
                for (size_t a = 0; a < mAddresses.size(); ++a) {
                    if (mAddresses[a].pubkeyHash == out.GetPubkeyHash()) {
                        mine = true; break;
                    }
                }
                if (!mine) continue;

                const std::string key =
                    OutpointKey(ptxid, static_cast<uint32_t>(o));
                if (spentInPool.count(key) > 0)   continue;
                if (mHeldOutpoints.count(key) > 0) continue;

                storage::Coin coin;
                coin.value      = out.GetValue();
                coin.pubkeyHash = out.GetPubkeyHash();
                coin.height     = chainHeight;
                coin.isCoinbase = false;
                coin.isSpent    = false;
                spendable.push_back(std::make_pair(
                    storage::OutPoint(ptxid, static_cast<uint32_t>(o)), coin));
            }
        }
    }

    int64_t needed    = amount + fee;
    int64_t collected = 0;
    std::vector<std::pair<storage::OutPoint,
                          storage::Coin>> selected;

    for (const auto& utxo : spendable) {
        if (collected >= needed) break;
        selected.push_back(utxo);
        collected += utxo.second.value;
    }

    if (collected < needed) {
        if (immatureHeld > 0) {
            throw WalletError(
                "Insufficient funds. " +
                std::to_string(immatureHeld / NetParams::COIN) +
                " MONEU is a mining reward that is not spendable yet - a "
                "reward needs " +
                std::to_string(NetParams::COINBASE_MATURITY) +
                " blocks on top of the block that paid it");
        }
        throw WalletError("Insufficient funds");
    }

    TransactionBuilder builder;

    for (const auto& utxo : selected) {
        const WalletAddress* wa = nullptr;
        for (const auto& a : mAddresses) {
            if (a.pubkeyHash == utxo.second.pubkeyHash) {
                wa = &a;
                break;
            }
        }
        if (!wa) {
            throw WalletError(
                "No wallet key found for a selected input");
        }

        SecretKey sk = DeriveKeyAtIndex(
            mUnlockedSeed, wa->keyIndex, wa->isChange);
        bytes32 realPubkey = sk.GetPublicKey().GetKey();

        builder.AddInput(utxo.first.txHash,
                         utxo.first.index,
                         realPubkey,
                         mNoiseKps);
    }

    builder.AddOutput(amount, toPubkeyHash);

    // A message rides along as an output that carries no value and cannot
    // be spent, so it leaves nothing behind in the unspent set.
    if (message != NULL && !message->empty()) {
        builder.AddDataOutput(*message);
    }

    int64_t change = collected - needed;
    if (change > NetParams::DUST_THRESHOLD) {
        WalletAddress changeAddr = GetChangeAddress();
        builder.AddOutput(change, changeAddr.pubkeyHash);
    }

    Transaction built = builder.Build();
    const bytes32 builtId = built.GetHash();
    for (size_t k = 0; k < selected.size(); ++k) {
        mHeldOutpoints[OutpointKey(selected[k].first.txHash,
                                   selected[k].first.index)] = builtId;
    }
    return built;
}

bool WalletManager::SignTransaction(Transaction& tx) {
    std::lock_guard<std::mutex> lock(mMutex);

    if (mLocked || mUnlockedSeed.size() != 64) {
        throw WalletError("Wallet is locked");
    }

    if (!mNoiseLoaded || !mNoiseFile) {
        throw WalletError("Noise file not loaded");
    }

    bool success = true;

    for (size_t i = 0; i < tx.GetInputCount(); ++i) {
        const TxInput& input = tx.GetInputs()[i];
        PublicKey inputPubkey(input.GetPubkey());
        bytes32 wantHash = NoiseBoundHash(inputPubkey, mNoiseKps);

        bool signed_input = false;
        for (size_t j = 0; j < mAddresses.size(); ++j) {
            const WalletAddress& addr = mAddresses[j];
            if (wantHash == addr.pubkeyHash) {
                SecretKey sk = DeriveKeyAtIndex(
                    mUnlockedSeed, addr.keyIndex, addr.isChange);
                tx.Sign(i, sk);
                signed_input = true;
                break;
            }
        }

        if (!signed_input) {
            std::cerr << "WalletManager: cannot sign input "
                      << i << " - key not found\n";
            success = false;
            break;
        }
    }

    if (!success) {
        return false;
    }

    if (!tx.IsCoinbase()) {
        const size_t inputCount = tx.GetInputCount();
        if (mNoiseFile->GetRemaining() < inputCount) {
            throw WalletError(
                "Noise pool exhausted: not enough single-use leaves left "
                "to authorise every input. Create a new wallet with a fresh "
                "noise file.");
        }

        const bytes32 txHash = tx.GetHash();
        std::vector<TxInput> inputs = tx.GetInputs();
        for (size_t i = 0; i < inputs.size(); ++i) {
            NoiseProof proof = mNoiseFile->CreateProof(txHash);
            inputs[i].SetNoiseProof(proof.Serialize());
        }
        tx.ClearInputs();
        for (size_t i = 0; i < inputs.size(); ++i) {
            tx.AddInput(inputs[i]);
        }

        mNoiseNextLeaf = mNoiseFile->GetNextLeaf();

        // The leaf pointer must reach the disk before this transaction is
        // allowed to leave the wallet.
        //
        // The leaves are consumed the moment the proofs are made, but only
        // this file records how far the pool has been used. A save that
        // failed while the transaction went out anyway left the pointer on
        // disk behind the leaves already spent on the chain: after a
        // restart the wallet would offer those same leaves again and every
        // spend it signed would be refused as reuse, with the owner given
        // no way to tell why.
        //
        // So the failure is raised rather than logged. The caller never
        // broadcasts, the leaves stay consumed in memory only, and nothing
        // that reached the chain disagrees with what is on disk.
        if (!SaveToFile()) {
            throw WalletError(
                "The transaction was signed but the wallet file could not "
                "be written, so the single-use leaves it consumed are not "
                "recorded. The transaction has NOT been sent. Make the "
                "wallet directory writable and try again.");
        }
    }

    return success;
}

fs::path WalletManager::GetNoiseFilePath() const {
    return mWalletFile.parent_path() / "noise.dat";
}

bool WalletManager::HasNoiseFile() const {
    return fs::exists(GetNoiseFilePath());
}

namespace {
}

uint32_t WalletManager::SyncNoiseLeafPointer(
    const storage::UTXOSet& utxoSet)
{
    std::lock_guard<std::mutex> lock(mMutex);

    if (!mNoiseLoaded || !mNoiseFile) {
        return 0;
    }

    uint32_t highest = 0;
    if (!utxoSet.GetHighestSpentNoiseLeaf(mNoiseKps, highest)) {
        return 0;
    }

    const uint32_t wanted = highest + 1;
    const uint32_t before = mNoiseFile->GetNextLeaf();
    mNoiseFile->SetNextLeaf(wanted);
    const uint32_t after = mNoiseFile->GetNextLeaf();

    if (after > before) {
        mNoiseNextLeaf = after;
        if (!SaveToFile()) {
            std::cerr << "WalletManager: could not save the corrected "
                         "noise leaf pointer\n";
        }
        std::cerr << "WalletManager: noise leaf pointer moved from "
                  << before << " to " << after
                  << " to match the chain\n";
    }

    return after - before;
}

bool WalletManager::LoadNoiseFile(const std::string& passphrase) {
    std::lock_guard<std::mutex> lock(mMutex);

    fs::path noisePath = GetNoiseFilePath();
    if (!fs::exists(noisePath)) {
        return false;
    }

    std::vector<uint8_t> raw;
    if (!NoiseStore::DecryptFromFile(noisePath.string(), passphrase, raw)) {
        return false;
    }

    if (raw.size() != NetParams::NOISE_FILE_BYTES) {
        std::cerr << "WalletManager: noise file is "
                  << raw.size() << " bytes, expected "
                  << NetParams::NOISE_FILE_BYTES << "\n";
        memzero(raw.data(), raw.size());
        return false;
    }

    const uint32_t leafCount = NetParams::NOISE_LEAF_COUNT;

    try {
        NoiseFile nf = NoiseFile::Generate(raw, leafCount);
        memzero(raw.data(), raw.size());
        mNoiseKps = nf.GetRoot();
        mNoiseFile.reset(new NoiseFile(std::move(nf)));
        mNoiseFile->SetNextLeaf(mNoiseNextLeaf);
        mNoiseLoaded = true;
    } catch (const std::exception&) {
        memzero(raw.data(), raw.size());
        return false;
    }

    return true;
}

// Both readers take the mutex.
//
// They report on mNoiseLoaded, mNoiseKps and mNoiseFile, all of which
// LoadNoiseFile replaces while it runs. Reading them without the lock let
// an RPC call land in the middle of an unlock and see a root that no
// longer belonged to the pool being reported alongside it - or read
// mNoiseFile while the pointer it holds was being reseated.
//
// Neither is called from anywhere inside this class, so taking the lock
// here cannot recurse into itself.
const bytes32& WalletManager::GetNoiseKps() const {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mNoiseLoaded) {
        throw WalletError("Noise file not loaded");
    }
    return mNoiseKps;
}

uint32_t WalletManager::GetNoiseRemaining() const {
    std::lock_guard<std::mutex> lock(mMutex);
    if (!mNoiseLoaded || !mNoiseFile) {
        return 0;
    }
    return mNoiseFile->GetRemaining();
}

void WalletManager::AddTxRecord(
    const WalletTxRecord& record)
{
    std::lock_guard<std::mutex> lock(mMutex);
    mTxHistory.push_back(record);
    SaveToFile();
}

std::vector<WalletTxRecord>
WalletManager::GetTxHistory() const
{
    std::lock_guard<std::mutex> lock(mMutex);
    return mTxHistory;
}

bool WalletManager::Exists() const {
    return fs::exists(mWalletFile);
}

bool WalletManager::SaveToFile() const {
    std::vector<uint8_t> buf;

    auto put = [&buf](const void* p, size_t n) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        buf.insert(buf.end(), b, b + n);
    };
    auto put32 = [&put](uint32_t v) { put(&v, sizeof(v)); };

    put32(WALLET_VERSION);
    put(mMasterPubkey.data(), 32);
    put(mSalt.data(), SALT_SIZE);
    put(mIV.data(), IV_SIZE);
    put(mTag.data(), TAG_SIZE);

    put32(static_cast<uint32_t>(mEncryptedEntropy.size()));
    if (!mEncryptedEntropy.empty()) {
        put(mEncryptedEntropy.data(), mEncryptedEntropy.size());
    }

    put32(static_cast<uint32_t>(mAddresses.size()));
    for (const auto& addr : mAddresses) {
        put(addr.pubkeyHash.data(), 32);
        put(&addr.keyIndex, sizeof(addr.keyIndex));
        uint8_t isChange = addr.isChange ? 1 : 0;
        put(&isChange, 1);
        put32(static_cast<uint32_t>(addr.label.size()));
        if (!addr.label.empty()) {
            put(addr.label.data(), addr.label.size());
        }
    }

    put(&mNextKeyIndex, sizeof(mNextKeyIndex));
    put(&mNextChangeIndex, sizeof(mNextChangeIndex));
    put32(mNoiseNextLeaf);

    put32(0);

    const std::string tmpFile = mWalletFile.string() + ".tmp";

#ifndef WIN32
    ::unlink(tmpFile.c_str());
    int fd = ::open(tmpFile.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        std::cerr << "WalletManager: cannot create tmp wallet file\n";
        return false;
    }
    size_t off = 0;
    bool ok = true;
    while (off < buf.size()) {
        ssize_t n = ::write(fd, buf.data() + off, buf.size() - off);
        if (n <= 0) {
            if (errno == EINTR) continue;
            ok = false;
            break;
        }
        off += static_cast<size_t>(n);
    }
    if (ok && ::fsync(fd) != 0) ok = false;
    if (::close(fd) != 0) ok = false;
    if (!ok) {
        std::cerr << "WalletManager: error writing tmp wallet\n";
        ::unlink(tmpFile.c_str());
        return false;
    }
#else
    {
        std::ofstream file(tmpFile,
            std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            std::cerr << "WalletManager: cannot open "
                         "tmp wallet file\n";
            return false;
        }
        file.write(reinterpret_cast<const char*>(buf.data()),
                   static_cast<std::streamsize>(buf.size()));
        if (!file.good()) {
            std::cerr << "WalletManager: error writing "
                         "tmp wallet\n";
            file.close();
            fs::remove(tmpFile);
            return false;
        }
        file.flush();
    }
#endif

    boost::system::error_code ec;
    fs::rename(tmpFile, mWalletFile, ec);
    if (ec) {
        std::cerr << "WalletManager: atomic rename "
                     "failed: " << ec.message() << "\n";
        fs::remove(tmpFile, ec);
        return false;
    }

    return true;
}

bool WalletManager::LoadFromFile() {
    if (!fs::exists(mWalletFile)) {
        std::cerr << "WalletManager: wallet file "
                     "not found\n";
        return false;
    }

    std::ifstream file(mWalletFile.string(),
                       std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "WalletManager: cannot open "
                     "wallet file\n";
        return false;
    }

    uint32_t version = 0;
    file.read(reinterpret_cast<char*>(&version),
              sizeof(version));
    if (version != WALLET_VERSION) {
        throw WalletError(
            "Unsupported wallet version: " +
            std::to_string(version));
    }

    file.read(reinterpret_cast<char*>(
        mMasterPubkey.data()), 32);

    mSalt.resize(SALT_SIZE);
    file.read(reinterpret_cast<char*>(
        mSalt.data()), SALT_SIZE);

    mIV.resize(IV_SIZE);
    file.read(reinterpret_cast<char*>(
        mIV.data()), IV_SIZE);

    mTag.resize(TAG_SIZE);
    file.read(reinterpret_cast<char*>(
        mTag.data()), TAG_SIZE);

    uint32_t entropySize = 0;
    file.read(reinterpret_cast<char*>(&entropySize),
              sizeof(entropySize));
    if (entropySize == 0 ||
        entropySize > MAX_ENCRYPTED_ENTROPY_SIZE ||
        (entropySize % crypto::ENC_BLOCK_SIZE) != 0) {
        throw WalletError(
            "Invalid wallet file - bad encrypted entropy size");
    }

    mEncryptedEntropy.resize(entropySize);
    file.read(reinterpret_cast<char*>(
        mEncryptedEntropy.data()), entropySize);

    uint32_t addrCount = 0;
    file.read(reinterpret_cast<char*>(&addrCount),
              sizeof(addrCount));
    if (addrCount > MAX_ADDRESSES) {
        throw WalletError(
            "Invalid wallet file - too many addresses");
    }

    mAddresses.clear();
    mAddresses.reserve(addrCount);

    for (uint32_t i = 0; i < addrCount; ++i) {
        WalletAddress addr;

        file.read(reinterpret_cast<char*>(
            addr.pubkeyHash.data()), 32);
        file.read(reinterpret_cast<char*>(
            &addr.keyIndex), sizeof(addr.keyIndex));

        uint8_t isChange = 0;
        file.read(reinterpret_cast<char*>(
            &isChange), 1);
        addr.isChange = (isChange == 1);

        uint32_t labelLen = 0;
        file.read(reinterpret_cast<char*>(&labelLen),
                  sizeof(labelLen));
        if (labelLen > 256) {
            throw WalletError(
                "Invalid wallet file - label too long");
        }
        addr.label.resize(labelLen);
        file.read(&addr.label[0], labelLen);

        addr.address = BuildAddress(addr.pubkeyHash);
        mAddresses.push_back(addr);
    }

    file.read(reinterpret_cast<char*>(&mNextKeyIndex),
              sizeof(mNextKeyIndex));
    file.read(reinterpret_cast<char*>(&mNextChangeIndex),
              sizeof(mNextChangeIndex));

    file.read(reinterpret_cast<char*>(&mNoiseNextLeaf),
              sizeof(mNoiseNextLeaf));
    if (mNoiseNextLeaf > NetParams::NOISE_LEAF_COUNT) {
        throw WalletError(
            "Invalid wallet file - noise leaf pointer out of range");
    }

    uint32_t preparedCount = 0;
    file.read(reinterpret_cast<char*>(&preparedCount),
              sizeof(preparedCount));
    if (file.good() && preparedCount > 0) {
        if (preparedCount > MAX_ADDRESSES) {
            throw WalletError(
                "Invalid wallet file - stored record count implausible");
        }
        for (uint32_t i = 0; i < preparedCount; ++i) {
            char key[32];
            file.read(key, 32);
            uint32_t proofCount = 0;
            file.read(reinterpret_cast<char*>(&proofCount),
                      sizeof(proofCount));
            if (!file.good()) break;
            if (proofCount > NetParams::NOISE_LEAF_COUNT_VALUE) {
                throw WalletError(
                    "Invalid wallet file - stored proof count implausible");
            }
            for (uint32_t k = 0; k < proofCount; ++k) {
                uint32_t blobLen = 0;
                file.read(reinterpret_cast<char*>(&blobLen),
                          sizeof(blobLen));
                if (!file.good()) break;
                file.seekg(static_cast<std::streamoff>(blobLen),
                           std::ios::cur);
            }
        }
    }

    if (!file.good() && !file.eof()) {
        throw WalletError(
            "Error reading wallet file - may be corrupted");
    }

    std::cerr << "WalletManager: loaded "
              << mAddresses.size() << " addresses\n";
    return true;
}

std::string WalletManager::GetMnemonic(
    const std::string& passphrase) const
{
    std::lock_guard<std::mutex> lock(mMutex);

    std::vector<uint8_t> entropy;
    if (!DecryptEntropy(passphrase, entropy)) {
        throw WalletError("Wrong passphrase");
    }

    const char* mnemonic =
        mnemonic_from_data(entropy.data(),
                           static_cast<int>(entropy.size()));
    memzero(entropy.data(), entropy.size());

    if (!mnemonic) {
        throw WalletError("Failed to recover mnemonic");
    }

    std::string result(mnemonic);
    mnemonic_clear();
    return result;
}

std::string WalletManager::DumpPrivKey(
    const std::string& address,
    const std::string& passphrase) const
{
    std::lock_guard<std::mutex> lock(mMutex);

    WalletAddress wa;
    bool found = false;
    for (const auto& a : mAddresses) {
        if (a.address == address) {
            wa = a;
            found = true;
            break;
        }
    }
    if (!found) {
        throw WalletError("Address not found in this wallet");
    }

    std::vector<uint8_t> entropy;
    if (!DecryptEntropy(passphrase, entropy)) {
        throw WalletError("Wrong passphrase");
    }

    uint8_t seedBuf[64];
    if (!EntropyToSeed(entropy, seedBuf)) {
        memzero(entropy.data(), entropy.size());
        throw WalletError("Failed to derive seed");
    }
    memzero(entropy.data(), entropy.size());

    std::vector<uint8_t> seed(seedBuf, seedBuf + 64);
    memzero(seedBuf, sizeof(seedBuf));

    SecretKey sk = DeriveKeyAtIndex(seed, wa.keyIndex, wa.isChange);
    memzero(seed.data(), seed.size());

    return sk.GetStrKeySeed();
}

}
}
