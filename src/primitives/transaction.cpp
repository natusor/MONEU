// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "transaction.h"
#include "../chainparams.h"
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>

extern "C" {
    #include "../crypto/sha2.h"
}

namespace MONEU {

static void WriteLE32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

static void WriteLE64(std::vector<uint8_t>& out, uint64_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 56) & 0xFF));
}

static uint32_t ReadLE32(const uint8_t* data, size_t& offset) {
    uint32_t value = static_cast<uint32_t>(data[offset]) |
                     (static_cast<uint32_t>(data[offset + 1]) << 8) |
                     (static_cast<uint32_t>(data[offset + 2]) << 16) |
                     (static_cast<uint32_t>(data[offset + 3]) << 24);
    offset += 4;
    return value;
}

static uint64_t ReadLE64(const uint8_t* data, size_t& offset) {
    uint64_t value = static_cast<uint64_t>(data[offset]) |
                     (static_cast<uint64_t>(data[offset + 1]) << 8) |
                     (static_cast<uint64_t>(data[offset + 2]) << 16) |
                     (static_cast<uint64_t>(data[offset + 3]) << 24) |
                     (static_cast<uint64_t>(data[offset + 4]) << 32) |
                     (static_cast<uint64_t>(data[offset + 5]) << 40) |
                     (static_cast<uint64_t>(data[offset + 6]) << 48) |
                     (static_cast<uint64_t>(data[offset + 7]) << 56);
    offset += 8;
    return value;
}

TxInput::TxInput() : mOutputIndex(0) {
    mPrevTxHash.fill(0);
    mPubkey.fill(0);
    mSignature.fill(0);
    mKps.fill(0);
}

TxInput::TxInput(const bytes32& prevTxHash, uint32_t outputIndex, const bytes32& pubkey, const bytes64& signature)
    : mPrevTxHash(prevTxHash), mOutputIndex(outputIndex), mPubkey(pubkey), mSignature(signature) {
    mKps.fill(0);
}

bool TxInput::IsValid() const {
    bool allZeroPrevHash = true;
    for (uint8_t byte : mPrevTxHash) {
        if (byte != 0) {
            allZeroPrevHash = false;
            break;
        }
    }
    if (allZeroPrevHash && mOutputIndex == 0xFFFFFFFF) {
        return true;
    }
    bool allZeroPubkey = true;
    for (uint8_t byte : mPubkey) {
        if (byte != 0) {
            allZeroPubkey = false;
            break;
        }
    }
    return !allZeroPubkey;
}

size_t TxInput::GetSerializedSize(bool withNoiseProof) const {
    size_t base = 32 + 4 + 32 + 64 + 32;
    if (withNoiseProof) {
        base += 4 + mNoiseProof.size();
    }
    return base;
}

std::vector<uint8_t> TxInput::Serialize(bool withNoiseProof) const {
    std::vector<uint8_t> data;
    data.reserve(GetSerializedSize(withNoiseProof));
    data.insert(data.end(), mPrevTxHash.begin(), mPrevTxHash.end());
    WriteLE32(data, mOutputIndex);
    data.insert(data.end(), mPubkey.begin(), mPubkey.end());
    data.insert(data.end(), mSignature.begin(), mSignature.end());
    data.insert(data.end(), mKps.begin(), mKps.end());
    if (withNoiseProof) {
        WriteLE32(data, static_cast<uint32_t>(mNoiseProof.size()));
        data.insert(data.end(), mNoiseProof.begin(), mNoiseProof.end());
    }
    return data;
}

TxInput TxInput::Deserialize(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 168 > len) {
        throw CryptoError("Insufficient data for TxInput");
    }
    TxInput input;
    std::memcpy(input.mPrevTxHash.data(), data + offset, 32);
    offset += 32;
    input.mOutputIndex = ReadLE32(data, offset);
    std::memcpy(input.mPubkey.data(), data + offset, 32);
    offset += 32;
    std::memcpy(input.mSignature.data(), data + offset, 64);
    offset += 64;
    std::memcpy(input.mKps.data(), data + offset, 32);
    offset += 32;
    uint32_t proofLen = ReadLE32(data, offset);
    if (proofLen > Transaction::MAX_TX_SIZE) {
        throw CryptoError("NoiseProof length implausible");
    }
    if (offset + proofLen > len) {
        throw CryptoError("Insufficient data for TxInput noise proof");
    }
    input.mNoiseProof.resize(proofLen);
    if (proofLen > 0) {
        std::memcpy(input.mNoiseProof.data(), data + offset, proofLen);
        offset += proofLen;
    }
    return input;
}

TxOutput::TxOutput() : mValue(0) {}

TxOutput::TxOutput(int64_t value, const bytes32& pubkeyHash)
    : mValue(value), mScriptPubKey(CreatePayToPubkeyHash(pubkeyHash)) {}

TxOutput::TxOutput(int64_t value, const Script& scriptPubKey)
    : mValue(value), mScriptPubKey(scriptPubKey) {}

bytes32 TxOutput::GetPubkeyHash() const {
    bytes32 hash;
    if (!ExtractPubkeyHash(mScriptPubKey, hash)) {
        hash.fill(0);
    }
    return hash;
}

void TxOutput::SetPubkeyHash(const bytes32& hash) {
    mScriptPubKey = CreatePayToPubkeyHash(hash);
}

bool TxOutput::IsValid() const {
    if (mValue < 0) return false;
    if (mScriptPubKey.empty()) return false;
    if (mScriptPubKey.size() > MAX_SCRIPT_SIZE) return false;
    return true;
}

bool TxOutput::IsDust() const {
    if (mScriptPubKey.IsUnspendable()) return false;
    return mValue < NetParams::DUST_THRESHOLD && mValue > 0;
}

static void WriteCompactSize(std::vector<uint8_t>& out, uint64_t value) {
    if (value < 253) {
        out.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xffff) {
        out.push_back(253);
        out.push_back(static_cast<uint8_t>(value & 0xff));
        out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    } else if (value <= 0xffffffff) {
        out.push_back(254);
        WriteLE32(out, static_cast<uint32_t>(value));
    } else {
        out.push_back(255);
        WriteLE64(out, value);
    }
}

static size_t CompactSizeLen(uint64_t value) {
    if (value < 253) return 1;
    if (value <= 0xffff) return 3;
    if (value <= 0xffffffff) return 5;
    return 9;
}

static uint64_t ReadCompactSize(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 1 > len) {
        throw CryptoError("Insufficient data for CompactSize");
    }
    uint8_t first = data[offset++];
    if (first < 253) return first;
    if (first == 253) {
        if (offset + 2 > len) {
            throw CryptoError("Insufficient data for CompactSize");
        }
        uint64_t v = static_cast<uint64_t>(data[offset]) |
                     (static_cast<uint64_t>(data[offset + 1]) << 8);
        offset += 2;
        return v;
    }
    if (first == 254) {
        if (offset + 4 > len) {
            throw CryptoError("Insufficient data for CompactSize");
        }
        return ReadLE32(data, offset);
    }
    if (offset + 8 > len) {
        throw CryptoError("Insufficient data for CompactSize");
    }
    return ReadLE64(data, offset);
}

size_t TxOutput::GetSerializedSize() const {
    return 8 + CompactSizeLen(mScriptPubKey.size()) + mScriptPubKey.size();
}

std::vector<uint8_t> TxOutput::Serialize() const {
    std::vector<uint8_t> data;
    data.reserve(GetSerializedSize());
    WriteLE64(data, static_cast<uint64_t>(mValue));
    WriteCompactSize(data, mScriptPubKey.size());
    data.insert(data.end(), mScriptPubKey.begin(), mScriptPubKey.end());
    return data;
}

TxOutput TxOutput::Deserialize(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 8 > len) {
        throw CryptoError("Insufficient data for TxOutput");
    }
    TxOutput output;
    output.mValue = static_cast<int64_t>(ReadLE64(data, offset));
    if (output.mValue < 0) {
        throw CryptoError("Negative output value");
    }
    uint64_t scriptLen = ReadCompactSize(data, len, offset);
    if (scriptLen > MAX_SCRIPT_SIZE) {
        throw CryptoError("scriptPubKey exceeds maximum script size");
    }
    if (offset + scriptLen > len) {
        throw CryptoError("Insufficient data for scriptPubKey");
    }
    output.mScriptPubKey = Script(data + offset, static_cast<size_t>(scriptLen));
    offset += static_cast<size_t>(scriptLen);
    return output;
}

Transaction::Transaction() : mVersion(CURRENT_VERSION), mLocktime(0), mHashCached(false) {
    mTxHash.fill(0);
}

Transaction::Transaction(uint32_t version) : mVersion(version), mLocktime(0), mHashCached(false) {
    mTxHash.fill(0);
}

void Transaction::ComputeHash() const {
    std::vector<uint8_t> serialized = Serialize(false);
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, serialized.data(), serialized.size());
    sha256_Final(&ctx, const_cast<uint8_t*>(mTxHash.data()));
    mHashCached = true;
}

const bytes32& Transaction::GetHash() const {
    if (!mHashCached) {
        ComputeHash();
    }
    return mTxHash;
}

void Transaction::AddInput(const TxInput& input) {
    if (mInputs.size() >= MAX_INPUTS) {
        throw CryptoError("Too many inputs");
    }
    mInputs.push_back(input);
    mHashCached = false;
}

void Transaction::AddOutput(const TxOutput& output) {
    if (mOutputs.size() >= MAX_OUTPUTS) {
        throw CryptoError("Too many outputs");
    }
    mOutputs.push_back(output);
    mHashCached = false;
}

void Transaction::ClearInputs() {
    mInputs.clear();
    mHashCached = false;
}

void Transaction::ClearOutputs() {
    mOutputs.clear();
    mHashCached = false;
}

bool Transaction::IsCoinbase() const {
    if (mInputs.size() != 1) return false;
    const TxInput& input = mInputs[0];
    bool allZero = true;
    for (uint8_t byte : input.GetPrevTxHash()) {
        if (byte != 0) {
            allZero = false;
            break;
        }
    }
    return allZero && input.GetOutputIndex() == 0xFFFFFFFF;
}

bool Transaction::IsValid() const {
    if (mInputs.empty() || mOutputs.empty()) return false;
    if (mInputs.size() > MAX_INPUTS) return false;
    if (mOutputs.size() > MAX_OUTPUTS) return false;
    if (GetSerializedSize() > MAX_TX_SIZE) return false;
    for (const auto& input : mInputs) {
        if (!input.IsValid()) return false;
    }
    for (const auto& output : mOutputs) {
        if (!output.IsValid()) return false;
        if (output.IsDust() && !IsCoinbase()) return false;
    }
    if (GetValueOut() < 0) return false;
    return true;
}

int64_t Transaction::GetValueIn(const std::vector<TxOutput>& prevOutputs) const {
    if (IsCoinbase()) return 0;
    if (prevOutputs.size() != mInputs.size()) {
        throw CryptoError("GetValueIn: prevOutputs size must match inputs");
    }
    int64_t total = 0;
    for (const auto& out : prevOutputs) {
        if (out.GetValue() < 0) {
            throw CryptoError("Negative input value");
        }
        if (total > INT64_MAX - out.GetValue()) {
            throw CryptoError("Input value overflow");
        }
        total += out.GetValue();
    }
    return total;
}

int64_t Transaction::GetValueOut() const {
    int64_t total = 0;
    for (const auto& output : mOutputs) {
        if (output.GetValue() < 0) {
            throw CryptoError("Negative output value");
        }
        if (total > INT64_MAX - output.GetValue()) {
            throw CryptoError("Output value overflow");
        }
        total += output.GetValue();
    }
    return total;
}

int64_t Transaction::GetFee(const std::vector<TxOutput>& prevOutputs) const {
    if (IsCoinbase()) return 0;
    return GetValueIn(prevOutputs) - GetValueOut();
}

bool Transaction::VerifySignature(size_t inputIndex, const TxOutput& prevOutput) const {
    if (inputIndex >= mInputs.size()) {
        throw CryptoError("Invalid input index");
    }
    const TxInput& input = mInputs[inputIndex];
    bytes32 sigHash = GetSignatureHash(inputIndex);
    PublicKey pubkey(input.GetPubkey());
    bytes32 pubkeyHash = NoiseBoundHash(pubkey, input.GetKps());
    if (pubkeyHash != prevOutput.GetPubkeyHash()) {
        return false;
    }
    return SecretKey::VerifySimple(pubkey, input.GetSignature(), sigHash.data(), sigHash.size());
}

bool Transaction::VerifyAllSignatures(const std::vector<TxOutput>& prevOutputs) const {
    if (prevOutputs.size() != mInputs.size()) {
        throw CryptoError("prevOutputs size must match inputs size");
    }
    for (size_t i = 0; i < mInputs.size(); ++i) {
        if (!VerifySignature(i, prevOutputs[i])) {
            return false;
        }
    }
    return true;
}

size_t Transaction::GetSerializedSize(bool withNoiseProof) const {
    size_t size = 4;
    size += 4;
    for (const auto& input : mInputs) {
        size += input.GetSerializedSize(withNoiseProof);
    }
    size += 4;
    for (const auto& output : mOutputs) {
        size += output.GetSerializedSize();
    }
    size += 8;
    return size;
}

std::vector<uint8_t> Transaction::Serialize(bool withNoiseProof) const {
    std::vector<uint8_t> data;
    data.reserve(GetSerializedSize(withNoiseProof));
    WriteLE32(data, mVersion);
    WriteLE32(data, static_cast<uint32_t>(mInputs.size()));
    for (const auto& input : mInputs) {
        std::vector<uint8_t> inputData = input.Serialize(withNoiseProof);
        data.insert(data.end(), inputData.begin(), inputData.end());
    }
    WriteLE32(data, static_cast<uint32_t>(mOutputs.size()));
    for (const auto& output : mOutputs) {
        std::vector<uint8_t> outputData = output.Serialize();
        data.insert(data.end(), outputData.begin(), outputData.end());
    }
    WriteLE64(data, mLocktime);
    return data;
}

Transaction Transaction::Deserialize(const uint8_t* data, size_t len) {
    size_t offset = 0;
    if (len < 20) {
        throw CryptoError("Transaction data too short");
    }
    Transaction tx;
    tx.mVersion = ReadLE32(data, offset);
    uint32_t inputCount = ReadLE32(data, offset);
    if (inputCount > MAX_INPUTS) {
        throw CryptoError("Too many inputs");
    }
    for (uint32_t i = 0; i < inputCount; ++i) {
        tx.mInputs.push_back(TxInput::Deserialize(data, len, offset));
    }
    if (offset + 4 > len) {
        throw CryptoError("Insufficient data for output count");
    }
    uint32_t outputCount = ReadLE32(data, offset);
    if (outputCount > MAX_OUTPUTS) {
        throw CryptoError("Too many outputs");
    }
    for (uint32_t i = 0; i < outputCount; ++i) {
        tx.mOutputs.push_back(TxOutput::Deserialize(data, len, offset));
    }
    if (offset + 8 > len) {
        throw CryptoError("Insufficient data for locktime");
    }
    tx.mLocktime = ReadLE64(data, offset);
    tx.mHashCached = false;
    return tx;
}

Transaction Transaction::Deserialize(const std::vector<uint8_t>& data) {
    return Deserialize(data.data(), data.size());
}

std::string Transaction::ToHex() const {
    std::vector<uint8_t> serialized = Serialize();
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : serialized) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

Transaction Transaction::FromHex(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw CryptoError("Invalid hex length");
    }
    std::vector<uint8_t> data;
    data.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte = hex.substr(i, 2);
        data.push_back(static_cast<uint8_t>(std::stoul(byte, nullptr, 16)));
    }
    return Deserialize(data);
}

bytes32 Transaction::GetSignatureHash(size_t inputIndex) const {
    if (inputIndex >= mInputs.size()) {
        throw CryptoError("Invalid input index");
    }
    std::vector<uint8_t> data;
    WriteLE32(data, mVersion);
    WriteLE32(data, static_cast<uint32_t>(mInputs.size()));
    const bytes64 zeroSig = {};
    for (size_t i = 0; i < mInputs.size(); ++i) {
        const TxInput& input = mInputs[i];
        data.insert(data.end(), input.GetPrevTxHash().begin(), input.GetPrevTxHash().end());
        WriteLE32(data, input.GetOutputIndex());
        data.insert(data.end(), input.GetPubkey().begin(), input.GetPubkey().end());
        data.insert(data.end(), zeroSig.begin(), zeroSig.end());
        data.insert(data.end(), input.GetKps().begin(), input.GetKps().end());
    }
    WriteLE32(data, static_cast<uint32_t>(mOutputs.size()));
    for (const auto& output : mOutputs) {
        std::vector<uint8_t> outData = output.Serialize();
        data.insert(data.end(), outData.begin(), outData.end());
    }
    WriteLE64(data, mLocktime);
    WriteLE32(data, static_cast<uint32_t>(inputIndex));
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, data.data(), data.size());
    bytes32 hash;
    sha256_Final(&ctx, hash.data());
    return hash;
}

void Transaction::Sign(size_t inputIndex, const SecretKey& key) {
    if (inputIndex >= mInputs.size()) {
        throw CryptoError("Invalid input index");
    }
    bytes32 sigHash = GetSignatureHash(inputIndex);
    bytes64 signature = key.Sign(sigHash.data(), sigHash.size());
    mInputs[inputIndex].SetSignature(signature);
    mInputs[inputIndex].SetPubkey(key.GetPublicKey().GetKey());
    mHashCached = false;
}

void Transaction::SignAll(const std::vector<SecretKey>& keys) {
    if (keys.size() != mInputs.size()) {
        throw CryptoError("Number of keys must match number of inputs");
    }
    for (size_t i = 0; i < keys.size(); ++i) {
        Sign(i, keys[i]);
    }
}

bool Transaction::operator==(const Transaction& other) const {
    return GetHash() == other.GetHash();
}

bool Transaction::operator!=(const Transaction& other) const {
    return !(*this == other);
}

TransactionBuilder::TransactionBuilder() : mTx(Transaction::CURRENT_VERSION) {}

TransactionBuilder::TransactionBuilder(uint32_t version) : mTx(version) {}

TransactionBuilder& TransactionBuilder::AddInput(const bytes32& prevTxHash, uint32_t outputIndex, const bytes32& pubkey, const bytes32& kps) {
    bytes64 emptySig;
    emptySig.fill(0);
    TxInput input(prevTxHash, outputIndex, pubkey, emptySig);
    input.SetKps(kps);
    mTx.AddInput(input);
    return *this;
}

TransactionBuilder& TransactionBuilder::AddOutput(int64_t value, const bytes32& pubkeyHash) {
    TxOutput output(value, pubkeyHash);
    mTx.AddOutput(output);
    return *this;
}

TransactionBuilder& TransactionBuilder::AddDataOutput(const std::vector<uint8_t>& data) {
    TxOutput output(0, CreateNullData(data));
    mTx.AddOutput(output);
    return *this;
}

TransactionBuilder& TransactionBuilder::AddOutput(int64_t value, const PublicKey& recipient, const bytes32& kps) {
    bytes32 pubkeyHash = NoiseBoundHash(recipient, kps);
    return AddOutput(value, pubkeyHash);
}

TransactionBuilder& TransactionBuilder::SetLocktime(uint64_t locktime) {
    mTx.SetLocktime(locktime);
    return *this;
}

TransactionBuilder& TransactionBuilder::SetPrevOutput(size_t inputIndex, const TxOutput& prevOutput) {
    if (inputIndex >= mPrevOutputs.size()) {
        mPrevOutputs.resize(inputIndex + 1);
    }
    mPrevOutputs[inputIndex] = prevOutput;
    return *this;
}

Transaction TransactionBuilder::Build() const {
    if (!mTx.IsValid()) {
        throw CryptoError("Invalid transaction");
    }
    return mTx;
}

Transaction TransactionBuilder::BuildAndSign(const std::vector<SecretKey>& keys) {
    mTx.SignAll(keys);
    if (!mTx.IsValid()) {
        throw CryptoError("Invalid transaction after signing");
    }
    return mTx;
}

Transaction TransactionBuilder::BuildAndSign(const SecretKey& key) {
    std::vector<SecretKey> keys;
    keys.push_back(key);
    return BuildAndSign(keys);
}

} // namespace MONEU
