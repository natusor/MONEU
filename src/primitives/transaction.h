// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#ifndef MONEU_PRIMITIVES_TRANSACTION_H
#define MONEU_PRIMITIVES_TRANSACTION_H

#include "keys.h"
#include "script.h"
#include <vector>
#include <string>
#include <cstdint>
#include <memory>

namespace MONEU {

class Transaction;
class TxInput;
class TxOutput;
using TransactionPtr = std::shared_ptr<Transaction>;

class TxInput {
private:
    bytes32 mPrevTxHash;
    uint32_t mOutputIndex;
    bytes32 mPubkey;
    bytes64 mSignature;
    bytes32 mKps;
    // Anti-quantum noise-OTP proof, stored as an opaque serialized blob so
    // the primitives layer carries it without depending on the wallet's
    // NoiseProof type. Empty for coinbase inputs (exempt). Excluded from the
    // transaction hash because the proof is bound to that hash.
    std::vector<uint8_t> mNoiseProof;
    
public:
    TxInput();
    TxInput(const bytes32& prevTxHash, uint32_t outputIndex, const bytes32& pubkey, const bytes64& signature);
    
    const bytes32& GetPrevTxHash() const { return mPrevTxHash; }
    uint32_t GetOutputIndex() const { return mOutputIndex; }
    const bytes32& GetPubkey() const { return mPubkey; }
    const bytes64& GetSignature() const { return mSignature; }
    const bytes32& GetKps() const { return mKps; }
    const std::vector<uint8_t>& GetNoiseProof() const { return mNoiseProof; }
    
    void SetPrevTxHash(const bytes32& hash) { mPrevTxHash = hash; }
    void SetOutputIndex(uint32_t index) { mOutputIndex = index; }
    void SetPubkey(const bytes32& pubkey) { mPubkey = pubkey; }
    void SetSignature(const bytes64& signature) { mSignature = signature; }
    void SetKps(const bytes32& kps) { mKps = kps; }
    void SetNoiseProof(const std::vector<uint8_t>& proof) { mNoiseProof = proof; }
    
    bool IsValid() const;
    size_t GetSerializedSize(bool withNoiseProof = true) const;
    std::vector<uint8_t> Serialize(bool withNoiseProof = true) const;
    static TxInput Deserialize(const uint8_t* data, size_t len, size_t& offset);
};

class TxOutput {
private:
    int64_t mValue;
    Script mScriptPubKey;
    
public:
    TxOutput();
    // Payment output: builds the standard pay-to-pubkey-hash script for the
    // noise-bound hash SHA256(pubkey || KPS).
    TxOutput(int64_t value, const bytes32& pubkeyHash);
    // Arbitrary script output (payment template, OP_RETURN data carrier).
    TxOutput(int64_t value, const Script& scriptPubKey);
    
    int64_t GetValue() const { return mValue; }
    const Script& GetScriptPubKey() const { return mScriptPubKey; }
    // For a payment output returns the noise-bound pubkey hash embedded in
    // the script; for any other script returns all zero bytes.
    bytes32 GetPubkeyHash() const;
    
    void SetValue(int64_t value) { mValue = value; }
    void SetScriptPubKey(const Script& script) { mScriptPubKey = script; }
    // Rebuilds the scriptPubKey as the standard payment template.
    void SetPubkeyHash(const bytes32& hash);
    
    bool IsValid() const;
    bool IsDust() const;
    // True when the script can never be spent (OP_RETURN data carrier).
    // Such outputs never enter the UTXO set.
    bool IsUnspendable() const { return mScriptPubKey.IsUnspendable(); }
    size_t GetSerializedSize() const;
    std::vector<uint8_t> Serialize() const;
    static TxOutput Deserialize(const uint8_t* data, size_t len, size_t& offset);
};

class Transaction {
private:
    uint32_t mVersion;
    std::vector<TxInput> mInputs;
    std::vector<TxOutput> mOutputs;
    uint64_t mLocktime;
    mutable bytes32 mTxHash;
    mutable bool mHashCached;
    
    void ComputeHash() const;
    
public:
    static constexpr uint32_t CURRENT_VERSION = 1;
    static constexpr size_t MAX_TX_SIZE = 100000;
    static constexpr size_t MAX_INPUTS = 1000;
    static constexpr size_t MAX_OUTPUTS = 1000;
    
    Transaction();
    explicit Transaction(uint32_t version);
    
    uint32_t GetVersion() const { return mVersion; }
    const std::vector<TxInput>& GetInputs() const { return mInputs; }
    const std::vector<TxOutput>& GetOutputs() const { return mOutputs; }
    uint64_t GetLocktime() const { return mLocktime; }
    const bytes32& GetHash() const;
    
    void SetVersion(uint32_t version) { mVersion = version; mHashCached = false; }
    void SetLocktime(uint64_t locktime) { mLocktime = locktime; mHashCached = false; }
    
    void AddInput(const TxInput& input);
    void AddOutput(const TxOutput& output);
    void ClearInputs();
    void ClearOutputs();
    
    size_t GetInputCount() const { return mInputs.size(); }
    size_t GetOutputCount() const { return mOutputs.size(); }
    
    bool IsCoinbase() const;
    bool IsValid() const;
    
    // Total value of the inputs this transaction spends. Requires the prevout
    // for each input (from the UTXO set), since input values are not stored in
    // the transaction itself. Zero for a coinbase.
    int64_t GetValueIn(const std::vector<TxOutput>& prevOutputs) const;
    int64_t GetValueOut() const;
    // Transaction fee: inputs minus outputs. Requires the prevouts. Zero for a
    // coinbase.
    int64_t GetFee(const std::vector<TxOutput>& prevOutputs) const;
    
    bool VerifySignature(size_t inputIndex, const TxOutput& prevOutput) const;
    bool VerifyAllSignatures(const std::vector<TxOutput>& prevOutputs) const;
    
    size_t GetSerializedSize(bool withNoiseProof = true) const;
    std::vector<uint8_t> Serialize(bool withNoiseProof = true) const;
    static Transaction Deserialize(const uint8_t* data, size_t len);
    static Transaction Deserialize(const std::vector<uint8_t>& data);
    
    std::string ToHex() const;
    static Transaction FromHex(const std::string& hex);
    
    bytes32 GetSignatureHash(size_t inputIndex) const;
    
    void Sign(size_t inputIndex, const SecretKey& key);
    void SignAll(const std::vector<SecretKey>& keys);
    
    bool operator==(const Transaction& other) const;
    bool operator!=(const Transaction& other) const;
};

class TransactionBuilder {
private:
    Transaction mTx;
    std::vector<TxOutput> mPrevOutputs;
    
public:
    TransactionBuilder();
    explicit TransactionBuilder(uint32_t version);
    
    // Every input and every payment output must carry a KPS. There is no
    // overload that omits it: an output paid to SHA256(pubkey) alone can
    // never be spent, because VerifySignature always recomputes the hash as
    // SHA256(pubkey || KPS), and an input with a zero KPS would fail the
    // same check. Leaving those variants available made it possible to burn
    // funds with a call that looked correct.
    TransactionBuilder& AddInput(const bytes32& prevTxHash, uint32_t outputIndex, const bytes32& pubkey, const bytes32& kps);
    // pubkeyHash must already be the noise-bound hash SHA256(pubkey || KPS),
    // which is what an address decodes to.
    TransactionBuilder& AddOutput(int64_t value, const bytes32& pubkeyHash);
    TransactionBuilder& AddOutput(int64_t value, const PublicKey& recipient, const bytes32& kps);
    // Zero-value OP_RETURN data carrier. The payload must not exceed
    // MAX_OP_RETURN_SIZE or validation will reject the transaction.
    TransactionBuilder& AddDataOutput(const std::vector<uint8_t>& data);
    TransactionBuilder& SetLocktime(uint64_t locktime);
    
    TransactionBuilder& SetPrevOutput(size_t inputIndex, const TxOutput& prevOutput);
    
    Transaction Build() const;
    Transaction BuildAndSign(const std::vector<SecretKey>& keys);
    Transaction BuildAndSign(const SecretKey& key);
};

}

#endif
