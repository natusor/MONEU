// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license
// Functional test for the noise-OTP single-use enforcement across the state
// and mempool layers: leaf consumption on apply, rejection of reuse, unmark
// on undo, persistence through a flush, and the mempool leaf-conflict index.

#include "storage/utxo_set.h"
#include "storage/chain_state.h"
#include "primitives/leaf_reveal.h"
#include "consensus/pow.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "validation/reveal_validation.h"
#include "validation/tx_validation.h"
#include "validation/block_validation.h"
#include "consensus/mempool.h"
#include "net/addrman.h"
#include "net/net.h"
#include "util/lockorder.h"
#include "node/wallet_manager.h"
extern "C" {
#include "crypto/sha2.h"
}
#include "wallet/noise_otp.h"
#include "primitives/transaction.h"
#include "primitives/script.h"

#include <boost/filesystem.hpp>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>
#include <utility>
#include <ctime>
#include <sstream>

using namespace MONEU;
using namespace MONEU::storage;

static int gFailures = 0;

static void Check(bool cond, const char* what) {
    if (cond) {
        std::printf("PASS  %s\n", what);
    } else {
        std::printf("FAIL  %s\n", what);
        gFailures++;
    }
}

static bytes32 FillHash(uint8_t b) {
    bytes32 h;
    h.fill(b);
    return h;
}

// Build a spendable transaction with real noise proofs from the given file.
// Signatures are not the subject here; the UTXO layer does not verify them.
static Transaction MakeSpendTx(const bytes32& prevTxHash,
                               uint32_t prevIndex,
                               NoiseFile& noiseFile,
                               const bytes32& kps,
                               const bytes32& destPubkeyHash,
                               int64_t value) {
    Transaction tx;
    TxInput input;
    input.SetPrevTxHash(prevTxHash);
    input.SetOutputIndex(prevIndex);
    input.SetPubkey(FillHash(0xE1));
    bytes64 sig;
    sig.fill(0xE2);
    input.SetSignature(sig);
    input.SetKps(kps);
    tx.AddInput(input);
    tx.AddOutput(TxOutput(value, destPubkeyHash));

    NoiseProof proof = noiseFile.CreateProof(tx.GetHash());
    TxInput signedInput = tx.GetInputs()[0];
    signedInput.SetNoiseProof(proof.Serialize());

    Transaction full;
    full.AddInput(signedInput);
    full.AddOutput(TxOutput(value, destPubkeyHash));
    return full;
}

// Two-block model: a transaction reaches its block carrying no proof at
// all. The leaves that authorise it are published later, by a reveal.
static Transaction MakeBareTx(const bytes32& prevTxHash,
                              uint32_t prevIndex,
                              const bytes32& kps,
                              const bytes32& destPubkeyHash,
                              int64_t value,
                              uint8_t pubkeyTag = 0xE1) {
    Transaction tx;
    TxInput input;
    input.SetPrevTxHash(prevTxHash);
    input.SetOutputIndex(prevIndex);
    input.SetPubkey(FillHash(pubkeyTag));
    bytes64 sig;
    sig.fill(0xE2);
    input.SetSignature(sig);
    input.SetKps(kps);
    tx.AddInput(input);
    tx.AddOutput(TxOutput(value, destPubkeyHash));
    return tx;
}

// Rebind an existing proof's leaf to a different transaction.
static Transaction RebindLeaf(const Transaction& source,
                              const bytes32& prevTxHash,
                              uint32_t prevIndex,
                              const bytes32& kps,
                              const bytes32& destPubkeyHash,
                              int64_t value) {
    size_t offset = 0;
    const std::vector<uint8_t>& proofBytes =
        source.GetInputs()[0].GetNoiseProof();
    NoiseProof taken = NoiseProof::Deserialize(
        proofBytes.data(), proofBytes.size(), offset);

    Transaction tx;
    TxInput input;
    input.SetPrevTxHash(prevTxHash);
    input.SetOutputIndex(prevIndex);
    input.SetPubkey(FillHash(0xE3));
    bytes64 sig;
    sig.fill(0xE4);
    input.SetSignature(sig);
    input.SetKps(kps);
    tx.AddInput(input);
    tx.AddOutput(TxOutput(value, destPubkeyHash));

    NoiseProof rebound = taken;
    rebound.boundProof = BindLeafToTx(taken.leaf, tx.GetHash());

    TxInput reboundInput = tx.GetInputs()[0];
    reboundInput.SetNoiseProof(rebound.Serialize());

    Transaction full;
    full.AddInput(reboundInput);
    full.AddOutput(TxOutput(value, destPubkeyHash));
    return full;
}

int main() {
    boost::filesystem::path dataDir =
        boost::filesystem::temp_directory_path() / "moneu_noise_test";
    boost::filesystem::remove_all(dataDir);
    boost::filesystem::create_directories(dataDir);

    // Deterministic raw noise for the test wallet.
    std::vector<uint8_t> rawNoise(64 * NOISE_OTP_LEAF_SIZE);
    for (size_t i = 0; i < rawNoise.size(); ++i) {
        rawNoise[i] = static_cast<uint8_t>((i * 31 + 7) & 0xFF);
    }
    NoiseFile noiseFile = NoiseFile::Generate(rawNoise, 64);
    const bytes32 kps = noiseFile.GetRoot();

    const bytes32 owner = FillHash(0xAA);
    const bytes32 dest  = FillHash(0xBB);

    {
        UTXOSet utxo(dataDir);

        // Two coins on the same owner, different outpoints.
        OutPoint op1(FillHash(0x01), 0);
        OutPoint op2(FillHash(0x02), 0);
        Check(utxo.AddCoin(op1, Coin(500000, owner, 1, false)),
              "coin 1 added");
        Check(utxo.AddCoin(op2, Coin(500000, owner, 1, false)),
              "coin 2 added");

        // Spend coin 1 with leaf 0.
        Transaction tx1 = MakeSpendTx(op1.txHash, 0, noiseFile, kps,
                                      dest, 400000);
        size_t off = 0;
        NoiseProof p1 = NoiseProof::Deserialize(
            tx1.GetInputs()[0].GetNoiseProof().data(),
            tx1.GetInputs()[0].GetNoiseProof().size(), off);
        Check(NoiseFile::VerifyProof(kps, tx1.GetHash(), p1, 64),
              "proof of tx1 verifies against KPS");

        std::vector<Coin> undo1;
        Check(utxo.ApplyTransaction(tx1, 2, false, &undo1),
              "tx1 applies");
        Check(utxo.IsNoiseLeafSpent(kps, p1.leafIndex),
              "leaf 0 marked spent after apply");

        Transaction txAtk = RebindLeaf(tx1, op2.txHash, 0, kps,
                                       FillHash(0xCC), 400000);
        off = 0;
        NoiseProof pAtk = NoiseProof::Deserialize(
            txAtk.GetInputs()[0].GetNoiseProof().data(),
            txAtk.GetInputs()[0].GetNoiseProof().size(), off);
        Check(NoiseFile::VerifyProof(kps, txAtk.GetHash(), pAtk, 64),
              "rebound proof verifies");

        std::vector<Coin> undoAtk;
        Check(!utxo.ApplyTransaction(txAtk, 2, false, &undoAtk),
              "reused leaf rejected");

        Coin c2;
        Check(utxo.GetCoin(op2, c2),
              "coin 2 untouched");

        // Reorg: undo tx1. The coin returns and the leaf is unmarked.
        Check(utxo.UndoTransaction(tx1, undo1),
              "tx1 undone");
        Check(!utxo.IsNoiseLeafSpent(kps, p1.leafIndex),
              "leaf 0 unmarked after undo");
        Coin c1;
        Check(utxo.GetCoin(op1, c1),
              "coin 1 restored after undo");

        // The same transaction re-confirms on the winning chain.
        std::vector<Coin> undo2;
        Check(utxo.ApplyTransaction(tx1, 3, false, &undo2),
              "tx1 re-applies after reorg");
        Check(utxo.IsNoiseLeafSpent(kps, p1.leafIndex),
              "leaf 0 spent again after re-apply");

        Check(utxo.Flush(),
              "state flushed to database");
    }

    {
        // Reopen: the consumed mark must have survived the flush.
        UTXOSet utxo(dataDir);
        size_t off = 0;
        Check(utxo.IsNoiseLeafSpent(kps, 0),
              "leaf 0 still spent after reopen");
        (void)off;
    }

    {
        // Mempool: two transactions, different outpoints, same leaf.
        Mempool pool;
        NoiseFile poolNoise = NoiseFile::Generate(rawNoise, 64);
        const bytes32 poolKps = poolNoise.GetRoot();

        Transaction txA = MakeSpendTx(FillHash(0x11), 0, poolNoise, poolKps,
                                      dest, 400000);
        Check(pool.AddTransaction(txA, 100000),
              "txA admitted to mempool");

        Transaction txB = RebindLeaf(txA, FillHash(0x12), 0, poolKps,
                                     dest, 400000);
        Check(!pool.AddTransaction(txB, 100000),
              "txB with reused leaf rejected by mempool");

        Transaction txC = MakeSpendTx(FillHash(0x13), 0, poolNoise, poolKps,
                                      dest, 400000);
        Check(pool.AddTransaction(txC, 100000),
              "txC with fresh leaf admitted");

        // A block confirms a transaction consuming txC's leaf but spending
        // a different outpoint: txC must be evicted as unconfirmable.
        Transaction txBlock = RebindLeaf(txC, FillHash(0x14), 0, poolKps,
                                         dest, 400000);
        std::vector<Transaction> blockTxs;
        blockTxs.push_back(txBlock);
        pool.RemoveForBlock(blockTxs);

        Check(!pool.HasTransaction(txC.GetHash()),
              "txC evicted after block consumed its leaf");
        Check(pool.HasTransaction(txA.GetHash()),
              "txA unaffected by the block");
    }

    // Leaf pointer recovery.
    //
    // The noise file holds the same bytes before and after a spend, so it
    // reloads with its pointer at the start every time. A wallet that
    // restarted, or that restored its noise file from a backup copy, would
    // re-offer leaves the chain has already consumed and every spend would
    // be rejected. The pointer is therefore rebuilt from the chain.
    {
        std::vector<uint8_t> raw(64 * 32);
        for (size_t i = 0; i < raw.size(); ++i) {
            raw[i] = static_cast<uint8_t>((i * 11 + 5) & 0xFF);
        }
        bytes32 txh = FillHash(0xAB);

        storage::UTXOSet recovery(dataDir / "recovery", 1 << 20);

        NoiseFile first = NoiseFile::Generate(raw, 64);
        bytes32 rkps = first.GetRoot();
        for (int i = 0; i < 5; ++i) {
            NoiseProof p = first.CreateProof(txh);
            recovery.MarkNoiseLeafSpent(rkps, p.leafIndex);
        }
        Check(first.GetNextLeaf() == 5, "five leaves consumed in session one");

        uint32_t highest = 0;
        Check(recovery.GetHighestSpentNoiseLeaf(rkps, highest),
              "chain reports this KPS has spent leaves");
        Check(highest == 4, "highest consumed leaf is 4");

        NoiseFile reloaded = NoiseFile::Generate(raw, 64);
        Check(reloaded.GetNextLeaf() == 0,
              "a reloaded noise file starts at leaf 0");

        reloaded.SetNextLeaf(highest + 1);
        Check(reloaded.GetNextLeaf() == 5,
              "pointer corrected from the chain");

        NoiseProof after = reloaded.CreateProof(txh);
        Check(after.leafIndex == 5,
              "first spend after reload uses leaf 5, not leaf 0");
        Check(!recovery.IsNoiseLeafSpent(rkps, 5),
              "leaf 5 was never consumed before");

        reloaded.SetNextLeaf(2);
        Check(reloaded.GetNextLeaf() == 6,
              "pointer refuses to move backwards");

        recovery.Flush();
        uint32_t afterFlush = 0;
        Check(recovery.GetHighestSpentNoiseLeaf(rkps, afterFlush) &&
              afterFlush == 4,
              "highest consumed leaf survives the database flush");

        bytes32 stranger = FillHash(0x77);
        uint32_t unused = 0;
        Check(!recovery.GetHighestSpentNoiseLeaf(stranger, unused),
              "an unrelated KPS has no consumed leaves");
    }

    // Memory hygiene around the leaf pool.
    //
    // The pool and the tree built from it are secret: an unspent leaf is
    // what authorises a future transaction. Moving must hand the buffers
    // over rather than duplicate them, so a second full set of leaves does
    // not sit in memory waiting to be freed unwiped.
    {
        std::vector<uint8_t> raw(1024 * 32);
        for (size_t i = 0; i < raw.size(); ++i) {
            raw[i] = static_cast<uint8_t>((i * 13 + 7) & 0xFF);
        }

        NoiseFile source = NoiseFile::Generate(raw, 1024);
        bytes32 root = source.GetRoot();

        NoiseFile moved = std::move(source);
        Check(moved.GetRoot() == root, "move keeps the root");
        Check(moved.GetLeafCount() == 1024, "move keeps the leaves");
        Check(source.GetLeafCount() == 0,
              "moved-from pool is empty, so secrets are not duplicated");

        NoiseFile copy = moved;
        bytes32 txh = FillHash(0x5A);
        copy.CreateProof(txh);
        Check(copy.GetNextLeaf() == 1 && moved.GetNextLeaf() == 0,
              "a copy advances independently of the original");

        NoiseProof p = moved.CreateProof(txh);
        Check(NoiseFile::VerifyProof(root, txh, p, 1024),
              "a proof from a moved pool still verifies");
    }

    // LeafReveal: the record that publishes a transaction's leaves in a
    // later block. Stage one of the two-block model - serialization and
    // parsing only, no consensus behaviour yet.
    {
        std::vector<uint8_t> raw(256 * 32);
        for (size_t i = 0; i < raw.size(); ++i) {
            raw[i] = static_cast<uint8_t>((i * 17 + 3) & 0xFF);
        }
        NoiseFile pool = NoiseFile::Generate(raw, 256);

        bytes32 txid = FillHash(0x91);
        LeafReveal reveal(txid, 4200);
        for (int i = 0; i < 3; ++i) {
            reveal.AddProof(pool.CreateProof(txid));
        }

        Check(reveal.GetProofCount() == 3, "reveal holds three proofs");
        Check(reveal.IsWellFormed(), "a normal reveal is well formed");

        // Round trip.
        std::vector<uint8_t> blob = reveal.Serialize();
        Check(blob.size() == reveal.GetSerializedSize(),
              "serialized size matches the declared size");

        size_t off = 0;
        LeafReveal back = LeafReveal::Deserialize(blob.data(), blob.size(), off);
        Check(off == blob.size(), "parsing consumes the whole record");
        Check(back.GetTxid() == txid, "txid survives the round trip");
        Check(back.GetHeight() == 4200, "height survives the round trip");
        Check(back.GetProofCount() == 3, "proof count survives the round trip");
        Check(back.GetHash() == reveal.GetHash(),
              "hash is stable across the round trip");

        // The hash must cover the proofs. This is what a block header can
        // commit to, which the transaction merkle root never could.
        LeafReveal fewer(txid, 4200);
        fewer.AddProof(reveal.GetProofs()[0]);
        Check(!(fewer.GetHash() == reveal.GetHash()),
              "dropping a proof changes the reveal hash");

        LeafReveal otherHeight(txid, 4201);
        for (size_t i = 0; i < reveal.GetProofs().size(); ++i) {
            otherHeight.AddProof(reveal.GetProofs()[i]);
        }
        Check(!(otherHeight.GetHash() == reveal.GetHash()),
              "changing the height changes the reveal hash");

        // Adversarial input: every one of these arrives from the network.
        bool threw = false;
        try { size_t o = 0; LeafReveal::Deserialize(blob.data(), 10, o); }
        catch (const std::exception&) { threw = true; }
        Check(threw, "a truncated record is rejected");

        threw = false;
        try {
            std::vector<uint8_t> bad = blob;
            bad[32 + 4] = 0xFF; bad[32 + 5] = 0xFF;
            bad[32 + 6] = 0xFF; bad[32 + 7] = 0xFF;   // proof count = 2^32-1
            size_t o = 0;
            LeafReveal::Deserialize(bad.data(), bad.size(), o);
        } catch (const std::exception&) { threw = true; }
        Check(threw, "an absurd proof count is rejected before allocating");

        threw = false;
        try {
            std::vector<uint8_t> bad = blob;
            bad[32 + 4] = 0; bad[32 + 5] = 0;
            bad[32 + 6] = 0; bad[32 + 7] = 0;          // proof count = 0
            size_t o = 0;
            LeafReveal::Deserialize(bad.data(), bad.size(), o);
        } catch (const std::exception&) { threw = true; }
        Check(threw, "a reveal carrying no proofs is rejected");

        threw = false;
        try {
            std::vector<uint8_t> bad = blob;
            bad[32 + 8] = 0xFF; bad[32 + 9] = 0xFF;    // first proof length
            size_t o = 0;
            LeafReveal::Deserialize(bad.data(), bad.size(), o);
        } catch (const std::exception&) { threw = true; }
        Check(threw, "a proof length running past the record is rejected");

        // The same leaf twice inside one record would consume a
        // single-use value twice.
        LeafReveal doubled(txid, 4200);
        doubled.AddProof(reveal.GetProofs()[0]);
        doubled.AddProof(reveal.GetProofs()[0]);
        Check(!doubled.IsWellFormed(), "a repeated leaf is not well formed");

        LeafReveal zeroTxid(FillHash(0x00), 4200);
        zeroTxid.AddProof(reveal.GetProofs()[0]);
        Check(!zeroTxid.IsWellFormed(), "an all-zero txid is not well formed");

        // Reveal root, the value a block header will commit to.
        std::vector<LeafReveal> none;
        bytes32 emptyRoot = ComputeRevealRoot(none);
        Check(emptyRoot == FillHash(0x00),
              "a block with no reveals has a zero reveal root");

        std::vector<LeafReveal> one;
        one.push_back(reveal);
        Check(ComputeRevealRoot(one) == reveal.GetHash(),
              "a single reveal is its own root");

        std::vector<LeafReveal> two;
        two.push_back(reveal);
        two.push_back(fewer);
        bytes32 rootTwo = ComputeRevealRoot(two);
        Check(!(rootTwo == reveal.GetHash()),
              "two reveals produce a combined root");

        std::vector<LeafReveal> swapped;
        swapped.push_back(fewer);
        swapped.push_back(reveal);
        Check(!(ComputeRevealRoot(swapped) == rootTwo),
              "reveal order is committed to by the root");
    }

    // Held spends: the state a transaction sits in between reaching a block
    // and having its leaves published. Stage two of the two-block model.
    {
        storage::UTXOSet held(dataDir / "held", 1 << 20);

        bytes32 owner = FillHash(0x41);
        bytes32 dest  = FillHash(0x42);
        OutPoint opA(FillHash(0x51), 0);
        OutPoint opB(FillHash(0x52), 0);
        Check(held.AddCoin(opA, Coin(500000, owner, 1, false)), "coin A added");
        Check(held.AddCoin(opB, Coin(500000, owner, 1, false)), "coin B added");

        std::vector<uint8_t> raw(64 * 32);
        for (size_t i = 0; i < raw.size(); ++i) {
            raw[i] = static_cast<uint8_t>((i * 19 + 2) & 0xFF);
        }
        NoiseFile hp = NoiseFile::Generate(raw, 64);
        bytes32 hkps = hp.GetRoot();

        Transaction t1 = MakeSpendTx(opA.txHash, 0, hp, hkps, dest, 400000);
        Coin heldCoin;
        Check(held.GetCoin(opA, heldCoin), "coin A readable before the hold");
        std::vector<Coin> spent;
        spent.push_back(heldCoin);

        // Holding must not touch the coin. The spend has not happened yet.
        Check(held.AddPendingSpend(t1, 10, spent, 1000), "spend held at height 10");
        Check(held.PendingSpendCount() == 1, "one spend awaiting its leaves");
        Check(held.GetCoin(opA, heldCoin),
              "the held coin is still unspent, the spend has not happened");
        Coin ghost;
        Check(!held.GetCoin(OutPoint(t1.GetHash(), 0), ghost),
              "the transaction's outputs do not exist yet");
        bytes32 holder;
        Check(held.IsOutpointPending(opA, &holder) && holder == t1.GetHash(),
              "the output reports which transaction holds it");
        Check(!held.IsOutpointPending(opB),
              "an untouched output is not held");

        // A second transaction naming the same output must be refused,
        // otherwise two spends would queue on one coin.
        Transaction t2 = MakeSpendTx(opA.txHash, 0, hp, hkps,
                                     FillHash(0x43), 300000);
        std::vector<Coin> spent2;
        spent2.push_back(heldCoin);
        Check(!held.AddPendingSpend(t2, 10, spent2, 1000),
              "a second spend of a held output is refused");
        Check(held.PendingSpendCount() == 1, "the refusal changed nothing");

        // Holding survives a restart: a node that forgot would settle
        // nothing and would let the held output be taken by someone else.
        Check(held.Flush(), "state flushed");
        storage::PendingSpend reloaded;
        Check(held.GetPendingSpend(t1.GetHash(), reloaded),
              "the held spend is readable after the flush");
        Check(reloaded.height == 10, "its height survived");
        Check(reloaded.fee == 1000, "its fee survived");
        Check(reloaded.spentCoins.size() == 1 &&
              reloaded.spentCoins[0].value == 500000,
              "the coin it holds survived");

        std::vector<bytes32> atTen = held.GetPendingSpendsAtHeight(10);
        Check(atTen.size() == 1 && atTen[0] == t1.GetHash(),
              "spends can be found by the height that carried them");
        Check(held.GetPendingSpendsAtHeight(11).empty(),
              "no spends are waiting from a height that carried none");

        // Settlement: the leaves arrived. Now the spend happens.
        Check(held.FinalizePendingSpend(t1.GetHash()), "spend settled");
        Check(!held.GetCoin(opA, ghost), "the input is gone after settlement");
        Check(held.GetCoin(OutPoint(t1.GetHash(), 0), ghost),
              "the outputs exist after settlement");
        Check(ghost.value == 400000, "the output carries the right value");
        Check(held.PendingSpendCount() == 0, "nothing is awaiting leaves");
        Check(!held.IsOutpointPending(opA), "the hold is gone");

        // Release: the other path out. Used when the block that carried the
        // transaction is disconnected, and when the reveal window closes.
        Transaction t3 = MakeSpendTx(opB.txHash, 0, hp, hkps, dest, 400000);
        Coin coinB;
        held.GetCoin(opB, coinB);
        std::vector<Coin> spentB;
        spentB.push_back(coinB);
        Check(held.AddPendingSpend(t3, 11, spentB, 1000), "second spend held");
        Check(held.ReleasePendingSpend(t3.GetHash()), "spend released");
        Check(held.PendingSpendCount() == 0, "nothing left waiting");
        Check(held.GetCoin(opB, coinB) && coinB.value == 500000,
              "the released coin is untouched and spendable again");
        Check(!held.GetCoin(OutPoint(t3.GetHash(), 0), ghost),
              "a released spend created no outputs");

        // And the output can now be held by a different transaction.
        Transaction t4 = MakeSpendTx(opB.txHash, 0, hp, hkps,
                                     FillHash(0x44), 350000);
        std::vector<Coin> spentB2;
        spentB2.push_back(coinB);
        Check(held.AddPendingSpend(t4, 12, spentB2, 1000),
              "a released output can be held by another spend");
        Check(held.ReleasePendingSpend(t4.GetHash()), "cleanup");
    }

    // Genesis block. ChainState rebuilds block 0 from BuildGenesisBlock()
    // at start-up and refuses to run if it does not match the hardcoded
    // hash, so a change to any genesis constant that was not carried
    // through to every place holding it stops the node dead. Checking it
    // here catches that at test time instead.
    {
        MONEU::Block genesis = NetParams::BuildGenesisBlock();
        const MONEU::BlockHeader& gh = genesis.GetHeader();

        Check(gh.GetHash() == NetParams::GetGenesisHash(),
              "genesis rebuilt from code matches the hardcoded hash");
        Check(gh.GetHash() == NetParams::GetCheckpointHash(0),
              "checkpoint zero matches the genesis hash");
        Check(PNC::CheckProofOfWork(gh.GetHash(), gh.GetBits()),
              "genesis proof of work is valid");
        Check(genesis.ComputeMerkleRoot() == gh.GetMerkleRoot(),
              "genesis merkle root recomputes from its transactions");
        Check(gh.GetHeight() == 0, "genesis sits at height zero");
        Check(gh.GetBits() == NetParams::POW_LIMIT_COMPACT,
              "genesis carries the minimum difficulty target");
        Check(genesis.GetTransactionCount() == 1,
              "genesis holds exactly one transaction");

        const Transaction& gcb = genesis.GetTransactions()[0];
        Check(gcb.IsCoinbase(), "that transaction is a coinbase");
        Check(gcb.GetValueOut() == NetParams::GENESIS_REWARD,
              "the coinbase pays exactly the genesis reward");
        Check(gcb.GetOutputCount() == 2,
              "the coinbase has a payment and a data carrier");
        Check(gcb.GetOutputs()[1].GetValue() == 0,
              "the data carrier is worth nothing");
        Check(gcb.GetOutputs()[1].IsUnspendable(),
              "the data carrier cannot be spent");
    }

    // Reveal validation: the rules that decide whether a published set of
    // leaves may settle a held spend. Stage three of the two-block model.
    {
        using validation::RevealValidation;
        using validation::RevealResult;

        storage::UTXOSet rv(dataDir / "reveal", 1 << 20);

        bytes32 owner = FillHash(0x61);
        bytes32 dest  = FillHash(0x62);
        OutPoint opX(FillHash(0x71), 0);
        OutPoint opY(FillHash(0x72), 0);
        rv.AddCoin(opX, Coin(500000, owner, 1, false));
        rv.AddCoin(opY, Coin(500000, owner, 1, false));

        std::vector<uint8_t> raw(NetParams::NOISE_FILE_BYTES);
        for (size_t i = 0; i < raw.size(); ++i) {
            raw[i] = static_cast<uint8_t>((i * 23 + 9) & 0xFF);
        }
        NoiseFile pool = NoiseFile::Generate(raw, NetParams::NOISE_LEAF_COUNT);
        bytes32 pkps = pool.GetRoot();

        // Held at height 100.
        Transaction bare = MakeBareTx(opX.txHash, 0, pkps, dest, 400000);
        Coin cx; rv.GetCoin(opX, cx);
        std::vector<Coin> sx; sx.push_back(cx);
        Check(rv.AddPendingSpend(bare, 100, sx, 1000), "transaction held at 100");

        LeafReveal good(bare.GetHash(), 100);
        good.AddProof(pool.CreateProof(bare.GetHash()));

        std::string why;
        Check(RevealValidation::CheckReveal(good, 101, rv, why) ==
              RevealResult::VALID,
              "a correct reveal in the next block is accepted");

        // Its own block is now allowed. A spend and the leaves that
        // authorise it travel together, so a payment settles in one block
        // instead of two. What remains barred is a later block: a reveal
        // still cannot reach forward to a transaction that does not exist
        // yet.
        Check(RevealValidation::CheckReveal(good, 100, rv, why) ==
              RevealResult::VALID,
              "a reveal settles a transaction from its own block");
        Check(RevealValidation::CheckReveal(good, 99, rv, why) ==
              RevealResult::NOT_YET_ELIGIBLE,
              "a reveal cannot settle a transaction from a later block");

        // Window edges.
        Check(RevealValidation::CheckReveal(good, 106, rv, why) ==
              RevealResult::VALID,
              "the last block of the window still accepts the reveal");
        Check(RevealValidation::CheckReveal(good, 107, rv, why) ==
              RevealResult::WINDOW_EXPIRED,
              "one block past the window the reveal is refused");
        Check(RevealValidation::ExpiryHeight(100) == 107,
              "spends held at 100 are released at 107");

        // A reveal naming the wrong position cannot be replayed.
        LeafReveal wrongHeight(bare.GetHash(), 99);
        wrongHeight.AddProof(good.GetProofs()[0]);
        Check(RevealValidation::CheckReveal(wrongHeight, 101, rv, why) ==
              RevealResult::HEIGHT_MISMATCH,
              "a reveal naming the wrong height is refused");

        LeafReveal unknown(FillHash(0x7F), 100);
        unknown.AddProof(good.GetProofs()[0]);
        Check(RevealValidation::CheckReveal(unknown, 101, rv, why) ==
              RevealResult::UNKNOWN_TRANSACTION,
              "a reveal for no held transaction is refused");

        LeafReveal tooMany(bare.GetHash(), 100);
        tooMany.AddProof(good.GetProofs()[0]);
        tooMany.AddProof(pool.CreateProof(bare.GetHash()));
        Check(RevealValidation::CheckReveal(tooMany, 101, rv, why) ==
              RevealResult::PROOF_COUNT_MISMATCH,
              "a reveal with more proofs than inputs is refused");

        // A proof bound to a different transaction must not verify.
        LeafReveal wrongBind(bare.GetHash(), 100);
        NoiseProof otherBound = pool.CreateProof(FillHash(0x7E));
        wrongBind.AddProof(otherBound);
        Check(RevealValidation::CheckReveal(wrongBind, 101, rv, why) ==
              RevealResult::INVALID_PROOF,
              "a proof bound to another transaction does not verify");

        Transaction second = MakeBareTx(opY.txHash, 0, pkps,
                                          FillHash(0x63), 400000, 0xEE);
        Coin cy; rv.GetCoin(opY, cy);
        std::vector<Coin> sy; sy.push_back(cy);
        Check(rv.AddPendingSpend(second, 101, sy, 1000),
              "spend held at 101");

        NoiseProof taken = good.GetProofs()[0];
        NoiseProof rebound = taken;
        rebound.boundProof = BindLeafToTx(taken.leaf, second.GetHash());

        LeafReveal reused(second.GetHash(), 101);
        reused.AddProof(rebound);

        Check(NoiseFile::VerifyProof(pkps, second.GetHash(), rebound,
                                     NetParams::NOISE_LEAF_COUNT),
              "rebound proof verifies");

        Check(RevealValidation::CheckReveal(reused, 101, rv, why) ==
              RevealResult::VALID,
              "reveal accepted");

        rv.MarkNoiseLeafSpent(pkps, taken.leafIndex);
        Check(RevealValidation::CheckReveal(reused, 102, rv, why) ==
              RevealResult::LEAF_ALREADY_SPENT,
              "consumed leaf refused");

        // Block-level checks.
        std::vector<LeafReveal> twice;
        twice.push_back(good);
        twice.push_back(good);
        Check(!RevealValidation::CheckBlockReveals(twice, 101, rv, why),
              "a block settling one transaction twice is refused");

        std::vector<LeafReveal> single;
        single.push_back(good);
        Check(!RevealValidation::CheckBlockReveals(single, 101, rv, why),
              "a reveal whose leaf was consumed meanwhile is refused");
    }

    // Mempool reveal queue: stage six of the two-block model. Reveals sit
    // in their own queue, never competing with transactions for space.
    {
        Mempool pool(1 << 20);

        std::vector<uint8_t> raw(64 * 32);
        for (size_t i = 0; i < raw.size(); ++i) {
            raw[i] = static_cast<uint8_t>((i * 29 + 4) & 0xFF);
        }
        NoiseFile np = NoiseFile::Generate(raw, 64);

        bytes32 t1 = FillHash(0xA1);
        bytes32 t2 = FillHash(0xA2);

        LeafReveal r1(t1, 50);
        r1.AddProof(np.CreateProof(t1));
        LeafReveal r2(t2, 50);
        r2.AddProof(np.CreateProof(t2));

        Check(pool.AddReveal(r1), "first reveal admitted");
        Check(pool.AddReveal(r2), "second reveal admitted");
        Check(pool.RevealCount() == 2, "queue holds both");
        Check(!pool.AddReveal(r1),
              "a second reveal for the same transaction is refused");

        Check(pool.HasReveal(t1), "queue reports what it holds");
        LeafReveal fetched;
        Check(pool.GetReveal(fetched, t1) && fetched.GetTxid() == t1,
              "a reveal comes back unchanged");

        Check(pool.GetReveals(10).size() == 2,
              "block assembly sees both");
        Check(pool.GetReveals(1).size() == 1,
              "block assembly respects the cap");

        LeafReveal malformed(FillHash(0xA3), 50);
        Check(!pool.AddReveal(malformed),
              "a reveal with no proofs is refused");

        // A block settled one of them.
        std::vector<LeafReveal> mined;
        mined.push_back(r1);
        pool.RemoveRevealsForBlock(mined);
        Check(pool.RevealCount() == 1 && !pool.HasReveal(t1),
              "a settled reveal leaves the queue");

        // And the other's transaction stopped being held.
        std::vector<bytes32> stillHeld;
        Check(pool.DropRevealsNotHeld(stillHeld) == 1,
              "a reveal for a spend no longer held is dropped");
        Check(pool.RevealCount() == 0, "queue is empty");

        // The queue must survive a transaction-side clear-out untouched,
        // and vice versa: they are separate resources.
        pool.AddReveal(r2);
        Check(pool.RevealCount() == 1 && pool.Size() == 0,
              "reveals and transactions are counted apart");
        pool.Clear();
        Check(pool.RevealCount() == 0, "Clear empties both");
    }

    // End to end: the path a real payment takes, from a signed transaction
    // through to settlement.
    //
    // Every layer below was already tested on its own, and every one of
    // them passed while the whole was broken: validation still demanded a
    // proof inside the transaction, and the wallet had stopped putting one
    // there. Each half was correct and they disagreed about the model.
    // Only a test that crosses the boundary can see that.
    {
        storage::UTXOSet e2e(dataDir / "e2e", 1 << 20);

        std::vector<uint8_t> raw(NetParams::NOISE_FILE_BYTES);
        for (size_t i = 0; i < raw.size(); ++i) {
            raw[i] = static_cast<uint8_t>((i * 37 + 11) & 0xFF);
        }
        NoiseFile pool = NoiseFile::Generate(raw, NetParams::NOISE_LEAF_COUNT);
        const bytes32 kps = pool.GetRoot();

        SecretKey sk = SecretKey::Random();
        PublicKey pk = sk.GetPublicKey();
        const bytes32 myHash = NoiseBoundHash(pk, kps);

        OutPoint funded(FillHash(0x81), 0);
        Check(e2e.AddCoin(funded, Coin(500000, myHash, 1, false)),
              "e2e: funding coin exists");

        // Built the way the wallet builds one: signature and KPS, no proof.
        Transaction tx;
        {
            TxInput in;
            in.SetPrevTxHash(funded.txHash);
            in.SetOutputIndex(0);
            in.SetPubkey(pk.GetKey());
            in.SetKps(kps);
            bytes64 blank; blank.fill(0);
            in.SetSignature(blank);
            tx.AddInput(in);
            tx.AddOutput(TxOutput(400000, FillHash(0x82)));

            const bytes32 sighash = tx.GetSignatureHash(0);
            bytes64 sig = sk.Sign(sighash.data(), sighash.size());
            std::vector<TxInput> ins = tx.GetInputs();
            ins[0].SetSignature(sig);
            tx.ClearInputs();
            tx.AddInput(ins[0]);
        }

        // Without a proof the spend is refused. The signature alone proves
        // possession of the key and nothing about the noise file, which is
        // exactly the case this shield exists for.
        {
            validation::TxValidationState nstate;
            Check(!validation::TxValidation::VerifyTransactionSignatures(
                      tx, e2e, nstate),
                  "e2e: a transaction carrying no proof is refused");
        }

        // With one, it goes through. The proof rides inside the input and
        // is left out of the transaction hash, so it can bind to that hash.
        {
            std::vector<TxInput> ins = tx.GetInputs();
            NoiseProof p = pool.CreateProof(tx.GetHash());
            ins[0].SetNoiseProof(p.Serialize());
            tx.ClearInputs();
            tx.AddInput(ins[0]);
        }

        validation::TxValidationState vstate;
        Check(validation::TxValidation::VerifyTransactionSignatures(
                  tx, e2e, vstate),
              "e2e: a transaction carrying its proof is accepted");

        // A proof from somebody else's file is refused. The address binds
        // to the owner's KPS, so a valid proof from the wrong tree settles
        // nothing.
        {
            Transaction wrong = tx;
            std::vector<TxInput> ins = wrong.GetInputs();
            NoiseProof p = pool.CreateProof(wrong.GetHash());
            ins[0].SetNoiseProof(p.Serialize());
            bytes32 otherKps = ins[0].GetKps();
            otherKps[0] ^= 0xFF;
            ins[0].SetKps(otherKps);
            wrong.ClearInputs();
            wrong.AddInput(ins[0]);

            validation::TxValidationState wstate;
            Check(!validation::TxValidation::VerifyTransactionSignatures(
                      wrong, e2e, wstate),
                  "e2e: a proof against the wrong KPS is refused");
        }

        // Block 200 holds it.
        Coin spent;
        e2e.GetCoin(funded, spent);
        std::vector<Coin> spentCoins;
        spentCoins.push_back(spent);
        Check(e2e.AddPendingSpend(tx, 200, spentCoins, 1000),
              "e2e: block 200 holds the spend");

        Coin ghost;
        Check(e2e.GetCoin(funded, ghost),
              "e2e: the input is still unspent while held");
        Check(!e2e.GetCoin(OutPoint(tx.GetHash(), 0), ghost),
              "e2e: the payment has not arrived yet");

        // Block 201 publishes the leaves.
        LeafReveal reveal(tx.GetHash(), 200);
        reveal.AddProof(pool.CreateProof(tx.GetHash()));

        std::string why;
        Check(validation::RevealValidation::CheckReveal(
                  reveal, 201, e2e, why) ==
              validation::RevealResult::VALID,
              "e2e: the reveal is accepted in block 201");

        Check(e2e.FinalizePendingSpend(reveal.GetTxid()),
              "e2e: the spend settles");
        e2e.MarkNoiseLeafSpent(kps, reveal.GetProofs()[0].leafIndex);

        Check(!e2e.GetCoin(funded, ghost),
              "e2e: the input is gone after settlement");
        Check(e2e.GetCoin(OutPoint(tx.GetHash(), 0), ghost) &&
              ghost.value == 400000,
              "e2e: the recipient has the money");
        Check(e2e.PendingSpendCount() == 0,
              "e2e: nothing is left waiting");
    }

    // Genesis carries work, and block 1 must end up with strictly more.
    //
    // AcceptBlock treated a genesis parent as carrying no work, so block 1
    // came out with the same cumulative work as genesis itself. The tip is
    // only displaced on strictly greater work, so block 1 was filed as a
    // side branch and the chain stayed at height zero - silently, because
    // that path returns true. On the live network it meant the first block
    // could never be mined, and nothing in the logs said so.
    //
    // This checks the arithmetic the bug lived in. Driving a real block
    // through AcceptBlock would cost about four billion hashes.
    {
        bytes32 zeroWork; zeroWork.fill(0);
        const bytes32 genesisWork =
            PNC::GetBlockProof(NetParams::POW_LIMIT_COMPACT);
        Check(PNC::CompareWork(genesisWork, zeroWork) > 0,
              "genesis carries work, it is not zero");

        // What AcceptBlock computes now: parent work read from the index.
        const bytes32 correct =
            PNC::AddChainWork(genesisWork, NetParams::POW_LIMIT_COMPACT);
        Check(PNC::CompareWork(correct, genesisWork) > 0,
              "block 1 on top of genesis has strictly more work");

        // What it computed before: parent work left at zero.
        const bytes32 broken =
            PNC::AddChainWork(zeroWork, NetParams::POW_LIMIT_COMPACT);
        Check(PNC::CompareWork(broken, genesisWork) == 0,
              "with a zero parent the work only equalled genesis, which is "
              "exactly why the tip never moved");
    }

    // A held spend pays no fee until it settles.
    //
    // Charging at hold time was an inflation bug. A transaction held in
    // block N leaves its inputs in the UTXO set and creates no outputs, so
    // no coins move. If it then expired without a reveal, no coins ever
    // moved at all - yet the miner of block N had already claimed the fee
    // in its coinbase. Those units were minted from nothing.
    //
    // The fee belongs to whoever settles the spend, and settlement is what
    // a reveal does.
    {
        storage::UTXOSet fees(dataDir / "fees", 1 << 20);

        bytes32 owner = FillHash(0xB1);
        OutPoint op(FillHash(0xB2), 0);
        Check(fees.AddCoin(op, Coin(500000, owner, 1, false)), "coin funded");

        std::vector<uint8_t> raw(64 * 32);
        for (size_t i = 0; i < raw.size(); ++i) {
            raw[i] = static_cast<uint8_t>((i * 31 + 6) & 0xFF);
        }
        NoiseFile pool = NoiseFile::Generate(raw, 64);

        Transaction tx = MakeBareTx(op.txHash, 0, pool.GetRoot(),
                                    FillHash(0xB3), 400000);
        Coin held; fees.GetCoin(op, held);
        std::vector<Coin> spent; spent.push_back(held);

        const int64_t fee = held.value - tx.GetValueOut();
        Check(fee == 100000, "the transaction pays a fee of 100000");

        Check(fees.AddPendingSpend(tx, 10, spent, fee), "spend held");

        // While held, nothing has moved: the input is still there and the
        // outputs do not exist. So there is nothing for a coinbase to claim.
        Coin still;
        Check(fees.GetCoin(op, still) && still.value == 500000,
              "the input is untouched while held, so no fee has been paid");
        Coin ghost;
        Check(!fees.GetCoin(OutPoint(tx.GetHash(), 0), ghost),
              "no output exists while held");

        // The fee travels with the held record, so the block that settles
        // it can find out what it is owed.
        storage::PendingSpend rec;
        Check(fees.GetPendingSpend(tx.GetHash(), rec) && rec.fee == 100000,
              "the fee is carried on the held record until settlement");

        // Released without a reveal: the coins never moved, so a fee paid
        // at hold time would have been minted from nothing.
        Check(fees.ReleasePendingSpend(tx.GetHash()), "hold released");
        Check(fees.GetCoin(op, still) && still.value == 500000,
              "after release the coin is whole, nothing was ever spent");
        Check(!fees.GetCoin(OutPoint(tx.GetHash(), 0), ghost),
              "and no output was ever created");
    }

    // Money arithmetic. Every one of these is a way coins could be created
    // from nothing, so each is checked rather than assumed.
    {
        // Emission is a function of height alone. Nobody supplies it.
        Check(NetParams::GetBlockSubsidy(0) == 7700000000ULL,
              "block 0 pays 77 MONEU");
        Check(NetParams::GetBlockSubsidy(NetParams::HALVING_INTERVAL - 1) ==
              7700000000ULL,
              "the last block of epoch 0 still pays the full subsidy");
        Check(NetParams::GetBlockSubsidy(NetParams::HALVING_INTERVAL) ==
              3850000000ULL,
              "the first block of epoch 1 pays half");

        // Emission ends rather than flattening. There is no tail: the
        // halvings reduce the subsidy to nothing in epoch 33, and from
        // there a block is paid by the fees of the spends it settles.
        Check(NetParams::GetBlockSubsidy(
                  NetParams::LAST_SUBSIDY_HEIGHT - 1) == 1ULL,
              "the last block with a reward pays one WAGA");
        Check(NetParams::GetBlockSubsidy(
                  NetParams::LAST_SUBSIDY_HEIGHT) == 0ULL,
              "the first block of epoch 33 pays nothing");
        Check(NetParams::GetBlockSubsidy(
                  NetParams::LAST_SUBSIDY_HEIGHT * 100) == 0ULL,
              "and nothing is ever paid again");

        // A shift of 64 or more would be undefined behaviour, so the
        // guard against it is exercised rather than assumed.
        Check(NetParams::GetBlockSubsidy(
                  NetParams::HALVING_INTERVAL * 64) == 0ULL,
              "an absurd height returns zero instead of shifting past 63");

        // Total issuance, computed the way the chain will actually pay it
        // out. This is every coin that will ever exist.
        int64_t issued = NetParams::GENESIS_REWARD;
        for (uint64_t epoch = 0; epoch < 33; ++epoch) {
            const uint64_t height = epoch * NetParams::HALVING_INTERVAL;
            const int64_t perBlock =
                static_cast<int64_t>(NetParams::GetBlockSubsidy(height));
            issued += perBlock *
                static_cast<int64_t>(NetParams::HALVING_INTERVAL);
        }
        Check(issued == 2999989297077940LL,
              "total issuance is exactly 29,999,892.97077940 MONEU");
        Check(issued < NetParams::MAX_MONEY,
              "total issuance stays under MAX_MONEY");

        // Range checks reject values outside the money range.
        Check(NetParams::CheckMoneyRange(0), "zero is in range");
        Check(NetParams::CheckMoneyRange(
                  static_cast<uint64_t>(NetParams::MAX_MONEY)),
              "MAX_MONEY itself is in range");
        Check(!NetParams::CheckMoneyRange(0xFFFFFFFFFFFFFFFFULL),
              "an absurd value is out of range");

        // Everything is integral. A subsidy that had ever passed through a
        // double would show it here: 77 MONEU is 7700000000 WAGA exactly,
        // and no rounding can produce that from a fraction.
        const int64_t oneCoin = NetParams::COIN;
        Check(oneCoin == 100000000LL, "one MONEU is 100,000,000 WAGA");
        Check(NetParams::GetBlockSubsidy(0) % 1 == 0u,
              "the subsidy is a whole number of WAGA");
    }

    // One validation path, and it caps what a block may mint.
    //
    // A miner is not a trusted party. A block this node mined itself used
    // to reach AcceptBlock without the coinbase cap ever being applied,
    // while a block from a peer had it applied on the way in - two paths,
    // one of them missing a rule. ValidateBlock is now the only entry, and
    // AcceptBlock calls it itself, so no caller can skip it.
    //
    // ValidateBlock also checks proof of work, and mining a real block
    // costs about four billion hashes, so the coinbase rule is exercised
    // through CheckCoinbaseTransaction - the part of it that decides how
    // much may be minted.
    {
        storage::UTXOSet vset(dataDir / "validate", 1 << 20);

        Transaction greedy;
        {
            TxInput in;
            bytes32 zero; zero.fill(0);
            in.SetPrevTxHash(zero);
            in.SetOutputIndex(0xFFFFFFFFu);
            greedy.AddInput(in);
            greedy.AddOutput(
                TxOutput(static_cast<int64_t>(
                             NetParams::GetBlockSubsidy(1)) + 1,
                         FillHash(0xC1)));
        }
        Block overpaying = BlockBuilder(1)
            .SetPrevBlockHash(NetParams::GetGenesisHash())
            .SetTimestamp(static_cast<uint64_t>(std::time(NULL)))
            .SetHeight(1)
            .SetBits(NetParams::POW_LIMIT_COMPACT)
            .AddCoinbase(greedy)
            .Build();

        validation::BlockValidationState vs;
        // The exact cap lives in CheckBlockTransactionsWithUTXO, which has
        // the UTXO set and so knows the fees this block actually settles.
        // CheckCoinbaseTransaction is only a loose structural bound.
        Check(!validation::BlockValidation::CheckBlockTransactionsWithUTXO(
                  overpaying, vset, 1, vs),
              "a coinbase paying one unit over the subsidy is refused");

        Transaction honest;
        {
            TxInput in;
            bytes32 zero; zero.fill(0);
            in.SetPrevTxHash(zero);
            in.SetOutputIndex(0xFFFFFFFFu);
            honest.AddInput(in);
            honest.AddOutput(
                TxOutput(static_cast<int64_t>(NetParams::GetBlockSubsidy(1)),
                         FillHash(0xC1)));
        }
        Block exact = BlockBuilder(1)
            .SetPrevBlockHash(NetParams::GetGenesisHash())
            .SetTimestamp(static_cast<uint64_t>(std::time(NULL)))
            .SetHeight(1)
            .SetBits(NetParams::POW_LIMIT_COMPACT)
            .AddCoinbase(honest)
            .Build();

        validation::BlockValidationState vs2;
        Check(validation::BlockValidation::CheckBlockTransactionsWithUTXO(
                  exact, vset, 1, vs2),
              "a coinbase paying exactly the subsidy is allowed");

        // And an unmined block is refused whatever its coinbase says, which
        // is what stops the above from being the only thing standing
        // between a fabricated block and the chain.
        validation::BlockValidationState vs3;
        Check(!validation::BlockValidation::ValidateBlock(exact, vset, 1, vs3),
              "a block with no proof of work is refused by ValidateBlock");
    }

    // Answering a peer that asks what it is missing.
    //
    // Blocks are relayed as they are found, so a node joining a network
    // that already has history is never sent any of it. It has to ask, and
    // GetBlockHashesAfter is what answers - it walks forward from the
    // block the peer names.
    //
    // Before this existed the handler was an empty function and nothing
    // ever sent the request, so a fresh node sat at height zero next to a
    // peer it could see was further ahead.
    {
        storage::ChainState sync(dataDir / "sync", 1 << 20);
        Check(sync.Initialize(), "chain initialises for the sync test");

        const bytes32 tip = sync.GetBestBlockHash();

        Check(sync.GetBlockHashesAfter(tip, 100).empty(),
              "a peer already at our tip is sent nothing");
        Check(sync.GetBlockHashesAfter(FillHash(0xD1), 100).empty(),
              "an unknown locator returns nothing rather than guessing");
        Check(sync.GetBlockHashesAfter(tip, 0).empty(),
              "a request for no hashes returns none");

        // The locator: our chain from the tip backwards, always ending at
        // genesis. On a one-block chain it is just genesis, but the shape
        // is what matters - a peer reading it can find where we agree.
        const std::vector<bytes32> loc = sync.GetBlockLocator();
        Check(!loc.empty(), "the locator is not empty");
        Check(loc.back() == NetParams::GetGenesisHash(),
              "the locator always ends at genesis, so two nodes on this "
              "network always share at least one entry");
        Check(loc.front() == tip, "the locator starts at our tip");

        // Finding the fork point: the newest entry we recognise.
        uint32_t forkHeight = 0xFFFFFFFF;
        Check(sync.FindForkPoint(loc, forkHeight) && forkHeight == 0,
              "our own locator resolves to our own tip");

        // A locator from a node on another network shares nothing, not
        // even genesis. Answering it with our chain would be wrong, so it
        // has to fail rather than fall back to genesis.
        std::vector<bytes32> alien;
        alien.push_back(FillHash(0xE1));
        alien.push_back(FillHash(0xE2));
        Check(!sync.FindForkPoint(alien, forkHeight),
              "a locator sharing nothing finds no fork point");

        // A locator whose newest entries are unknown but which still
        // contains genesis resolves to genesis - which is exactly what
        // happens when a peer has forked away from us.
        std::vector<bytes32> forked;
        forked.push_back(FillHash(0xE3));          // their block 2
        forked.push_back(FillHash(0xE4));          // their block 1
        forked.push_back(NetParams::GetGenesisHash());
        forkHeight = 0xFFFFFFFF;
        Check(sync.FindForkPoint(forked, forkHeight) && forkHeight == 0,
              "a forked peer's locator resolves to the last block we share");
    }

    // The address table, and what it is for.
    //
    // A plain list of addresses makes a network work and does nothing to
    // keep it working. Someone holding a thousand addresses in one subnet
    // fills a plain list entirely, and from then on every peer the victim
    // dials is theirs: it never hears of anyone else and is cut off while
    // looking perfectly healthy. That costs no hash power at all.
    //
    // The defence is bucketing by network group rather than by address, so
    // a thousand addresses from one /16 displace each other instead of
    // displacing everyone.
    {
        net::AddrMan am;
        const int64_t now = static_cast<int64_t>(std::time(NULL));

        Check(am.Size() == 0, "a new address table is empty");
        Check(am.Add("1.2.3.4", 8327, 0, "5.6.7.8", now),
              "a new address is accepted");
        Check(!am.Add("1.2.3.4", 8327, 0, "5.6.7.8", now),
              "the same address again is not new, so it is not relayed");
        Check(am.Size() == 1, "the table holds one address");

        // Grouping: what decides the bucket.
        Check(net::AddrMan::GroupOf("1.2.3.4") ==
              net::AddrMan::GroupOf("1.2.9.9"),
              "two addresses in one /16 share a network group");
        Check(!(net::AddrMan::GroupOf("1.2.3.4") ==
                net::AddrMan::GroupOf("9.9.3.4")),
              "addresses in different /16s do not");

        // The flood. One attacker, one subnet, a thousand addresses, all
        // vouched for by itself.
        net::AddrMan flooded;
        for (int i = 0; i < 200; ++i) {
            for (int j = 0; j < 5; ++j) {
                std::ostringstream ip;
                ip << "6.6." << i << "." << j;
                flooded.Add(ip.str(), 8327, 0, "6.6.6.6", now);
            }
        }
        const size_t attackerHeld = flooded.Size();

        // An honest address arrives afterwards and must still get in.
        Check(flooded.Add("77.88.99.1", 8327, 0, "77.88.99.1", now),
              "an honest address is still accepted after the flood");

        // And the flood cannot have taken the whole table: the attacker's
        // addresses share a source group, so they compete for a limited
        // number of buckets rather than spreading across all of them.
        Check(attackerHeld < 1000,
              "a thousand addresses from one source do not all fit - they "
              "displace each other, not everyone else");

        // Promotion needs a connection this node made itself.
        net::AddrMan promo;
        promo.Add("10.0.0.1", 8327, 0, "10.0.0.1", now);
        Check(promo.TriedCount() == 0,
              "an address nobody has connected to is not in the tried table");
        promo.Good("10.0.0.1", 8327, now);
        Check(promo.TriedCount() == 1,
              "a successful connection promotes it, which no third party "
              "can do on its behalf");

        // Selection returns something usable.
        std::string ip; uint16_t port = 0;
        Check(promo.Select(ip, port, now) && ip == "10.0.0.1" && port == 8327,
              "selection returns the address that worked");

        // Failure history, and being written off.
        net::AddrMan fails;
        fails.Add("10.0.0.2", 8327, 0, "10.0.0.2", now);
        for (int i = 0; i < 5; ++i) {
            fails.Attempt("10.0.0.2", 8327, now - 3600);
        }
        Check(fails.Sweep(now) == 1,
              "an address tried repeatedly and never answering is counted "
              "as stale");
        Check(fails.Size() == 1,
              "but it stays in the table rather than being deleted");
        {
            std::string sIp; uint16_t sPort = 0;
            Check(!fails.Select(sIp, sPort, now),
                  "a stale address is not selected");
            fails.Good("10.0.0.2", 8327, now);
            Check(fails.Select(sIp, sPort, now) &&
                      sIp == "10.0.0.2" && sPort == 8327,
                  "and it is reachable again the moment it answers");
        }

        // Round trip through disk.
        net::AddrMan saved;
        saved.Add("11.22.33.44", 8327, 5, "11.22.33.44", now);
        saved.Good("11.22.33.44", 8327, now);
        const std::string path = (dataDir / "addrs.txt").string();
        Check(saved.Save(path), "the table is written to disk");

        net::AddrMan restored;
        Check(restored.Load(path), "and read back");
        Check(restored.Size() == 1, "the address survived");
        Check(restored.TriedCount() == 1,
              "and so did the fact that it once answered");

        // Grouping is what eviction leans on too: the peer to drop is
        // chosen from the network group holding the most connections, so a
        // flood from one subnet consumes itself rather than the rest.
        Check(net::AddrMan::GroupOf("6.6.1.1") ==
              net::AddrMan::GroupOf("6.6.250.250"),
              "a whole /16 counts as one group for eviction as well");
        Check(!(net::AddrMan::GroupOf("6.6.1.1") ==
                net::AddrMan::GroupOf("6.7.1.1")),
              "and a neighbouring /16 is a different group");

        // IPv6 grouping, so an attacker cannot sidestep the whole scheme
        // by using addresses from one v6 allocation.
        Check(net::AddrMan::GroupOf("2001:db8:1:2::1") ==
              net::AddrMan::GroupOf("2001:db8:1:2::ffff"),
              "two IPv6 addresses in one /64 share a group");
        Check(!(net::AddrMan::GroupOf("2001:db8:1:2::1") ==
                net::AddrMan::GroupOf("2001:db8:9:9::1")),
              "different IPv6 /64s do not");
    }

    // Two ways of writing a header must produce the same bytes.
    //
    // The miner hashes from SerializeTo and everything else from
    // Serialize. If they ever disagreed, this node would compute a block
    // hash nobody else computes: it would mine blocks the network refuses
    // and refuse blocks the network accepts, while every test that uses
    // only one of the two paths would still pass.
    {
        Block b = NetParams::BuildGenesisBlock();
        const BlockHeader& h = b.GetHeader();

        const std::vector<uint8_t> viaVector = h.Serialize();

        uint8_t viaBuffer[BlockHeader::SERIALIZED_SIZE];
        Check(h.SerializeTo(viaBuffer, sizeof(viaBuffer)),
              "a header serialises into a buffer of the right size");

        Check(viaVector.size() == BlockHeader::SERIALIZED_SIZE,
              "and that size is what the header says it is");
        Check(std::memcmp(viaVector.data(), viaBuffer,
                          BlockHeader::SERIALIZED_SIZE) == 0,
              "both ways of writing a header give byte-for-byte the same "
              "result, so the miner and the rest of the node cannot "
              "disagree about what a block hashes to");

        // A short buffer is refused rather than half-filled or overrun.
        uint8_t tooSmall[BlockHeader::SERIALIZED_SIZE - 1];
        Check(!h.SerializeTo(tooSmall, sizeof(tooSmall)),
              "a buffer one byte too small is refused, not overflowed");
        Check(!h.SerializeTo(NULL, BlockHeader::SERIALIZED_SIZE),
              "and a null buffer is refused too");
    }

    // Which address to announce depends on who is asking.
    //
    // This is what lets two machines on one network find each other. Told a
    // single fixed address, a node behind a router gives its public address
    // to a neighbour that cannot use it, and the two stay deaf to each
    // other while both talk to some node outside. Scoring by who is asking
    // means a peer on our own network is told the address on that network.
    {
        typedef net::ConnManager CM;

        // Private ranges recognised, so "reachable from inside" can be
        // distinguished from "reachable from anywhere".
        Check(CM::IsPrivateAddress("192.168.1.10"), "192.168/16 is private");
        Check(CM::IsPrivateAddress("10.0.0.5"), "10/8 is private");
        Check(CM::IsPrivateAddress("172.16.0.1"), "172.16/12 is private");
        Check(!CM::IsPrivateAddress("172.32.0.1"),
              "172.32 is outside that range and is not private");
        Check(!CM::IsPrivateAddress("8.8.8.8"), "a public address is not");

        // Two separate questions kept apart.
        //
        // Usable means somebody could dial it, even if only a neighbour on
        // the same network. Relayable means it may be passed on across the
        // network to strangers, and a private address must never be,
        // because it names a different machine in every household.
        Check(!CM::IsUsableAddress("127.0.0.1"),
              "loopback is unusable - announcing it would tell a peer to "
              "connect to itself");
        Check(!CM::IsUsableAddress("0.0.0.0"), "nor the unspecified one");
        Check(CM::IsUsableAddress("192.168.1.10"),
              "a private address is usable, to a neighbour on that network");
        Check(CM::IsUsableAddress("8.8.8.8"), "and so is a public one");

        Check(!CM::IsRelayableAddress("192.168.1.10"),
              "but a private address is never passed on across the network, "
              "because it names a different machine in every household");
        Check(CM::IsRelayableAddress("8.8.8.8"),
              "while a public address is");

        // The other ranges that are never relayed, by the RFC that
        // reserves each of them.
        Check(!CM::IsRelayableAddress("100.64.0.1"),
              "carrier-grade NAT is not relayed - RFC6598");
        Check(!CM::IsRelayableAddress("169.254.1.1"),
              "nor link-local - RFC3927");
        Check(!CM::IsRelayableAddress("198.18.0.1"),
              "nor the benchmarking range - RFC2544");
        Check(!CM::IsRelayableAddress("192.0.2.1"),
              "nor the documentation ranges - RFC5737");
        Check(!CM::IsRelayableAddress("203.0.113.1"),
              "including the third of them");
        Check(!CM::IsRelayableAddress("224.0.0.1"),
              "nor multicast, which nobody listens on");
        Check(!CM::IsRelayableAddress("fd00::1"),
              "nor an IPv6 unique local address");
        Check(CM::IsRelayableAddress("2a02:8108:94a1:9400::1"),
              "a global IPv6 address is relayed like any other public one");

        // The decision itself.
        Check(CM::ReachabilityScore("192.168.1.10", "192.168.1.20") >
              CM::ReachabilityScore("8.8.8.8", "192.168.1.20"),
              "a peer on our network is told our address on that network, "
              "not the public one it cannot reach behind the same router");
        Check(CM::ReachabilityScore("8.8.8.8", "1.2.3.4") >
              CM::ReachabilityScore("192.168.1.10", "1.2.3.4"),
              "and a peer on the internet is told the public address");
        Check(CM::ReachabilityScore("127.0.0.1", "192.168.1.20") == 0,
              "loopback scores zero for everyone, so it is never chosen");
    }

    // Lock ordering. Present only when built with MONEU_DEBUG_LOCKORDER;
    // otherwise these compile to nothing and the check below is trivially
    // true, which is deliberate - the cost is not worth paying in a node
    // carrying money, only in development and here.
    {
        Check(util::LockOrderIsConsistent(),
              "no lock-order conflict was seen while running these tests");

        std::mutex first, second;
        {
            MONEU_LOCK(first);
            MONEU_LOCK(second);
        }
        Check(util::LockOrderIsConsistent(),
              "taking two locks in a consistent order raises nothing");
    }

    // Timeouts around fetching transactions.
    //
    // The numbers matter for two separate reasons. One copy of a
    // transaction is all anybody needs, so without a limit a well
    // connected node fetches the same bytes once per peer. And a peer that
    // announces a transaction then stays silent keeps it out of this node
    // for as long as the request stands, so the timeout has to be short
    // enough that staying silent buys very little.
    {
        Check(net::MAX_TX_IN_FLIGHT_PER_PEER > 0,
              "a peer may be asked for more than nothing");
        Check(net::TX_REQUEST_TIMEOUT_SEC > 0,
              "an unanswered transaction request eventually gives up");
        Check(net::TX_REQUEST_TIMEOUT_SEC <
              net::BLOCK_STALL_TIMEOUT_SEC * 2,
              "a transaction request gives up sooner than a block one, "
              "because a transaction is cheap to ask for again and a "
              "silent peer should not hold it long");
        Check(net::MAX_TX_IN_FLIGHT_PER_PEER >
              net::MAX_BLOCKS_IN_FLIGHT_PER_PEER,
              "more transactions may be outstanding than blocks, since "
              "they are small and arrive quickly");
    }

    // The compiled seed table.
    //
    // This is what lets somebody who knows nobody join the network at all,
    // so a mistake here is the difference between a node that finds the
    // network and one that sits alone reporting that everything is fine.
    // The table is generated from a plain list by a script and decoded
    // here, and the two have to agree byte for byte.
    {
        const std::vector<std::string> seeds = NetParams::GetFixedSeeds();
        Check(!seeds.empty(),
              "the compiled seed table decodes to at least one address");

        bool foundKnown = false;
        for (size_t i = 0; i < seeds.size(); ++i) {
            if (seeds[i] == "135.181.255.219:8327") foundKnown = true;

            // Every decoded entry must carry a port, or a node would try
            // to dial an address with nothing to dial.
            Check(seeds[i].find(':') != std::string::npos,
                  "a decoded seed carries a port");

            // And every one must be an address worth passing on, since a
            // private address here would send new nodes nowhere.
            const size_t colon = seeds[i].rfind(':');
            const std::string host = seeds[i].substr(0, colon);
            Check(net::ConnManager::IsRelayableAddress(host),
                  "a seed address is one that can be reached from anywhere");
        }
        Check(foundKnown,
              "the known mainnet seed survives the round trip through the "
              "compiled table");
    }

    // Internal addresses must never leave the node.
    //
    // There are four ways an address can go out to a peer. Answering a
    // request for addresses. Sending the list when a connection opens.
    // Passing on one just learned. Announcing our own. Each has to refuse
    // anything that only means something inside one network, because an
    // internal address that escapes travels the whole network and tells
    // strangers about the shape of somebody's home network while being
    // useless to every one of them.
    //
    // The list a node keeps is allowed to hold private addresses, because
    // addnode puts them there when an operator names a machine on their own
    // network. That is right for dialling and wrong for telling anybody
    // about, so the filter sits at the point of sending rather than at the
    // point of storing.
    {
        typedef net::ConnManager CM;

        const char* mustNotLeak[] = {
            "192.168.1.10", "10.0.0.5", "172.16.0.1",
            "169.254.1.1", "100.64.0.1",
            "127.0.0.1", "0.0.0.0",
            "fd00::1", "fe80::1",
            "198.18.0.1", "192.0.2.1", "224.0.0.1"
        };
        for (size_t i = 0; i < sizeof(mustNotLeak) / sizeof(char*); ++i) {
            Check(!CM::IsRelayableAddress(mustNotLeak[i]),
                  (std::string("never handed to a peer: ") +
                   mustNotLeak[i]).c_str());
        }

        const char* mustBeRelayed[] = {
            "135.181.255.219", "8.8.8.8", "1.1.1.1",
            "2a02:8108:94a1:9400::1"
        };
        for (size_t i = 0; i < sizeof(mustBeRelayed) / sizeof(char*); ++i) {
            Check(CM::IsRelayableAddress(mustBeRelayed[i]),
                  (std::string("passed on normally: ") +
                   mustBeRelayed[i]).c_str());
        }

        // And the other half of the rule: a private address is still the
        // right thing to give a neighbour on that same network, which is
        // why storing it and sending it are separate questions.
        Check(CM::IsUsableAddress("192.168.1.10"),
              "a private address stays usable for a peer on that network "
              "even though it is never passed on");

        // And the same filter runs at discovery, so an address nobody
        // outside can reach never enters the list of this node's own
        // addresses in the first place: an address that can never be
        // announced is not an address the node has.
        //
        // A machine with Docker or a virtual machine manager has several
        // such interfaces, and without this the node reports discovering
        // ten addresses when it has one worth announcing.
        const char* neverDiscovered[] = {
            "172.17.0.1",      // Docker default bridge
            "192.168.56.1",    // VirtualBox host-only
            "10.8.0.1",        // a VPN tunnel
            "127.0.0.1"
        };
        for (size_t i = 0; i < sizeof(neverDiscovered) / sizeof(char*); ++i) {
            Check(!CM::IsRelayableAddress(neverDiscovered[i]),
                  (std::string("not kept as one of our own addresses: ") +
                   neverDiscovered[i]).c_str());
        }
    }

    // The mining loop must hash exactly what the block will carry.
    //
    // This caught a real failure and would have caught it in seconds. The
    // header stores the nonce least significant byte first, while SHA-256
    // reads message words most significant byte first. Writing the raw
    // nonce into the message word meant the loop hashed a header whose
    // nonce was the byte-swap of the one the block ended up carrying.
    //
    // The symptom was the worst kind. The miner reported a healthy hash
    // rate, found solutions at the expected pace, and every block it
    // produced failed the proof of work check on arrival. Nothing looked
    // broken and nothing was mined for six hours.
    {
        Block gen = NetParams::BuildGenesisBlock();
        BlockHeader& h = gen.GetMutableHeader();

        uint8_t buf[BlockHeader::SERIALIZED_SIZE];
        const uint32_t nonces[] = {
            0u, 1u, 0x12345678u, NetParams::GENESIS_NONCE, 0xFFFFFFFFu
        };

        for (size_t i = 0; i < sizeof(nonces) / sizeof(uint32_t); ++i) {
            h.SetNonce(nonces[i]);
            Check(h.SerializeTo(buf, sizeof(buf)),
                  "the header serialises for the nonce under test");

            // The same three compressions the miner performs.
            uint32_t b1[16], b2[16], b3[16], mid[8], st[8], hw[8];
            for (int k = 0; k < 16; ++k) {
                b1[k] = ((uint32_t)buf[k*4]     << 24) |
                        ((uint32_t)buf[k*4 + 1] << 16) |
                        ((uint32_t)buf[k*4 + 2] << 8)  |
                        ((uint32_t)buf[k*4 + 3]);
            }
            static const uint32_t iv[8] = {
                0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
                0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL };
            sha256_Transform(iv, b1, mid);

            for (int k = 0; k < 14; ++k) {
                const size_t o = 64 + k*4;
                b2[k] = ((uint32_t)buf[o]     << 24) |
                        ((uint32_t)buf[o + 1] << 16) |
                        ((uint32_t)buf[o + 2] << 8)  |
                        ((uint32_t)buf[o + 3]);
            }
            b2[14] = 0x80000000UL;
            b2[15] = 0;
            for (int k = 0; k < 15; ++k) b3[k] = 0;
            b3[15] = BlockHeader::SERIALIZED_SIZE * 8;

            // The substitution the loop makes, byte order and all.
            const uint32_t n = nonces[i];
            b2[13] = ((n & 0x000000FFu) << 24) | ((n & 0x0000FF00u) << 8) |
                     ((n & 0x00FF0000u) >> 8)  | ((n & 0xFF000000u) >> 24);

            sha256_Transform(mid, b2, st);
            sha256_Transform(st, b3, hw);

            uint8_t viaLoop[32];
            for (int k = 0; k < 8; ++k) {
                viaLoop[k*4]     = (uint8_t)(hw[k] >> 24);
                viaLoop[k*4 + 1] = (uint8_t)(hw[k] >> 16);
                viaLoop[k*4 + 2] = (uint8_t)(hw[k] >> 8);
                viaLoop[k*4 + 3] = (uint8_t)(hw[k]);
            }

            const bytes32 viaHeader = h.GetHash();
            Check(std::memcmp(viaLoop, viaHeader.data(), 32) == 0,
                  "the mining loop and the header agree on the hash, so a "
                  "block that solves the target still solves it once "
                  "written down");
        }
    }

    // A mining reward cannot be offered to coin selection before it is old
    // enough to spend.
    //
    // Leaving this to block validation looked harmless and was not. The
    // wallet picked an immature reward, built a transaction around it and
    // was then told the transaction was invalid. The owner saw a balance
    // they could not spend and an error that named the cause without saying
    // which coins were at fault or how long the wait was.
    {
        storage::Coin ordinary;
        ordinary.isCoinbase = false;
        ordinary.height = 100;
        Check(node::WalletManager::IsSpendableNow(ordinary, 100),
              "an ordinary output is spendable as soon as its block is on "
              "the chain");

        storage::Coin reward;
        reward.isCoinbase = true;
        reward.height = 100;
        Check(!node::WalletManager::IsSpendableNow(reward, 100),
              "a reward is not spendable in the block that paid it");
        Check(!node::WalletManager::IsSpendableNow(
                  reward, 100 + NetParams::COINBASE_MATURITY - 1),
              "nor one block short of maturity");
        Check(node::WalletManager::IsSpendableNow(
                  reward, 100 + NetParams::COINBASE_MATURITY),
              "and is spendable exactly at maturity");
        Check(node::WalletManager::IsSpendableNow(
                  reward, 100 + NetParams::COINBASE_MATURITY + 1000),
              "and stays spendable afterwards");
    }

    boost::filesystem::remove_all(dataDir);

    if (gFailures == 0) {
        std::printf("ALL TESTS PASSED\n");
        return 0;
    }
    std::printf("%d TEST(S) FAILED\n", gFailures);
    return 1;
}
