// Copyright (c) 2025-2026 natusor (MONEU)
// Distributed under the MIT software license

#include "rpcworker.h"
#include "miutil.h"

#include "chainparams.h"

#include <QMetaType>
#include <QMutex>
#include <QMutexLocker>
#include <QVariantList>

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace mi {

void RegisterMetaTypes()
{
    qRegisterMetaType<mi::ChainInfo>("mi::ChainInfo");
    qRegisterMetaType<mi::WalletInfo>("mi::WalletInfo");
    qRegisterMetaType<mi::ActionResult>("mi::ActionResult");
}

static QString Text(const std::string& s)
{
    return QString::fromStdString(s);
}

static QString ResultText(const json& result)
{
    if (result.is_string()) return Text(result.get<std::string>());
    if (result.is_null()) return QString();
    return Text(result.dump(4));
}

static int64_t JsonInt(const json& obj, const char* key, int64_t fallback = 0)
{
    if (!obj.is_object() || !obj.contains(key)) return fallback;
    const json& v = obj[key];
    if (v.is_number_integer()) return v.get<int64_t>();
    if (v.is_number()) return static_cast<int64_t>(v.get<double>());
    return fallback;
}

static double JsonDouble(const json& obj, const char* key)
{
    if (!obj.is_object() || !obj.contains(key)) return 0.0;
    const json& v = obj[key];
    if (v.is_number()) return v.get<double>();
    return 0.0;
}

static bool JsonBool(const json& obj, const char* key, bool fallback = false)
{
    if (!obj.is_object() || !obj.contains(key)) return fallback;
    const json& v = obj[key];
    if (v.is_boolean()) return v.get<bool>();
    return fallback;
}

static std::string JsonString(const json& obj, const char* key)
{
    if (!obj.is_object() || !obj.contains(key)) return std::string();
    const json& v = obj[key];
    if (v.is_string()) return v.get<std::string>();
    return std::string();
}

static void Wipe(std::string& s)
{
    std::fill(s.begin(), s.end(), '\0');
    s.clear();
}

Poller::Poller(const std::string& dataDir)
    : mRpc(dataDir)
{
}

void Poller::PollChain()
{
    ChainInfo info;
    std::vector<std::pair<std::string, json> > calls;
    calls.push_back(std::make_pair(std::string("getblockcount"), json::array()));
    calls.push_back(std::make_pair(std::string("getpeerinfo"), json::array()));
    calls.push_back(std::make_pair(std::string("getmininginfo"), json::array()));

    std::vector<RpcReply> r;
    {
        QMutexLocker lock(&MinerCallLock());
        r = mRpc.Batch(calls, 30);
    }

    if (!r[0].Ok()) {
        info.error = Text(r[0].ErrorText());
        Q_EMIT ChainUpdated(info);
        return;
    }
    info.ok = true;
    if (r[0].result.is_number_integer())
        info.height = r[0].result.get<int64_t>();
    if (r[1].Ok())
        info.peers = static_cast<int>(JsonInt(r[1].result, "count"));
    if (r[2].Ok()) {
        info.mining = JsonBool(r[2].result, "mining");
        info.hashRate = JsonDouble(r[2].result, "hashespersec");
        info.networkHash = JsonDouble(r[2].result, "networkhashps");
        info.nextBits = static_cast<quint32>(JsonInt(r[2].result, "nextbits"));
    }
    Q_EMIT ChainUpdated(info);
}

void Poller::PollWallet()
{
    WalletInfo info;
    const std::string dataDir = mRpc.DataDir();
    info.walletFile = FileExists(WalletFilePathText(dataDir));
    info.noiseFile = FileExists(NoiseFilePathText(dataDir));

    RpcReply wi = mRpc.Call("getwalletinfo", json::array(), 120);
    if (!wi.Ok()) {
        info.error = Text(wi.ErrorText());
        Q_EMIT WalletUpdated(info);
        return;
    }
    info.ok = true;
    info.initialized = JsonBool(wi.result, "initialized");
    info.locked = JsonBool(wi.result, "locked", true);
    info.noiseLoaded = JsonBool(wi.result, "noise_loaded");
    info.leavesLeft = JsonInt(wi.result, "noise_leaves_remaining");
    info.leavesTotal = JsonInt(wi.result, "noise_leaves_total");

    if (!info.initialized) {
        Q_EMIT WalletUpdated(info);
        return;
    }

    RpcReply la = mRpc.Call("listaddresses", json::array(), 120);
    if (la.Ok() && la.result.is_array()) {
        for (const auto& a : la.result) {
            AddressRow row;
            row.address = Text(JsonString(a, "address"));
            row.isChange = JsonBool(a, "ischange");
            row.index = static_cast<quint32>(JsonInt(a, "index"));
            info.addresses.append(row);
        }
    }

    std::vector<std::pair<std::string, json> > calls;
    std::vector<int> rowOf;
    for (int i = 0; i < info.addresses.size(); ++i) {
        if (info.addresses[i].isChange) continue;
        json p = json::array();
        p.push_back(info.addresses[i].address.toStdString());
        calls.push_back(std::make_pair(std::string("getbalance"), p));
        rowOf.push_back(i);
    }

    bool allKnown = wi.result.contains("balance_units");
    int64_t immature = 0;
    if (!calls.empty()) {
        std::vector<RpcReply> b = mRpc.Batch(calls, 300);
        for (size_t k = 0; k < b.size(); ++k) {
            AddressRow& row = info.addresses[rowOf[k]];
            if (!b[k].Ok()) {
                allKnown = false;
                continue;
            }
            row.balanceKnown = true;
            row.spendable = CoinsToUnits(JsonDouble(b[k].result, "spendable"));
            row.immature = CoinsToUnits(JsonDouble(b[k].result, "immature"));
            immature += row.immature;
        }
    }

    if (allKnown) {
        info.balanceKnown = true;
        info.total = JsonInt(wi.result, "balance_units");
        info.immature = immature;
        info.spendable = info.total - immature;
        if (info.spendable < 0) info.spendable = 0;
    }
    Q_EMIT WalletUpdated(info);
}

Actions::Actions(const std::string& dataDir)
    : mRpc(dataDir)
    , mDataDir(dataDir)
{
}

void Actions::CreateWallet(const QString& passphrase)
{
    ActionResult res;
    res.kind = QStringLiteral("create");

    if (FileExists(WalletFilePathText(mDataDir))) {
        res.text = QStringLiteral("error: Wallet already exists. Use loadwallet.");
        Q_EMIT Finished(res);
        return;
    }

    std::string pass = passphrase.toStdString();
    json params = json::array();
    params.push_back(pass);
    RpcReply r = mRpc.Call("createwallet", params, 900);
    if (!r.Ok()) {
        Wipe(pass);
        res.text = Text(r.ErrorText());
        Q_EMIT Finished(res);
        return;
    }
    res.ok = true;
    res.data[QStringLiteral("mnemonic")] = Text(JsonString(r.result, "mnemonic"));
    res.data[QStringLiteral("warning")] = Text(JsonString(r.result, "warning"));

    RpcReply u = mRpc.Call("walletunlock", params, 900);
    Wipe(pass);
    params = json::array();
    res.data[QStringLiteral("unlock")] =
        u.Ok() ? ResultText(u.result) : Text(u.ErrorText());
    Q_EMIT Finished(res);
}

void Actions::Unlock(const QString& passphrase, const QString& kind)
{
    ActionResult res;
    res.kind = kind;
    std::string pass = passphrase.toStdString();
    json params = json::array();
    params.push_back(pass);
    RpcReply r = mRpc.Call("walletunlock", params, 900);
    Wipe(pass);
    params = json::array();
    res.ok = r.Ok();
    res.text = r.Ok() ? ResultText(r.result) : Text(r.ErrorText());
    Q_EMIT Finished(res);
}

void Actions::NewAddress()
{
    ActionResult res;
    res.kind = QStringLiteral("newaddress");
    RpcReply r = mRpc.Call("getnewaddress", json::array(), 120);
    res.ok = r.Ok();
    res.text = r.Ok() ? ResultText(r.result) : Text(r.ErrorText());
    Q_EMIT Finished(res);
}

void Actions::LoadAddresses()
{
    ActionResult res;
    res.kind = QStringLiteral("addresses");
    RpcReply la = mRpc.Call("listaddresses", json::array(), 120);
    if (!la.Ok() || !la.result.is_array()) {
        res.text = la.Ok() ? QStringLiteral("error: invalid JSON response")
                           : Text(la.ErrorText());
        Q_EMIT Finished(res);
        return;
    }

    std::vector<std::pair<std::string, json> > calls;
    for (const auto& a : la.result) {
        json p = json::array();
        p.push_back(JsonString(a, "address"));
        calls.push_back(std::make_pair(std::string("getbalance"), p));
    }
    std::vector<RpcReply> b = mRpc.Batch(calls, 600);

    QVariantList rows;
    size_t k = 0;
    for (const auto& a : la.result) {
        QVariantMap row;
        row[QStringLiteral("address")] = Text(JsonString(a, "address"));
        row[QStringLiteral("change")] = JsonBool(a, "ischange");
        row[QStringLiteral("index")] = static_cast<qlonglong>(JsonInt(a, "index"));
        if (k < b.size() && b[k].Ok()) {
            row[QStringLiteral("known")] = true;
            row[QStringLiteral("spendable")] = static_cast<qlonglong>(
                CoinsToUnits(JsonDouble(b[k].result, "spendable")));
            row[QStringLiteral("immature")] = static_cast<qlonglong>(
                CoinsToUnits(JsonDouble(b[k].result, "immature")));
        } else {
            row[QStringLiteral("known")] = false;
        }
        rows.append(row);
        ++k;
    }
    res.ok = true;
    res.data[QStringLiteral("rows")] = rows;
    Q_EMIT Finished(res);
}

void Actions::StartMining(int threads)
{
    ActionResult res;
    res.kind = QStringLiteral("startmining");

    std::string address;
    RpcReply la = mRpc.Call("listaddresses", json::array(), 120);
    if (la.Ok() && la.result.is_array()) {
        int64_t best = -1;
        for (const auto& a : la.result) {
            if (JsonBool(a, "ischange")) continue;
            const int64_t index = JsonInt(a, "index");
            if (index > best) {
                best = index;
                address = JsonString(a, "address");
            }
        }
    }

    json params = json::array();
    if (!address.empty()) {
        params.push_back(address);
        params.push_back(threads < 1 ? 1 : threads);
        params.push_back("gpu");
    }

    RpcReply r;
    {
        QMutexLocker lock(&MinerCallLock());
        r = mRpc.Call("startmining", params, 900);
    }
    res.ok = r.Ok();
    if (r.Ok()) {
        res.data[QStringLiteral("device")] = Text(JsonString(r.result, "device"));
        res.data[QStringLiteral("threads")] =
            static_cast<qlonglong>(JsonInt(r.result, "threads"));
        res.data[QStringLiteral("address")] = Text(JsonString(r.result, "address"));
    } else {
        res.text = Text(r.ErrorText());
    }
    Q_EMIT Finished(res);
}

void Actions::StopMining()
{
    ActionResult res;
    res.kind = QStringLiteral("stopmining");
    RpcReply r;
    {
        QMutexLocker lock(&MinerCallLock());
        r = mRpc.Call("stopmining", json::array(), 900);
    }
    res.ok = r.Ok();
    if (!r.Ok()) res.text = Text(r.ErrorText());
    Q_EMIT Finished(res);
}

// Reads the finished transaction back from the node: what the recipient got,
// the fee it charged and the change that came back.
void Actions::ReadPayment(const std::string& txid, const std::string& address,
                          ActionResult& res)
{
    std::string recipientHash;
    if (!HashHexFromAddress(address, recipientHash)) return;
    json p = json::array();
    p.push_back(txid);
    p.push_back(true);
    RpcReply t = mRpc.Call("getrawtransaction", p, 60);
    if (!t.Ok() || !t.result.is_object() || !t.result.contains("vout") ||
        !t.result["vout"].is_array() || !t.result.contains("vin") ||
        !t.result["vin"].is_array())
        return;

    int64_t totalOut = 0;
    int64_t toRecipient = 0;
    for (const auto& out : t.result["vout"]) {
        const int64_t value = JsonInt(out, "value");
        totalOut += value;
        if (JsonString(out, "pubkeyhash") == recipientHash) toRecipient += value;
    }

    std::vector<std::pair<std::string, json> > calls;
    std::vector<int64_t> index;
    for (const auto& in : t.result["vin"]) {
        json q = json::array();
        q.push_back(JsonString(in, "prevtxid"));
        q.push_back(true);
        calls.push_back(std::make_pair(std::string("getrawtransaction"), q));
        index.push_back(JsonInt(in, "outputindex", -1));
    }
    if (calls.empty()) return;
    std::vector<RpcReply> prev = mRpc.Batch(calls, 120);
    int64_t totalIn = 0;
    for (size_t i = 0; i < prev.size(); ++i) {
        if (!prev[i].Ok() || !prev[i].result.contains("vout") ||
            !prev[i].result["vout"].is_array())
            return;
        bool found = false;
        for (const auto& out : prev[i].result["vout"]) {
            if (JsonInt(out, "n", -1) == index[i]) {
                totalIn += JsonInt(out, "value");
                found = true;
                break;
            }
        }
        if (!found) return;
    }
    if (totalIn < totalOut) return;
    res.data[QStringLiteral("fee")] = static_cast<qlonglong>(totalIn - totalOut);
    res.data[QStringLiteral("change")] =
        static_cast<qlonglong>(totalOut - toRecipient);
    res.data[QStringLiteral("received")] = static_cast<qlonglong>(toRecipient);
}

void Actions::Send(const QString& address, const QString& amount,
                   const QString& message)
{
    ActionResult res;
    res.kind = QStringLiteral("send");

    const std::string amountText = amount.trimmed().toStdString();
    int64_t units = 0;
    std::string why;
    if (!ParseAmountText(amountText, units, why)) {
        res.text = Text("error: Invalid amount: " + why);
        Q_EMIT Finished(res);
        return;
    }

    // The node reads a number back with eight decimals. Anything a double
    // cannot carry that far is refused here rather than sent rounded.
    json amountJson;
    if (units % ::NetParams::COIN == 0) {
        amountJson = units / ::NetParams::COIN;
    } else {
        amountJson = static_cast<double>(units) /
                     static_cast<double>(::NetParams::COIN);
        std::ostringstream back;
        back << std::fixed << std::setprecision(8) << amountJson.get<double>();
        int64_t check = 0;
        std::string ignored;
        if (!ParseAmountText(back.str(), check, ignored) || check != units) {
            res.text = Text("error: Invalid amount: " + amountText);
            Q_EMIT Finished(res);
            return;
        }
    }

    json params = json::array();
    params.push_back(address.trimmed().toStdString());
    params.push_back(amountJson);

    const QByteArray bytes = message.toUtf8();
    if (!bytes.isEmpty()) {
        if (bytes.size() > 300) {
            res.text = QStringLiteral("error: message is %1 bytes; the limit is 300")
                           .arg(bytes.size());
            Q_EMIT Finished(res);
            return;
        }
        params.push_back(nullptr);
        params.push_back(bytes.toHex().toStdString());
    }

    static const int MAX_ATTEMPTS = 16;
    RpcReply r;
    int attempt = 0;
    while (attempt < MAX_ATTEMPTS) {
        ++attempt;
        r = mRpc.Call("sendtoaddress", params, 900);
        if (r.kind == RpcReply::RPC_ERROR &&
            r.message.find("sign again.") != std::string::npos)
            continue;
        break;
    }

    res.ok = r.Ok();
    res.data[QStringLiteral("attempts")] = attempt;
    res.data[QStringLiteral("amount")] = static_cast<qlonglong>(units);
    res.data[QStringLiteral("address")] = address.trimmed();
    if (r.Ok()) {
        res.text = ResultText(r.result);
        ReadPayment(res.text.toStdString(), address.trimmed().toStdString(), res);
        RpcReply wi = mRpc.Call("getwalletinfo", json::array(), 120);
        if (wi.Ok() && wi.result.contains("noise_leaves_remaining") &&
            wi.result.contains("noise_leaves_total")) {
            const int64_t left = JsonInt(wi.result, "noise_leaves_remaining");
            const int64_t total = JsonInt(wi.result, "noise_leaves_total");
            QString noise = QStringLiteral("Noise file: %1 of %2 single-use leaves left.")
                                .arg(left).arg(total);
            if (left == 0)
                noise += QStringLiteral("\nWARNING: none are left. No further transfer "
                                        "can be authorised from this wallet.");
            else if (left <= 100)
                noise += QStringLiteral("\nWARNING: create a new wallet and move the "
                                        "funds while there are still leaves to do it "
                                        "with.");
            else if (left <= 10000)
                noise += QStringLiteral("\nPlan a move to a new wallet before they run "
                                        "out.");
            res.data[QStringLiteral("noise")] = noise;
        }
    } else {
        res.text = Text(r.ErrorText());
    }
    Q_EMIT Finished(res);
}

void Actions::LoadNetwork()
{
    ActionResult res;
    res.kind = QStringLiteral("network");
    std::vector<std::pair<std::string, json> > calls;
    calls.push_back(std::make_pair(std::string("getnetworkinfo"), json::array()));
    calls.push_back(std::make_pair(std::string("getpeerinfo"), json::array()));
    std::vector<RpcReply> r = mRpc.Batch(calls, 60);
    if (!r[0].Ok()) {
        res.text = Text(r[0].ErrorText());
        Q_EMIT Finished(res);
        return;
    }
    res.ok = true;
    const json& n = r[0].result;
    res.data[QStringLiteral("subversion")] = Text(JsonString(n, "subversion"));
    res.data[QStringLiteral("localport")] =
        static_cast<qlonglong>(JsonInt(n, "localport"));
    res.data[QStringLiteral("inbound")] = static_cast<qlonglong>(JsonInt(n, "inbound"));
    res.data[QStringLiteral("outbound")] =
        static_cast<qlonglong>(JsonInt(n, "outbound"));
    res.data[QStringLiteral("recv")] =
        static_cast<qlonglong>(JsonInt(n, "totalbytesrecv"));
    res.data[QStringLiteral("sent")] =
        static_cast<qlonglong>(JsonInt(n, "totalbytessent"));
    res.data[QStringLiteral("active")] = JsonBool(n, "networkactive", true);

    QVariantList peers;
    if (r[1].Ok() && r[1].result.contains("peers") &&
        r[1].result["peers"].is_array()) {
        for (const auto& p : r[1].result["peers"]) {
            QVariantMap row;
            row[QStringLiteral("addr")] = Text(JsonString(p, "addr"));
            row[QStringLiteral("inbound")] = JsonBool(p, "inbound");
            row[QStringLiteral("subver")] = Text(JsonString(p, "subver"));
            row[QStringLiteral("height")] =
                static_cast<qlonglong>(JsonInt(p, "startingheight"));
            row[QStringLiteral("ping")] = JsonDouble(p, "pingtime");
            peers.append(row);
        }
    }
    res.data[QStringLiteral("peers")] = peers;
    Q_EMIT Finished(res);
}

} // namespace mi
