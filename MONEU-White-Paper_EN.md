# MONEU

## Electronic system for transferring and holding value. The wallet is protected by a file of entropy from physical events

White Paper

---

## Contents

1. Introduction
2. The single use leaf shield
3. The physical source of entropy
4. Privacy
5. Transaction step by step
6. The block of creation
7. Consensus
8. Emission schedule
9. Addresses and transaction format
10. Node architecture
11. Running a node
12. Spent files as an archive
13. What keeps the coins in place
14. Parameter summary
15. Disclaimer
16. Acknowledgements

---

## 1. Introduction

MONEU is an electronic system for transferring and holding value that runs without an intermediary. 
It rests on SHA-256 proof of work. What sets it apart is that it protects user transactions from quantum computers. 
Beyond that layer MONEU uses methods already proven in older proof of work systems. 
These are the UTXO model and Merkle trees and the choice of the chain with the greatest work.

In such systems the right to spend is decided by the private key signature alone. 
That is enough for as long as nobody can recover the private key from the public one. 
MONEU requires a one time proof from a private file of physical randomness as a factor that a quantum computer cannot break.

---

## 2. The single use leaf shield

Every wallet creates its own file of physical randomness. 
Such a file is cut into pieces commonly called leaves. 
Every leaf is hashed. 
In this way all those hashes build a Merkle tree. 
The root of that tree is public and is called the KPS. 
The noise file itself is never revealed.
One leaf is 32 bytes. 
A file holds 1048576 leaves and takes 32 megabytes.

Spending one output reveals one leaf together with its path through the tree. 
Anyone can then check whether that leaf really belongs to this KPS. 
Such a leaf is marked as spent and cannot be used again while every other leaf in the file stays secret.

---

## 3. The physical source of entropy

It matters where the material for the noise file comes from.

At the base of this file lie sources that carry an unpredictable physical component. 
The flow of electrons in hardware is one of them. 
Part of that unpredictability comes from thermal noise and from shot noise. 
The rest of the variation comes from the machine itself and cannot be separated from it. 
For that reason the generator treats every single measurement as weak. 
The noise generator runs a short operation many times. 
It reads the processor cycle counter before and after each run and also computes the difference between such readings. 
What matters here are the lowest bits because those are the bits that change with every measurement.
Since one measurement gives little randomness then for safety every output byte comes from many thousands of measurements. 
The generator also loads the processor and the memory in the background. 
That load is not randomness in itself. 
It does however make the physical noise show up more strongly in the measured times.
Another fast source is the timing of random memory accesses. 
Slower sources are the processor temperature sensor and system counters. 
The generator measures how much the readings vary before it writes anything. 
It refuses to build a file when the variation is too small to trust. 
That refusal is deliberate. 
A file that looks random without being random would give a false sense of safety.

For that reason a noise file cannot be made on a virtual machine. 
A hypervisor smooths the processor cycle counter and the variation the generator needs disappears. 
The generator then stops and reports that the readings barely differ. 
This is not a fault. 
It is the guard doing its work. 
A wallet and its noise file belong on a physical machine. 
A virtual machine can still run a full node and mine to an address created elsewhere. 
Mining needs no wallet and no noise file on the machine that mines.

The material gathered this way passes through a hash function. 
The hash does not create randomness but only spreads out what has already been gathered. 
The choice of sources belongs to the wallet and is not part of the network rules. 
The network sees only the KPS and checks proofs against it. 
New sources can therefore be added later independently. 
This opens the way to building devices and gathering entropy from various external sources without any need to modify the consensus. 
Such as noise from radar data of a sand storm or of a snow storm. 
Likewise noise from a camera sensor which comes from the quantum nature of the photons landing on it. 
Adding such a source changes no network rule and does not break older nodes.
It means that as technology advances the people running nodes can build their own devices and modules gathering entropy 
that comes from events in the real world.


---

## 4. Privacy

MONEU blockchain respects human dignity and does not require biometrics. It never will.
There are also reasons why MONEU takes no randomness from the keyboard or from the microphone. 
Even though a microphone would be one of the better sources of randomness.
That would unfortunately require listening to the surroundings or recording keystrokes.

---

## 5. Transaction step by step

Alice wants to send coins to Bob.

Her wallet takes the first unused leaf from the noise file and builds a proof from it. 
It then signs the whole transaction with Alice's private key under Ed25519 and sends it to the network.

Every time each node checks five things. 
Whether the Ed25519 signature is valid. 
Whether Alice's public key matches her address. 
Whether the revealed leaf belongs to Alice's KPS along the Merkle path. 
Whether the proof is bound to the hash of this transaction. 
Whether this leaf has not been used before.

Only when all five are confirmed as correct does the transfer enter a block and Alice's leaf is marked as spent. 
Bob then receives the coins on a transaction output and can spend them later with his own leaf from his own noise file.


The transaction hash is computed without the proofs. 
That is what lets every proof bind to that hash without a circular dependency.

The single use of a leaf is checked at several levels and because of that the same leaf cannot pass twice. 
The first check is inside one transaction and the second inside one block. 
The third is in the queue of transactions waiting for a block. 
The fourth is in the set of spent leaves of the whole chain. 
The last one comes when the new state is written to disk.

The set of spent leaves is tied to the active chain. 
If an ordinary reorganisation detaches a block then the leaves it spent return to the pool. 
Its transactions return to the queue. 
They confirm again on the chain that won. 
In this way the set of spent leaves always matches the active chain.
A leaf comes back only so that the same transaction can settle. 
The proof binds that leaf to the hash of that one transaction. 
Any other transaction has a different hash and therefore needs a different unused leaf. 
Unused leaves come from the noise file alone. 
Whoever does not hold that file holds nothing that would authorise a different transfer.
Between two competing transfers the chain decides by order. 
The one that reaches a block first holds the leaf and the other is refused as reuse.


---

## 6. The block of creation

The reward in coins in the block of creation went to an address that anyone reading that block can see.
Spending the coins from that address requires holding the private key and the matching noise file.
That address is therefore also a demonstration of how the shield works.

---

## 7. Consensus

Which chain is the right one is decided by the greatest total work. 
Never by height alone.

Anyone who runs a node synchronises the whole chain from the block of creation and reaches the same state as every other node in the network.
The history is protected by the rule of greatest total work. 
Rewriting an old part of the chain would mean redoing all the work that was built on top of it. 
Checkpoints written into the code give a second layer. 
A checkpoint names a block at a chosen height and every node refuses a chain that disagrees with it. 
Checkpoints are added as the chain grows longer.

The mining difficulty adjusts once every 2016 blocks. 
At the target pace that is roughly once every two weeks. 
The network measures the real time of the recent blocks and corrects the difficulty to return to a pace of one block every ten minutes.
No proof of work network is by itself safe from an opponent with very large computing power. 
MONEU does not claim otherwise. 
Resistance is gained gradually and it grows with decentralisation and with the total power of the network and with a rising number of users. 
The more independent miners and nodes there are the more expensive and the harder it becomes to disturb the network.
That is why the greatest contribution to the growth of the network is running your own node and keeping it going. The same for a node on a VPS.

---

## 8. Emission schedule

The MONEU supply is fixed at 30000000 coins. 
One coin divides into 100000000 smallest units.

The block reward starts at 77 coins. 
A halving occurs every 194804 blocks which is roughly every 3.7 years. 
The reward then falls by half and so on until it reaches zero. 
This should take about 33 epochs which is around 122 years. 
The total emission of the whole schedule is 29999815.97 coins. 
That leaves 184.03 coins of headroom.

The first epoch produces 14999908 coins which is just under half of the whole supply. 
The interval of 194804 blocks was chosen so that the sum of the whole schedule fits under the value of 30000000.
Those who join earliest and support the network by keeping nodes running and mining coins are the pioneers. 
With a small effort of their own processors they will earn coins most easily.

MONEU deliberately has no tail emission. 
When successive halvings bring it to zero the reward in coins for mining a block ends for good.
From that point miners live on the fees of the transfers a block carries.
Mining stays worthwhile because of the scale of the network and the number of transactions whose fees pay for every further block.

The whole fee goes to the miner who put the transaction into a block. 
This keeps miners paid after the last coin is mined. 
Such a fee depends on the size of the transaction in bytes. 
A larger transfer therefore pays proportionally more and the rate per byte together with the dust threshold protects the network from being filled with tiny transactions. 
An ordinary transfer of about 1012 bytes therefore pays about 1012 units. 
The floor of 1000 units is below what any transfer weighs so in practice the size decides the fee. 
A transfer that spends several outputs carries one proof for each of them and grows accordingly. 
Eight outputs spent at once weigh over fourteen thousand bytes and the fee follows that weight. 
A transfer that carries a message grows by the length of that message and pays for those bytes as well. 
The wallet computes this by itself when no fee is given. 
The sender of a transaction may attach a higher fee to have the transfer confirmed sooner.
Miners order the waiting transactions by the fee per byte.
A mining reward cannot be spent until 50 further blocks have been built on top of the block that paid it. 
This protects the network from spending coins from a block that could be removed by a reorganisation of the chain.

---

## 9. Addresses and transaction format

MONEU uses the Ed25519 curve for signatures. 
An address in MONEU is not a plain hash of the public key because it is bound to the shield.

```
address_hash = SHA-256 of (public_key + KPS)
address      = Base58Check of (prefix_byte + address_hash)
```

The prefix byte says what kind of address it is. 
It also decides the character an address starts with. 
A payment address uses 33 and starts with the digit 2 and is 51 characters long. 
Two further prefix bytes are reserved for kinds of address that MONEU does not build today.

The KPS is part of the address hash and nobody will create a valid address without both the key and the noise file. Your address is bound to one particular noise file.

Transactions use the UTXO model. 
Every input points to the output being spent. 
It carries the public key and the signature and the KPS and the noise proof. 
Every output simply gives an amount and the address hash of the recipient.

A transaction with one input and two outputs weighs about 1012 bytes and the proof is 732 of them. 
A block of 6 megabytes holds about 6200 such transactions. 
With blocks arriving every ten minutes that gives about 10 transactions a second.
That is around 900 thousand transactions a day.

A transaction may also carry up to 300 bytes of extra data in an OP_RETURN field. 
That field has no value and cannot be spent. 
An output with data that tries to carry any amount at all is rejected.

In an OP_RETURN field you can record the hash of a document as evidence that the document existed at a given moment. 
Likewise you can record in that field the hash of a database or of a fragment of one. 
Somebody looking from outside sees only a number and does not know what it refers to nor in what order such hashes would have to be read.

---

## 10. Node architecture

MONEU is a network of equal nodes with no central server. 
Every full node keeps the whole history and also checks every block and every transaction itself without relying on anyone.

The network layer keeps connections and passes on blocks and transactions within sizes that protect against overload. 
The transaction queue checks and holds transfers waiting for confirmation and also protects against double spending and against reuse of a leaf. 
A transfer waiting for a block is not lost when the node is stopped. 
The consensus engine checks the proof of work and also adjusts the difficulty and picks the heaviest chain. 
The validation layer checks the full rules of a block and of a transaction. 
The state store keeps the UTXO set and the set of spent leaves in line with the active chain. 
The wallet manages the keys and the noise file and the building of transactions.


---

## 11. Running a node

MONEU is open source.

**Build**

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

**Check the build**

```
./build/src/moneu-test-noise
```

Every test must pass before you start the node.

**Start the node**

```
./build/src/moneud -daemon
```

The node writes its data to `~/.moneu`. 
Blocks and chain state and wallet and logs are in the ~/.moneu directory.
After entering the start command wait about thirty seconds.
Then create a wallet. 

**Creating a wallet**

```
./build/src/moneu-cli createwallet "your-passphrase"
```

Then create the noise file. Without it you cannot spend the coins from your wallet even holding the private key. 

**Creating the noise file**

```
./build/src/moneu-cli makenoise "your-passphrase"
```

Creating the noise file takes a few minutes and loads the machine on purpose. 
Do not interrupt it. This is the only noise file your wallet will ever have. 
After it is made you will find it in the wallet directory.
`~/.moneu/wallet/noise.dat` 
That file is 32 megabytes holding 1048576 single use leaves.

Copy this file onto two separate media before you go further. 
It is required for signing transactions. 
Losing it means losing access to the coins.

**One wallet for life**

A wallet in MONEU is made once and kept. 
Its noise file is created with it and belongs to it alone. 
No other noise file can be attached later and no noise file can be handed to a second wallet. 
Every address is derived from the key together with the KPS. 
Both halves must be the same ones that created it.

The backup is therefore a pair. 
The wallet file and the noise file. 
Copied they should be kept together and used together.

**Backup**

Best make it right after you create the wallet and the noise file. 
Copy the whole contents of the `~/.moneu/wallet` directory onto external media.
When creating the wallet and the noise file you must use a passphrase of at least eight characters.
Keeping these files on encrypted media is advised.
Making two copies and keeping them in two different places is advised. 
For better safety of the files on the media it is advised to write down the passphrases for the media and for the files separately.

**Unlocking the wallet**

```
./build/src/moneu-cli walletunlock "your-passphrase"
```

Loading the noise file takes about half a minute.

**Address**

```
./build/src/moneu-cli getnewaddress
./build/src/moneu-cli getwalletinfo
```

**Mining**

```
./build/src/moneu-cli startmining <your-address> <threads>
./build/src/moneu-cli getmininginfo
./build/src/moneu-cli stopmining
```

**Sending**

```
./build/src/moneu-cli sendtoaddress <address> <amount>
./build/src/moneu-cli sendtoaddress <address> <amount> <fee>
./build/src/moneu-cli sendtoaddress <address> <amount> <fee> "message"
```

The wallet must be unlocked before any transfer. 
Given no fee the wallet works out what the transfer weighs and sets the fee from that weight. 
This is the form to use in normal work.

A fee given by hand replaces that calculation. 
It must cover the weight of the transfer or the wallet refuses and names the amount required. 
A transfer carrying a message weighs more than a plain one so it needs more than the floor. 
A message is passed as the fourth argument and therefore a fee must be given in the third. 
The message may hold at most 300 bytes.

```
./build/src/moneu-cli sendtoaddress <address> 0.001 0.00002 "hello"
```

After every transfer a counter is shown telling how many unused leaves are left in the noise file. 
Keep an eye on that number. If few leaves are left then on a separate machine create a new wallet with its own noise file and a new address. 
Move the coins to it from the old address before the available leaves run out.
When the leaves run out then no transfer can be authorised from such a wallet any more.


**Looking around**

```
./build/src/moneu-cli getinfo
./build/src/moneu-cli getblockcount
./build/src/moneu-cli getbestblockhash
./build/src/moneu-cli getblock <hash>
./build/src/moneu-cli getrawtransaction <txid> true
./build/src/moneu-cli getbalance <address>
./build/src/moneu-cli getmempoolinfo
./build/src/moneu-cli getrawmempool true
./build/src/moneu-cli getpeerinfo
```

**Stopping the node**

```
./build/src/moneu-cli stop
```

Waiting transfers go to `~/.moneu/mempool.dat` and come back at the next start.

---

## 12. Spent files as an archive

This chapter is about what can be done with a noise file once every leaf in it has been spent.

A noise file is a collection of 1048576 pieces of randomness gathered from real events in hardware.

When the owner has spent every leaf then the file loses its value for the wallet. 
Such a file does not however lose its value as physical material. 
A spent file gives no power over any address so sharing it puts no coins at risk.
As research material such a file can be useful in work on random generators and on encryption. 
Even a spent file is still bound to a KPS and through the KPS to the addresses of its owner. 
Sharing it may therefore reveal links between them. 
That is why the decision whether to share a spent file belongs to the owner of the file alone.

---

## 13. What keeps the coins in place

Together the parts described above stop an attacker with a quantum computer from taking the coins. 
They do not however protect against losing your own noise file or your own key. 
The safety of those files is up to the wallet owner and nobody else.

Spending coins requires three things. 
The private key. 
The noise file the address is bound to. 
An unused leaf from that file. 

A private key on its own moves nothing. 
Every transfer needs an unused leaf and unused leaves live in the noise file alone. 
An opponent who recovers a private key and does not hold that file can read a balance and can do nothing with it.

A public key becomes visible only when an address spends. 
The change of that transfer moves to a fresh address whose key has never been seen. 
Each address is therefore used once and the key of the next transfer is not on the chain yet when the previous one settles. 
The wallet creates that fresh address by itself for every change output.

This is why an address should not be used twice. 
A transfer takes only the outputs it needs to cover the amount and the fee. 
An address that received many payments keeps the rest of them after a transfer and its public key is by then on the chain. 
Mining to one address again and again builds exactly that situation.

A leaf that has been used is worthless to anyone. 
It is written as spent across the whole chain and no node accepts it a second time. 
The proof also binds a leaf to the hash of one transaction and any other transaction has a hash of its own.

One noise file serves the whole wallet. 
Addresses for payment and addresses for change are bound to the same KPS and draw from the same leaves. 
The counter of unused leaves therefore belongs to the wallet and not to any single address. 
A wallet is made once and lives as long as unused leaves remain in that file. 
That is over a million spends. 
Copy the wallet file and the noise file together and keep both for as long as the wallet holds anything.

What chapter seven says about a very strong opponent holds here too.

---

## 14. Parameter summary

The network is called MONEU. The proof of work is SHA-256. The signature curve is Ed25519. The shield is single use leaves from a file of physical randomness.

The address hash is formed as SHA-256 of the public key together with the KPS. A payment address is that hash written in Base58Check behind the prefix byte 33. It starts with the digit 2 and is 51 characters long.

The maximum supply is 30000000 coins. One coin divides into 100000000 units. The block time is 600 seconds. The initial reward is 77 coins per block. A halving occurs every 194804 blocks which is about every 3.7 years. The schedule runs for 33 epochs and about 122 years. Then emission ends and miners earn from transaction fees alone. Total emission is 29999815.97 coins.

The difficulty adjusts every 2016 blocks which is about every 14 days. A single correction may move the difficulty only so far in either direction. A block timestamp may not run ahead of the clock by more than two hours.

The noise file holds 1048576 leaves of 32 bytes each and takes 32 megabytes. The maximum block size is 6 megabytes. A mining reward matures after 50 blocks. The extra data field holds at most 300 bytes. The fee is 1 unit per byte and never less than 1000 units in total. The dust threshold is 1000 units. The peer to peer port is 8327. The port of the interface for programs is 8328.

---

## 15. Disclaimer

This document describes the technical design of MONEU.

MONEU is open source software released for further development. The code is there to be read and checked by anyone who wants to. Taking part in the network is voluntary.

The noise file and the private keys are held by the owner. Losing them means losing access to the coins for good. Keep copies on separate encrypted media.

The safety of the operating system and the machine is up to the user. MONEU is not responsible for an unsecured device or system.

---

## 16. Acknowledgements

I thank Adam Back for Hashcash and for the idea of proof of work based on a hash function. I also thank Satoshi Nakamoto for building a consensus without an intermediary on that foundation.

Special thanks go to everyone who runs a full node and keeps it running as long as possible. Also to everyone who keeps a node on a VPS.

MONEU deliberately does not use the post quantum signature schemes recommended by NIST and the NSA. I think solutions based on single use proofs from a Merkle tree and on physical entropy are simpler and lighter.

natusor
natusor@tutamail.com
