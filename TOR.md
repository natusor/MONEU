# Tor support in MONEU

MONEU has Tor support built in. A node can make all of its connections
through Tor, reach peers on `.onion` addresses, and offer its own `.onion`
address so that others can reach it without knowing its IP address. Only Tor
onion services version 3 are used.

Do not start `moneud` under `torsocks`. torsocks refuses connections to
127.0.0.1, so the Tor proxy and the Tor control port cannot be reached through
it. Use the options below instead. The node writes a warning to its log when
it finds itself running under torsocks.

## 1. Connecting through Tor

Add to `moneu.conf`:

    proxy=127.0.0.1:9050

Every outbound connection then goes through the Tor SOCKS5 proxy. Names and
addresses are handed to the proxy as they are and nothing is looked up in DNS
on this machine. Each connection uses its own Tor circuit
(`proxyrandomize=1`, the default).

With `proxy=` set the node also, unless told otherwise:

- does not look up the DNS seeds and uses the fixed seeds only,
- does not announce the addresses of its network interfaces (`discover=0`),
- does not ask the router to forward a port (`portmap=0`).

A `proxy=` or `onion=` value that cannot be used stops the node from
starting, so that a typing mistake never sends connections past Tor.

| Option | Meaning |
|---|---|
| `proxy=ip:port` | SOCKS5 proxy for all outbound connections |
| `onion=ip:port` | Separate SOCKS5 proxy for `.onion` peers only |
| `proxyrandomize=0/1` | A new Tor circuit for every connection (default 1) |
| `onlynet=ipv4/ipv6/onion` | Connect out only to the networks named; may be repeated |
| `discover=0/1` | Announce the addresses of this machine's interfaces |
| `externalip=addr` | Announce this address; may be repeated, for example the public IP and the `.onion` address |
| `bind=addr[:port][=onion]` | Listen only on this address; `=onion` marks the address Tor connects to |
| `listenonion=0/1` | Create an onion service through the Tor control port (default 1) |
| `torcontrol=ip:port` | Tor control port (default 127.0.0.1:9051) |
| `torpassword=pass` | Password for the Tor control port, if Tor uses one |

`onlynet=onion` keeps the node on onion peers only. Use it only when enough
MONEU nodes run onion services, or give some with `addnode=`, otherwise the
node is left without peers.

## 2. An onion address made automatically

With `listen=1` and `listenonion=1` (both the default) the node asks Tor for
an onion service through the control port. Tor must allow this. On Debian
and Ubuntu add to `/etc/tor/torrc`:

    ControlPort 9051
    CookieAuthentication 1
    CookieAuthFileGroupReadable 1

then let the user that runs `moneud` read the cookie and restart Tor:

    sudo usermod -a -G debian-tor $USER
    sudo systemctl restart tor

Log out and in again for the group to take effect. If Tor uses
`HashedControlPassword` instead, set `torpassword=` in `moneu.conf`.

The key of the onion service is kept in `onion_v3_private_key` in the data
directory, so the address stays the same after a restart. Keep that file
private; anyone who has it can run a node under the same address.

`moneu-cli getnetworkinfo` shows the address under `onionaddress`, and the
proxies in use under `proxy` and `onionproxy`. Once Tor accepts the node on
its control port, `.onion` peers are reached through 127.0.0.1:9050 even
without `proxy=` set.

## 3. An onion service set up by hand

Tor hands connections for the onion service to the node on 127.0.0.1:8329,
which is not reachable from outside this machine. This keeps peers that come
through Tor apart from everyone else. Nothing needs to be opened on the router
or in a firewall.

To run the service from `torrc` instead of the control port:

    HiddenServiceDir /var/lib/tor/moneu-service/
    HiddenServiceVersion 3
    HiddenServicePort 8327 127.0.0.1:8329

After restarting Tor, the address is in
`/var/lib/tor/moneu-service/hostname`. Put it into `moneu.conf`:

    externalip=youraddress.onion
    listenonion=0

The address Tor connects to can be changed with `bind=127.0.0.1:PORT=onion`.

## 4. A node reachable only through Tor

    proxy=127.0.0.1:9050
    listen=1
    bind=127.0.0.1:8327

`bind=` makes the node listen on this machine only, so it cannot be reached
over the local network or the internet; peers reach it through its onion
address.

## 5. Ports

| Port | Use |
|---|---|
| 8327 | P2P, and the port of the `.onion` address |
| 8328 | RPC, 127.0.0.1 only by default |
| 8329 | Local port Tor uses for the onion service, 127.0.0.1 only |

## 6. Example moneu.conf files

First add the three lines from section 3 to `/etc/tor/torrc`, restart Tor and
read the onion address from `/var/lib/tor/moneu-service/hostname`. Then write
one of the two files below to `~/.moneu/moneu.conf`. Use only letters and
digits in `rpcpassword`.

### Tor and clearnet together

The node reaches `.onion` peers through Tor and everyone else directly. If
Tor stops working, the node stays connected over clearnet and does not fall
behind. Peers on clearnet see the IP address of this machine, as with any
node without Tor.

    rpcuser=moneu
    rpcpassword=PUT-A-LONG-RANDOM-STRING-HERE
    rpcbind=127.0.0.1
    rpcport=8328
    rpcallowip=127.0.0.1

    port=8327
    listen=true
    portmap=1

    dbcache=450
    txindex=true

    loglevel=info
    logtofile=true
    maxlogsize=10
    logips=false

    onion=127.0.0.1:9050
    listenonion=0
    externalip=youraddress.onion
    addnode=135.181.255.219:8327
    addnode=92.5.174.122:8327

### Tor only

Every connection goes through Tor and no peer learns the IP address of this
machine. If Tor stops working, the node has no peers until Tor works again.

    rpcuser=moneu
    rpcpassword=PUT-A-LONG-RANDOM-STRING-HERE
    rpcbind=127.0.0.1
    rpcport=8328
    rpcallowip=127.0.0.1

    port=8327
    listen=true
    portmap=0

    dbcache=450
    txindex=true

    loglevel=info
    logtofile=true
    maxlogsize=10
    logips=false

    proxy=127.0.0.1:9050
    listenonion=0
    externalip=youraddress.onion
    bind=127.0.0.1:8327
    addnode=135.181.255.219:8327
    addnode=92.5.174.122:8327

In the Tor only file the `addnode` addresses are reached through Tor as well.

Start the node as usual and check it with `moneu-cli getnetworkinfo` and
`moneu-cli getpeerinfo`.

