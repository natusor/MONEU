#!/usr/bin/env python3
"""Check addresses before they go into the seed list.

The seed list is the first thing a new node reads and the only thing it has
before it knows anybody. An address that does not work there does not simply
fail quietly. It costs every new node a connection attempt and a timeout
before it tries the next one, and if enough entries are dead then somebody
joining gives up believing the network is gone.

So entries are checked before they are added rather than after somebody
complains. This is a smaller version of what Bitcoin does in
contrib/seeds/makeseeds.py.

What it refuses:

    anything that only means something inside one network, because
    192.168.1.10 is a different machine in every household and would send
    new nodes to their own printer

    anything malformed, since a broken line becomes a silent gap in the list

    duplicates, including the same address written two different ways

What it optionally does with -c is open a connection to each address to see
whether anything answers. Slow but worth running before a release.

Usage:
    makeseeds.py candidates.txt              check only
    makeseeds.py candidates.txt -c           check and connect
    makeseeds.py candidates.txt > seeds_main.txt
"""

import socket
import sys


DEFAULT_PORT = 8327
CONNECT_TIMEOUT = 5


def parse_ipv4(host):
    parts = host.split('.')
    if len(parts) != 4:
        return None
    out = []
    for p in parts:
        if not p.isdigit() or len(p) > 3:
            return None
        v = int(p)
        if v < 0 or v > 255:
            return None
        out.append(v)
    return out


def is_private_v4(o):
    """Ranges that only have meaning inside one network."""
    if o[0] == 10:
        return True                                   # RFC1918
    if o[0] == 192 and o[1] == 168:
        return True                                   # RFC1918
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True                                   # RFC1918
    if o[0] == 100 and 64 <= o[1] <= 127:
        return True                                   # RFC6598 carrier NAT
    if o[0] == 169 and o[1] == 254:
        return True                                   # RFC3927 link-local
    return False


def is_reserved_v4(o):
    """Ranges reserved for something other than reaching a machine."""
    if o[0] == 0:
        return True                                   # unspecified
    if o[0] == 127:
        return True                                   # loopback
    if o[0] == 198 and o[1] in (18, 19):
        return True                                   # RFC2544 benchmarking
    if o[0] == 192 and o[1] == 0 and o[2] == 2:
        return True                                   # RFC5737 documentation
    if o[0] == 198 and o[1] == 51 and o[2] == 100:
        return True                                   # RFC5737
    if o[0] == 203 and o[1] == 0 and o[2] == 113:
        return True                                   # RFC5737
    if o[0] >= 224:
        return True                                   # multicast and above
    return False


def is_private_v6(host):
    h = host.lower()
    if h in ('::', '::1'):
        return True
    if h.startswith('fc') or h.startswith('fd'):
        return True                                   # unique local
    if h.startswith('fe80'):
        return True                                   # link-local
    return False


def split_address(line):
    """Line to (host, port, is_v6), or None with a reason on stderr."""
    if line.startswith('['):
        close = line.find(']')
        if close == -1:
            return None
        host = line[1:close]
        port = DEFAULT_PORT
        rest = line[close + 1:]
        if rest.startswith(':'):
            if not rest[1:].isdigit():
                return None
            port = int(rest[1:])
        return (host, port, True)

    if line.count(':') == 1:
        host, portstr = line.rsplit(':', 1)
        if not portstr.isdigit():
            return None
        return (host, int(portstr), ':' in host)

    if ':' in line:
        return (line, DEFAULT_PORT, True)

    return (line, DEFAULT_PORT, False)


def check(line):
    """Returns (ok, canonical form, reason)."""
    parsed = split_address(line)
    if parsed is None:
        return (False, line, 'malformed')

    host, port, looks_v6 = parsed

    if port < 1 or port > 65535:
        return (False, line, 'port out of range')

    if not looks_v6:
        o = parse_ipv4(host)
        if o is None:
            return (False, line, 'not a valid IPv4 address')
        if is_private_v4(o):
            return (False, line,
                    'private address which means a different machine in '
                    'every network')
        if is_reserved_v4(o):
            return (False, line, 'reserved range, nothing listens there')
        return (True, '%s:%d' % (host, port), '')

    if is_private_v6(host):
        return (False, line, 'IPv6 address that is local to one network')
    try:
        socket.inet_pton(socket.AF_INET6, host)
    except (socket.error, ValueError):
        return (False, line, 'not a valid IPv6 address')
    return (True, '[%s]:%d' % (host, port), '')


def reachable(host, port, is_v6):
    family = socket.AF_INET6 if is_v6 else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(__doc__)
        return 1

    do_connect = '-c' in sys.argv[2:]
    seen = set()
    accepted = []

    with open(sys.argv[1]) as f:
        for raw in f:
            comment = raw.find('#')
            if comment != -1:
                raw = raw[:comment]
            line = raw.strip()
            if not line:
                continue

            ok, canonical, reason = check(line)
            if not ok:
                sys.stderr.write('refused  %-46s %s\n' % (line, reason))
                continue

            if canonical in seen:
                sys.stderr.write('refused  %-46s already listed\n' % line)
                continue
            seen.add(canonical)

            if do_connect:
                parsed = split_address(canonical)
                if not reachable(parsed[0], parsed[1], parsed[2]):
                    sys.stderr.write('refused  %-46s nothing answered\n'
                                     % canonical)
                    continue
                sys.stderr.write('answered %s\n' % canonical)

            accepted.append(canonical)

    print('# Fixed seed nodes for MONEU (blockchain) mainnet.')
    print('#')
    print('# Checked by contrib/makeseeds.py. Regenerate the compiled table')
    print('# with:')
    print('#     python3 contrib/generate-seeds.py contrib/seeds_main.txt \\')
    print('#         > src/chainparamsseeds.h')
    print('')
    for a in accepted:
        print(a)

    sys.stderr.write('\n%d accepted\n' % len(accepted))
    return 0 if accepted else 1


if __name__ == '__main__':
    sys.exit(main())
