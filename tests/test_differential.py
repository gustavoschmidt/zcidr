"""Randomized differential tests against the stdlib ``ipaddress`` module.

Covers the plan's "fuzz parse round-trips" note: for many random inputs, our
native results must agree with Python's reference implementation.
"""

import ipaddress
import random

import znetaddress as z

SEED = 20260704


def test_ipv4_roundtrip_fuzz():
    rng = random.Random(SEED)
    for _ in range(5000):
        v = rng.getrandbits(32)
        s = str(ipaddress.IPv4Address(v))
        assert z.parse_ipv4(s) == v
        assert z.format_ipv4(v) == s


def test_ipv6_format_fuzz():
    rng = random.Random(SEED + 1)
    for _ in range(5000):
        packed = rng.getrandbits(128).to_bytes(16, "big")
        assert z.format_ipv6(packed) == str(ipaddress.IPv6Address(packed))


def test_ipv6_parse_fuzz():
    rng = random.Random(SEED + 2)
    for _ in range(5000):
        packed = rng.getrandbits(128).to_bytes(16, "big")
        text = str(ipaddress.IPv6Address(packed))  # canonical form
        assert z.parse_ipv6(text) == packed


def _ref_lookup(nets, ip):
    """Reference longest-prefix-match over ``nets`` (insertion order)."""
    addr = ipaddress.ip_address(ip)
    best_val = None
    best_len = -1
    for net, val in nets:
        if net.version == addr.version and addr in net and net.prefixlen >= best_len:
            best_len = net.prefixlen
            best_val = val
    return best_val


def test_trie_matches_reference_ipv4():
    rng = random.Random(SEED + 3)
    # Build a set of unique random IPv4 networks.
    nets = {}
    while len(nets) < 300:
        prefix = rng.randint(0, 32)
        base = rng.getrandbits(32)
        net = ipaddress.ip_network((base, prefix), strict=False)
        nets[str(net)] = None
    ordered = []
    m = z.PrefixMap()
    for i, cidr in enumerate(nets):
        val = i + 1
        m.add(cidr, val)
        ordered.append((ipaddress.ip_network(cidr), val))

    for _ in range(5000):
        ip = str(ipaddress.IPv4Address(rng.getrandbits(32)))
        assert m.get(ip) == _ref_lookup(ordered, ip)
    m.close()


def test_trie_matches_reference_ipv6():
    rng = random.Random(SEED + 4)
    nets = {}
    while len(nets) < 200:
        prefix = rng.randint(0, 128)
        base = rng.getrandbits(128)
        net = ipaddress.ip_network((base, prefix), strict=False)
        nets[str(net)] = None
    ordered = []
    m = z.PrefixMap()
    for i, cidr in enumerate(nets):
        val = i + 1
        m.add(cidr, val)
        ordered.append((ipaddress.ip_network(cidr), val))

    for _ in range(3000):
        ip = str(ipaddress.IPv6Address(rng.getrandbits(128)))
        assert m.get(ip) == _ref_lookup(ordered, ip)
    m.close()
