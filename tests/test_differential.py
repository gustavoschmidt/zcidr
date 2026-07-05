"""Randomized differential tests against the stdlib ``ipaddress`` module.

Covers the plan's "fuzz parse round-trips" note: for many random inputs, our
native results must agree with Python's reference implementation.
"""

import ipaddress
import random

import zcidr

SEED = 20260704


def test_ipv4_roundtrip_fuzz():
    rng = random.Random(SEED)
    for _ in range(5000):
        v = rng.getrandbits(32)
        s = str(ipaddress.IPv4Address(v))
        assert zcidr.parse_ipv4(s) == v
        assert zcidr.format_ipv4(v) == s


def test_ipv6_format_fuzz():
    rng = random.Random(SEED + 1)
    for _ in range(5000):
        packed = rng.getrandbits(128).to_bytes(16, "big")
        assert zcidr.format_ipv6(packed) == str(ipaddress.IPv6Address(packed))


def test_ipv6_parse_fuzz():
    rng = random.Random(SEED + 2)
    for _ in range(5000):
        packed = rng.getrandbits(128).to_bytes(16, "big")
        text = str(ipaddress.IPv6Address(packed))  # canonical form
        assert zcidr.parse_ipv6(text) == packed


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
    cidrs = list(nets)
    values = [i + 1 for i in range(len(cidrs))]
    ordered = [(ipaddress.ip_network(c), v) for c, v in zip(cidrs, values)]
    m = zcidr.build(cidrs, values)

    for _ in range(5000):
        ip = str(ipaddress.IPv4Address(rng.getrandbits(32)))
        assert zcidr.match(m, ip) == _ref_lookup(ordered, ip)


def test_trie_matches_reference_ipv6():
    rng = random.Random(SEED + 4)
    nets = {}
    while len(nets) < 200:
        prefix = rng.randint(0, 128)
        base = rng.getrandbits(128)
        net = ipaddress.ip_network((base, prefix), strict=False)
        nets[str(net)] = None
    cidrs = list(nets)
    values = [i + 1 for i in range(len(cidrs))]
    ordered = [(ipaddress.ip_network(c), v) for c, v in zip(cidrs, values)]
    m = zcidr.build(cidrs, values)

    for _ in range(3000):
        ip = str(ipaddress.IPv6Address(rng.getrandbits(128)))
        assert zcidr.match(m, ip) == _ref_lookup(ordered, ip)


def test_batch_match_agrees_with_scalar_ipv4():
    """The batch LPM path must agree with the scalar path element-for-element."""
    rng = random.Random(SEED + 5)
    cidrs = []
    seen = set()
    while len(cidrs) < 200:
        net = ipaddress.ip_network((rng.getrandbits(32), rng.randint(0, 32)), strict=False)
        if str(net) not in seen:
            seen.add(str(net))
            cidrs.append(str(net))
    m = zcidr.build(cidrs)  # default index values

    ips = [str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(4000)]
    keys, valid = zcidr.parse_ipv4_lines("\n".join(ips))
    assert all(valid)
    values, found = zcidr.match_ipv4_many(m, keys)
    for i, ip in enumerate(ips):
        scalar = zcidr.match(m, ip)
        if scalar is None:
            assert found[i] == 0
        else:
            assert found[i] == 1 and values[i] == scalar
