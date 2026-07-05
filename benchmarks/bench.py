"""Benchmark zcidr against the stdlib ``ipaddress`` and ``netaddr``.

Run with an optimized native core for a fair comparison::

    zig build -Doptimize=ReleaseFast
    python benchmarks/bench.py

``netaddr`` is optional; comparisons against it are skipped if it is not
installed.
"""

from __future__ import annotations

import ipaddress
import os
import random
import sys
from time import perf_counter

# Allow running as a plain script (`python benchmarks/bench.py`) from a checkout.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import zcidr  # noqa: E402

try:
    import netaddr

    HAVE_NETADDR = True
except ImportError:  # pragma: no cover - optional dependency
    HAVE_NETADDR = False


def _rate(fn, workload, n=None) -> float:
    """Return operations/second for ``fn`` applied over ``workload``."""
    n = len(workload) if n is None else n
    t0 = perf_counter()
    fn(workload)
    elapsed = perf_counter() - t0
    return n / elapsed if elapsed > 0 else float("inf")


# --- workloads -------------------------------------------------------------


def _ipv4_strings(n, rng):
    return [str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(n)]


def _ipv6_strings(n, rng):
    return [str(ipaddress.IPv6Address(rng.getrandbits(128))) for _ in range(n)]


def _random_cidrs(k, rng, version=4):
    bits = 32 if version == 4 else 128
    out = []
    seen = set()
    while len(out) < k:
        prefix = rng.randint(8, bits)
        net = ipaddress.ip_network((rng.getrandbits(bits), prefix), strict=False)
        if str(net) not in seen:
            seen.add(str(net))
            out.append(net)
    return out


# --- benchmarks ------------------------------------------------------------


def bench_ipv4_parse(n=200_000, seed=1):
    rng = random.Random(seed)
    data = _ipv4_strings(n, rng)
    blob = "\n".join(data).encode()
    results = {
        "zcidr (batch)": _rate(zcidr.parse_ipv4_lines, blob, n=n),
        "zcidr (scalar)": _rate(lambda w: [zcidr.parse_ipv4(s) for s in w], data),
        "ipaddress": _rate(lambda w: [int(ipaddress.IPv4Address(s)) for s in w], data),
    }
    if HAVE_NETADDR:
        results["netaddr"] = _rate(lambda w: [int(netaddr.IPAddress(s)) for s in w], data)
    assert zcidr.parse_ipv4(data[0]) == int(ipaddress.IPv4Address(data[0]))
    return results


def bench_ipv6_parse(n=200_000, seed=2):
    rng = random.Random(seed)
    data = _ipv6_strings(n, rng)
    blob = "\n".join(data).encode()
    results = {
        "zcidr (batch)": _rate(zcidr.parse_ipv6_lines, blob, n=n),
        "zcidr (scalar)": _rate(lambda w: [zcidr.parse_ipv6(s) for s in w], data),
        "ipaddress": _rate(lambda w: [ipaddress.IPv6Address(s).packed for s in w], data),
    }
    if HAVE_NETADDR:
        results["netaddr"] = _rate(lambda w: [netaddr.IPAddress(s).packed for s in w], data)
    assert zcidr.parse_ipv6(data[0]) == ipaddress.IPv6Address(data[0]).packed
    return results


def bench_membership(k=2_000, m=100_000, seed=3):
    """"Is this IP in any of these CIDRs?" over a large rule set."""
    rng = random.Random(seed)
    nets = _random_cidrs(k, rng, version=4)
    cidrs = [str(n) for n in nets]
    queries = _ipv4_strings(m, rng)
    query_blob = "\n".join(queries).encode()

    matcher = zcidr.build(cidrs)

    def z_scalar(w):
        return [zcidr.contains(matcher, ip) for ip in w]

    def z_fused(_w):
        # one native pass: parse + longest-prefix-match, straight from text
        _values, found = zcidr.match_lines(matcher, query_blob)
        return found

    py_nets = [ipaddress.ip_network(c) for c in cidrs]

    def ipaddress_run(w):
        out = []
        for ip in w:
            addr = ipaddress.ip_address(ip)
            out.append(any(addr in net for net in py_nets))
        return out

    results = {
        "zcidr (batch, fused)": _rate(z_fused, queries),
        "zcidr (scalar)": _rate(z_scalar, queries),
    }
    if HAVE_NETADDR:
        na_set = netaddr.IPSet(cidrs)

        def netaddr_run(w):
            return [netaddr.IPAddress(ip) in na_set for ip in w]

        results["netaddr"] = _rate(netaddr_run, queries)

    # ipaddress linear scan is O(k) per query; use a smaller sample so it finishes.
    sample = queries[: min(len(queries), 2_000)]
    results["ipaddress (linear scan)"] = _rate(ipaddress_run, sample)

    # correctness: fused, scalar, and the linear scan agree on the sample
    scan = ipaddress_run(sample)
    assert z_scalar(sample) == scan
    _v, found = zcidr.match_lines(matcher, sample)
    assert [bool(b) for b in found] == scan
    return results


def bench_build(k=200_000, seed=4):
    """Matcher construction: one native batch insert vs per-CIDR alternatives."""
    rng = random.Random(seed)
    cidrs = [str(n) for n in _random_cidrs(k, rng, version=4)]
    results = {
        "zcidr build()": _rate(zcidr.build, cidrs),
        "ipaddress ip_network()": _rate(lambda w: [ipaddress.ip_network(c) for c in w], cidrs),
    }
    if HAVE_NETADDR:
        results["netaddr IPSet()"] = _rate(netaddr.IPSet, cidrs)
    return results


def _print_table(title, results):
    baseline = results.get("ipaddress") or results.get("ipaddress (linear scan)") or results.get(
        "ipaddress ip_network()"
    )
    print(f"\n{title}")
    print("-" * len(title))
    for impl, rate in sorted(results.items(), key=lambda kv: -kv[1]):
        speedup = f"{rate / baseline:9.1f}x" if baseline else "    -    "
        print(f"  {impl:26} {rate:14,.0f} ops/s  {speedup}")


def main():
    print(f"zcidr {zcidr.__version__}  (native core {'.'.join(map(str, zcidr.version()))})")
    print(f"netaddr available: {HAVE_NETADDR}")
    _print_table("IPv4 parse", bench_ipv4_parse())
    _print_table("IPv6 parse", bench_ipv6_parse())
    _print_table("CIDR membership (longest-prefix / containment)", bench_membership())
    _print_table("Matcher build (200k CIDR rules)", bench_build())


if __name__ == "__main__":
    main()
