# Benchmarks

`znetaddress` vs the stdlib `ipaddress` and `netaddr`.

## Running

```sh
zig build -Doptimize=ReleaseFast   # optimized native core (important!)
python benchmarks/bench.py         # needs cffi; netaddr optional
```

## Sample results

Apple Silicon (macOS), CPython 3.12, Zig 0.16 `ReleaseFast`. Numbers vary by
machine; relative speedups are the point.

| Benchmark                          | znetaddress   | ipaddress   | netaddr     | speedup vs stdlib |
|------------------------------------|---------------|-------------|-------------|-------------------|
| IPv4 parse                         | 2.6 M ops/s   | 1.0 M ops/s | 0.9 M ops/s | **2.6×**          |
| IPv6 parse                         | 1.8 M ops/s   | 0.47 M ops/s| 0.42 M ops/s| **3.8×**          |
| CIDR membership (2k rules)         | 1.16 M ops/s  | 6.6 k ops/s¹| 112 k ops/s²| **177×** / 10× vs netaddr |

¹ `ipaddress` has no prefix index; the honest equivalent is a linear scan over
the rule set — O(rules) per query. ² `netaddr.IPSet` membership.

## Takeaway

Single-address parse is dominated by the Python↔C call overhead, so the native
core buys a solid but bounded 2–4×. The **longest-prefix-match trie** is where
the architecture pays off: containment queries over large rule sets — the
networking/security hot path the project targets — run ~2 orders of magnitude
faster than a stdlib scan and ~10× faster than `netaddr`'s `IPSet`.
