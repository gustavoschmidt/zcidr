# Benchmarks

`zcidr` vs the stdlib `ipaddress` and `netaddr`.

## Running

```sh
zig build -Doptimize=ReleaseFast   # optimized native core (important!)
python benchmarks/bench.py         # needs cffi; netaddr optional
```

## Sample results

Apple Silicon (macOS), CPython 3.12, Zig 0.16 `ReleaseFast`. Numbers vary by
machine; relative speedups are the point.

| Benchmark                          | zcidr batch | zcidr scalar | ipaddress    | netaddr     | batch vs stdlib |
|------------------------------------|-------------|--------------|--------------|-------------|-----------------|
| IPv4 parse                         | 37 M ops/s  | 2.6 M ops/s  | 1.0 M ops/s  | 0.9 M ops/s | **~36×**        |
| IPv6 parse                         | 7 M ops/s   | 1.8 M ops/s  | 0.47 M ops/s | 0.41 M ops/s| **~15×**        |
| CIDR membership (2k rules)         | 18 M ops/s  | 1.1 M ops/s  | 6.8 k ops/s¹ | 114 k ops/s²| **~2600×** / 160× vs netaddr |

¹ `ipaddress` has no prefix index; the honest equivalent is a linear scan over
the rule set — O(rules) per query. ² `netaddr.IPSet` membership.

## Takeaway

Two levers compound:

1. **The native core** does parsing and longest-prefix-match in Zig instead of
   pure Python.
2. **Batch APIs** cross the Python↔C boundary once per *workload* instead of
   once per *element*, and return arrays instead of N boxed Python objects.

Scalar single-address parse is dominated by call overhead, so it buys a solid
2–4×. The batch path removes that overhead and is where the design pays off:
tens of millions of parses per second, and CIDR containment over large rule
sets ~3 orders of magnitude faster than a stdlib scan.
