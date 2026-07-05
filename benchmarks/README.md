# Benchmarks

`zcidr` vs the stdlib `ipaddress` and `netaddr`.

## Running

```sh
zig build -Doptimize=ReleaseFast   # optimized native core (important!)
python benchmarks/bench.py         # needs cffi; netaddr optional
```

## Sample results

Apple Silicon (macOS), CPython 3.12, Zig 0.16 `ReleaseFast`, zcidr 0.2.0.
Numbers vary by machine; relative speedups are the point.

### IPv4 parse (200k random addresses)

| Implementation | Rate         | vs `ipaddress` |
|----------------|--------------|----------------|
| zcidr (batch)  | 44 M ops/s   | **43×**        |
| zcidr (scalar) | 2.7 M ops/s  | 2.6×           |
| ipaddress      | 1.0 M ops/s  | 1.0×           |
| netaddr        | 0.95 M ops/s | 0.9×           |

### IPv6 parse (200k random addresses)

| Implementation | Rate         | vs `ipaddress` |
|----------------|--------------|----------------|
| zcidr (batch)  | 7.2 M ops/s  | **15×**        |
| zcidr (scalar) | 1.8 M ops/s  | 3.7×           |
| ipaddress      | 0.50 M ops/s | 1.0×           |
| netaddr        | 0.43 M ops/s | 0.9×           |

### CIDR membership — 100k IPs against 2k rules

"Is this IP in any of these networks?" — longest-prefix-match containment.
The zcidr batch row is `match_lines()`: one native pass that parses *and*
matches, straight from newline-delimited text.

| Implementation           | Rate         | vs `ipaddress`² |
|--------------------------|--------------|-----------------|
| zcidr (batch, fused)     | 19 M ops/s   | **~2900×**      |
| zcidr (scalar)           | 1.2 M ops/s  | 177×            |
| netaddr (`IPSet`)        | 113 k ops/s  | 17×             |
| ipaddress (linear scan)¹ | 6.6 k ops/s  | 1.0×            |

¹ `ipaddress` has no prefix index; the honest equivalent is a linear scan over
the rule set — O(rules) per query. ² Scan sampled at 2k queries so it finishes.

### Matcher build (200k CIDR rules)

| Implementation           | Rate         | vs `ipaddress` |
|--------------------------|--------------|----------------|
| zcidr `build()`          | 3.7 M ops/s  | **7.5×**       |
| ipaddress `ip_network()` | 0.50 M ops/s | 1.0×           |
| netaddr `IPSet()`        | 0.33 M ops/s | 0.7×           |

(The `ipaddress` row only *parses* the rules — it builds no queryable index at
all. `build()` from an already-loaded bytes blob instead of a list reaches
~7 M rules/s; rule inserts are one native batch call into an arena-allocated
trie.)

## Takeaway

Two levers compound:

1. **The native core** does parsing and longest-prefix-match in Zig instead of
   pure Python.
2. **Batch APIs** cross the Python↔C boundary once per *workload* instead of
   once per *element*, and return arrays instead of N boxed Python objects.

Scalar single-address calls are dominated by per-call overhead, so they buy a
solid 2–4×. The batch path removes that overhead and is where the design pays
off: tens of millions of parses per second, and CIDR containment over large
rule sets ~3 orders of magnitude faster than a stdlib scan. The fused
`match_lines()` goes one step further and skips the intermediate key arrays
entirely — text in, verdicts out, one boundary crossing.
