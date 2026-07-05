# zcidr

**Parse millions of IP addresses per second and match them against huge CIDR
rule sets — from Python.**

`zcidr` is a fast, functional IP / CIDR toolkit backed by a native
[Zig](https://ziglang.org) core. On an ordinary laptop it parses **44M IPv4
addresses/s** (~43× the stdlib) and answers "is this IP in any of these 2,000
networks?" at **19M queries/s** — about **2,900×** a stdlib scan and **170×**
`netaddr` ([benchmarks](benchmarks/README.md)).

If you filter request logs against blocklists, geo-map flows, enrich telemetry
with network tags, or score millions of addresses against threat feeds, the
address handling itself stops being your bottleneck.

## Why it's fast

Pure-Python IP libraries pay twice: interpreted parsing, and one boxed address
object per element. `zcidr` removes both costs:

- **A native core.** Parsing, formatting, and longest-prefix-match run in
  optimized Zig behind a narrow C ABI.
- **Batch by design.** The `*_lines` / `*_many` functions cross the
  Python↔native boundary **once per workload**, not once per address —
  buffers in, arrays out, no per-element objects. Errors don't interrupt a
  batch either: results carry a 1/0 validity mask instead of raising halfway.
- **Functional API.** Simple values in, simple values out — ints, `bytes`,
  `array` — which is exactly what you can hand to NumPy, pandas, or a file
  without conversion.
- **True parallelism.** Every native call releases the GIL, so batch calls
  scale across threads.

## Install

```sh
pip install zcidr
```

Wheels bundle the prebuilt native library (loaded with `cffi` in ABI mode); no
compiler is needed at install time. One wheel per platform serves every
supported Python version (3.10+).

## Sixty seconds of zcidr

```python
import zcidr

# --- one-offs -------------------------------------------------------------
zcidr.parse_ipv4("192.168.0.1")        # -> 3232235521
zcidr.format_ipv4(3232235521)          # -> "192.168.0.1"
zcidr.parse_ipv6("::1")                # -> b'\x00...\x01' (16 bytes)
zcidr.normalize("2001:0db8:0000::1")   # -> "2001:db8::1"
zcidr.is_valid("::gg")                 # -> False

# --- the batch path (where the speed lives) --------------------------------
# One native call for a whole file: values + validity mask, no objects.
data = open("ips.txt", "rb").read()
values, valid = zcidr.parse_ipv4_lines(data)   # array('I'), bytes of 1/0

# The same function takes str blobs, open files, generators, lists:
values, valid = zcidr.parse_ipv4_lines(["1.2.3.4", "8.8.8.8"])
zcidr.format_ipv4_lines(values)                # -> b"1.2.3.4\n8.8.8.8"

# --- CIDR matching ----------------------------------------------------------
# Build a longest-prefix matcher from any mix of IPv4/IPv6 networks.
m = zcidr.build(["10.0.0.0/8", "10.1.2.0/24", "2001:db8::/32"])

zcidr.match(m, "10.1.2.9")             # -> 1   (index of the longest match)
zcidr.match(m, "8.8.8.8")              # -> None
zcidr.contains(m, "2001:db8::5")       # -> True

# The fused fast path: parse + match a whole workload in ONE native pass.
verdicts, found = zcidr.match_lines(m, data)   # array('Q'), bytes of 1/0
```

### Values, not just membership

Each network can carry a `uint64` payload — a rule ID, an ASN, a country
code — returned on match. By default it's the network's index.

```python
m = zcidr.build(["10.0.0.0/8", "172.16.0.0/12"], values=[3356, 64512])
zcidr.match(m, "172.20.1.1")           # -> 64512
```

`build()` takes rule sets the same way the parsers take addresses: a list, a
generator, an open file, or a newline-delimited blob — inserted with one
native batch call into an arena-allocated trie (~7M rules/s). Matchers free
their native memory on garbage collection, eagerly via `zcidr.free(m)`, or
scoped:

```python
with zcidr.build(open("blocklist.txt")) as m:
    _, found = zcidr.match_lines(m, open("access.log.ips"))
```

### Big files, zero copies

Anything with the buffer protocol is read in place — `bytes`, `bytearray`,
`memoryview`, NumPy arrays, `mmap`. A multi-gigabyte address file never gets
copied into Python:

```python
import mmap, zcidr

with open("addresses.txt", "rb") as f:
    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        values, valid = zcidr.parse_ipv4_lines(mm)   # native reads the mmap directly
```

Iterables of strings are consumed in bounded chunks, so streaming an
unbounded generator works too — but when your data can be bytes, feed bytes:
skipping per-line Python strings is itself a ~2× win.

### Input conventions at a glance

| Suffix     | Direction  | Input                                                        |
|------------|------------|--------------------------------------------------------------|
| `*_lines`  | text side  | newline-delimited `str` / bytes-like buffer, or any iterable of strings |
| `*_many`   | binary side| fixed-width record buffer (uint32 for IPv4, 16-byte packed for IPv6) |

Batch parses return `(values, valid_mask)`; batch matches return
`(values, found_mask)`. Masks are `bytes` of 1/0 per record — invalid records
never shift positions, and a string containing a stray newline raises instead
of silently desyncing.

## Performance

See [benchmarks/](benchmarks/README.md) for the harness and full tables.
Representative (Apple Silicon, `ReleaseFast`):

| Workload                        | zcidr            | vs stdlib `ipaddress` |
|---------------------------------|------------------|-----------------------|
| IPv4 parse (batch)              | 44 M ops/s       | ~43×                  |
| IPv6 parse (batch)              | 7.2 M ops/s      | ~15×                  |
| Membership, 2k rules (fused)    | 19 M queries/s   | ~2,900× (170× netaddr)|
| Matcher build, 200k rules       | 3.7–7 M rules/s  | 7.5×¹                 |

¹ vs merely *parsing* the rules with `ip_network()` — which builds no index.

## Building from source

Requires [Zig](https://ziglang.org) 0.16 (or `pip install ziglang`).

```sh
zig build -Doptimize=ReleaseFast   # native library -> zig-out/lib/
zig build test                     # Zig unit tests
pip install -e . && pytest         # Python wrapper + test suite
```

## Architecture

- **Core** (`src/`): Zig, exposed over a C ABI (`include/zcidr.h`). Bytes /
  ints / bools across the FFI line; an arena-backed longest-prefix-match trie
  for CIDR containment; batch parse/format/insert/match primitives that loop
  natively — including a fused parse+match kernel (`zcidr_trie_match_lines`).
- **Wrapper** (`zcidr/`): purely functional `cffi` ABI/dlopen binding — no
  build step at install, one wheel per platform for all Python versions.
- **Packaging**: `cibuildwheel` (manylinux / macOS / Windows) with the native
  toolchain supplied by the `ziglang` wheel.
