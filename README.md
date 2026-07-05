# zcidr

A fast, **functional** IP / CIDR toolkit for Python, backed by a native **Zig**
core over a narrow C ABI.

The stdlib `ipaddress` and `netaddr` are pure-Python and slow at scale, and both
are object-heavy. `zcidr` is the opposite: simple values in, simple values out,
no address objects — and it leans on **batch** operations (buffers in, arrays
out) that cross the native boundary once for a whole workload. Its focus is
**longest-prefix-match** containment over large CIDR rule sets — the
networking/security hot path — which neither stdlib does fast.

## Install

```sh
pip install zcidr
```

Wheels bundle the prebuilt native library (loaded with `cffi` in ABI mode); no
compiler is needed at install time. One wheel per platform serves every
supported Python version.

## Usage

### Scalar helpers (one-off)

```python
import zcidr as z

z.parse_ipv4("192.168.0.1")        # -> 3232235521
z.format_ipv4(3232235521)          # -> "192.168.0.1"
z.parse_ipv6("::1")                # -> b'\x00...\x01' (16 bytes)
z.normalize("2001:0db8:0000::1")   # -> "2001:db8::1"
z.is_valid("::gg")                 # -> False
```

### Batch (the fast path)

Buffers in, arrays out — one native call for the whole workload. Inputs accept
anything with the buffer protocol (`bytes`, `array`, `memoryview`, NumPy); no
NumPy dependency.

```python
# Parse a whole file of addresses at once (values + validity mask):
data = open("ips.txt", "rb").read()
values, valid = z.parse_ipv4_lines(data)   # array('I'), bytes-of-0/1

# Or from an iterable of strings:
values, valid = z.parse_ipv4_many(["1.2.3.4", "8.8.8.8"])
z.format_ipv4_many(values)                  # -> b"1.2.3.4\n8.8.8.8"
```

### Longest-prefix-match

`build()` returns an opaque matcher handle; free functions operate on it. The
handle frees itself on garbage collection, or eagerly via `free()`.

```python
m = z.build(["10.0.0.0/8", "10.1.2.0/24", "2001:db8::/32"])
z.match(m, "10.1.2.9")             # -> 1  (index of the longest match)
z.match(m, "8.8.8.8")              # -> None
z.contains(m, "2001:db8::5")       # -> True

# Custom values instead of indices:
m = z.build(["10.0.0.0/8"], values=[42])
z.match(m, "10.1.1.1")             # -> 42

# Batch lookup: parse once, match once.
keys, _ = z.parse_ipv4_lines(data)
found_values, found_mask = z.match_ipv4_many(m, keys)

z.free(m)                          # optional; GC does it otherwise
```

## Performance

See [benchmarks/](benchmarks/README.md). Representative (Apple Silicon,
`ReleaseFast`): batch IPv4 parse ~36× stdlib, and batch CIDR membership over a
2k-rule set ~2600× a stdlib linear scan / ~160× `netaddr.IPSet`.

## Building from source

Requires [Zig](https://ziglang.org) 0.16 (or `pip install ziglang`).

```sh
zig build -Doptimize=ReleaseFast   # native library -> zig-out/lib/
zig build test                     # Zig unit tests
pip install -e . && pytest         # Python wrapper + test suite
```

## Architecture

- **Core** (`src/`): Zig, exposed over a C ABI (`include/zcidr.h`). Bytes / ints
  / bools across the FFI line; a longest-prefix-match trie for CIDR containment;
  batch parse/format/lookup primitives that loop natively.
- **Wrapper** (`zcidr/`): purely functional `cffi` ABI/dlopen binding — no build
  step at install, one wheel per platform for all Python versions.
- **Packaging**: `cibuildwheel` (manylinux / macOS / Windows) with the native
  toolchain supplied by the `ziglang` wheel.
