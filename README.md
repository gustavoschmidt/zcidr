# znetaddress

A fast, reliable **IP / CIDR toolkit** for Python, backed by a native **Zig**
core over a narrow C ABI.

The stdlib `ipaddress` and `netaddr` are pure-Python and slow at scale.
`znetaddress` keeps a Pythonic API but does the work in Zig: parsing/normalizing
IPv4 & IPv6, and **longest-prefix-match** containment over large CIDR rule sets
via a radix trie.

## Install

```sh
pip install znetaddress
```

Wheels bundle the prebuilt native library (loaded with `cffi` in ABI mode), so
there is no compiler requirement at install time.

## Usage

```python
import znetaddress as z

z.parse_ipv4("192.168.0.1")        # -> 3232235521
z.format_ipv4(3232235521)          # -> "192.168.0.1"
z.normalize("2001:0db8:0000::1")   # -> "2001:db8::1"
z.is_valid("::gg")                 # -> False

# Longest-prefix-match over a large rule set:
m = z.PrefixMap()
m.add("10.0.0.0/8", 1)
m.add("10.1.2.0/24", 2)
m.get("10.1.2.9")                  # -> 2  (most specific match)
m.get("8.8.8.8")                   # -> None

# Fast "is this IP in any of these CIDRs?" membership:
allow = z.PrefixSet(["10.0.0.0/8", "2001:db8::/32"])
"10.9.9.9" in allow                # -> True
```

## Performance

Longest-prefix-match containment — the networking/security hot path — runs ~2
orders of magnitude faster than a stdlib scan and ~10× faster than
`netaddr.IPSet`. See [benchmarks/](benchmarks/README.md).

## Building from source

Requires [Zig](https://ziglang.org) 0.16 (or `pip install ziglang`).

```sh
zig build -Doptimize=ReleaseFast   # native library -> zig-out/lib/
zig build test                     # Zig unit tests
pip install -e . && pytest         # Python wrapper + test suite
```

## Architecture

- **Core** (`src/`): Zig, exposed over a C ABI (`include/znetaddress.h`).
  Bytes / ints / bools across the FFI line; a longest-prefix-match trie for CIDR
  containment.
- **Wrapper** (`znetaddress/`): `cffi` ABI/dlopen binding — no build step at
  install, one wheel per platform serves all supported Python versions.
- **Packaging**: `cibuildwheel` (manylinux / macOS / Windows) with the native
  toolchain supplied by the `ziglang` wheel.
