"""zcidr — a fast, functional IP / CIDR toolkit backed by a native Zig core.

The API is deliberately functional: simple values in, simple values out, no
address objects. Scalar helpers cover one-off use; the ``*_many`` / ``*_lines``
batch functions cross the native boundary once for a whole workload (buffers in,
arrays out) and are where the speed lives.

Longest-prefix-match uses an opaque *matcher handle* built with :func:`build`;
free functions (:func:`match`, :func:`contains`, :func:`match_ipv4_many`)
operate on it. The handle frees its native memory automatically when garbage
collected, or eagerly via :func:`free`.

Batch conventions:
  * Inputs accept anything supporting the buffer protocol (``bytes``,
    ``array.array``, ``memoryview``, NumPy arrays) — zero-copy, no NumPy
    dependency.
  * Parse results return ``(values, valid_mask)``; ``valid_mask`` is a ``bytes``
    of 1/0 per record (invalid records parse to 0 / all-zero). Lookups return
    ``(values, found_mask)``. This keeps partial failure vectorizable instead of
    raising mid-batch.
  * IPv4 values are a ``array('I')`` (uint32); IPv6 addresses are packed 16-byte
    records in a single ``bytes``; lookup values are ``array('Q')`` (uint64).
"""

from __future__ import annotations

import weakref
from array import array

from ._core import ERR_INVALID, ERR_NOTFOUND, OK, ffi, lib

__all__ = [
    "__version__",
    "version",
    "AddressError",
    # scalar
    "parse_ipv4",
    "format_ipv4",
    "parse_ipv6",
    "format_ipv6",
    "normalize",
    "is_valid",
    # batch
    "parse_ipv4_lines",
    "parse_ipv4_many",
    "format_ipv4_many",
    "parse_ipv6_lines",
    "parse_ipv6_many",
    "format_ipv6_many",
    # longest-prefix-match
    "build",
    "free",
    "match",
    "contains",
    "match_ipv4_many",
    "match_ipv6_many",
]

__version__ = "0.1.0"

_U64_MAX = 0xFFFFFFFFFFFFFFFF


class AddressError(ValueError):
    """Raised when a string is not a valid IP address or CIDR network."""


def version() -> tuple[int, int, int]:
    """Return the native core version as ``(major, minor, patch)``."""
    v = lib.zcidr_version()
    return ((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)


def _encode(s: str) -> bytes:
    try:
        return s.encode("ascii")
    except (UnicodeEncodeError, AttributeError) as exc:
        raise AddressError(f"invalid address: {s!r}") from exc


def _as_bytes(data) -> bytes:
    if isinstance(data, str):
        return _encode(data)
    return bytes(data) if not isinstance(data, (bytes, bytearray)) else data


def _to_array(typecode: str, cdata, nbytes: int) -> array:
    a = array(typecode)
    a.frombytes(bytes(ffi.buffer(cdata, nbytes)))
    return a


# --- scalar ----------------------------------------------------------------


def parse_ipv4(s: str) -> int:
    """Parse a dotted-decimal IPv4 address into its 32-bit integer value."""
    data = _encode(s)
    out = ffi.new("uint32_t *")
    if lib.zcidr_ipv4_parse(data, len(data), out) != OK:
        raise AddressError(f"invalid IPv4 address: {s!r}")
    return int(out[0])


def format_ipv4(value: int) -> str:
    """Format a 32-bit integer as a dotted-decimal IPv4 address."""
    if not 0 <= value <= 0xFFFFFFFF:
        raise AddressError(f"IPv4 value out of range: {value}")
    buf = ffi.new("uint8_t[16]")
    n = lib.zcidr_ipv4_format(value, buf, len(buf))
    if n < 0:
        raise AddressError(f"could not format IPv4 value: {value}")
    return bytes(ffi.buffer(buf, n)).decode("ascii")


def parse_ipv6(s: str) -> bytes:
    """Parse an IPv6 address into 16 network-order bytes."""
    data = _encode(s)
    out = ffi.new("uint8_t[16]")
    if lib.zcidr_ipv6_parse(data, len(data), out) != OK:
        raise AddressError(f"invalid IPv6 address: {s!r}")
    return bytes(ffi.buffer(out, 16))


def format_ipv6(packed: bytes) -> str:
    """Format 16 network-order bytes as an RFC 5952 canonical IPv6 string."""
    if len(packed) != 16:
        raise AddressError("IPv6 packed form must be exactly 16 bytes")
    src = ffi.new("uint8_t[16]", list(packed))
    buf = ffi.new("uint8_t[46]")
    n = lib.zcidr_ipv6_format(src, buf, len(buf))
    if n < 0:
        raise AddressError("could not format IPv6 bytes")
    return bytes(ffi.buffer(buf, n)).decode("ascii")


def normalize(s: str) -> str:
    """Return the canonical string form of an IPv4 or IPv6 address."""
    if ":" in s:
        return format_ipv6(parse_ipv6(s))
    return format_ipv4(parse_ipv4(s))


def is_valid(s: str) -> bool:
    """Return True if ``s`` is a valid IPv4 or IPv6 address."""
    try:
        normalize(s)
        return True
    except AddressError:
        return False


# --- batch parse / format --------------------------------------------------


def parse_ipv4_lines(data) -> tuple[array, bytes]:
    """Parse newline-delimited IPv4 addresses (``str`` or ``bytes``).

    Returns ``(values: array('I'), valid_mask: bytes)`` with one entry per line
    (a trailing newline is ignored; CRLF is handled).
    """
    data = _as_bytes(data)
    if not data:
        return array("I"), b""
    cap = data.count(b"\n") + 1
    out_v = ffi.new("uint32_t[]", cap)
    out_m = ffi.new("uint8_t[]", cap)
    n = lib.zcidr_ipv4_parse_lines(data, len(data), out_v, out_m, cap)
    if n < 0:  # pragma: no cover - cap is a safe upper bound
        raise RuntimeError("zcidr_ipv4_parse_lines overflowed its buffer")
    return _to_array("I", out_v, 4 * n), bytes(ffi.buffer(out_m, n))


def parse_ipv4_many(addrs) -> tuple[array, bytes]:
    """Like :func:`parse_ipv4_lines` but over an iterable of address strings."""
    return parse_ipv4_lines("\n".join(addrs))


def format_ipv4_many(values) -> bytes:
    """Format a buffer of uint32 values as newline-separated dotted-decimal.

    ``values`` is any uint32 buffer (``array('I')``, NumPy ``uint32``, or raw
    ``bytes`` whose length is a multiple of 4). Returns ``bytes`` (no trailing
    newline).
    """
    src = ffi.from_buffer(values)
    nbytes = len(src)
    if nbytes % 4:
        raise ValueError("values buffer length must be a multiple of 4 bytes")
    n = nbytes // 4
    if n == 0:
        return b""
    vptr = ffi.cast("uint32_t *", src)
    cap = n * 16  # "255.255.255.255\n"
    out = ffi.new("uint8_t[]", cap)
    total = lib.zcidr_ipv4_format_lines(vptr, n, out, cap)
    if total < 0:  # pragma: no cover
        raise RuntimeError("format buffer too small")
    return bytes(ffi.buffer(out, total))


def parse_ipv6_lines(data) -> tuple[bytes, bytes]:
    """Parse newline-delimited IPv6 addresses.

    Returns ``(packed: bytes, valid_mask: bytes)`` where ``packed`` holds 16
    network-order bytes per record contiguously.
    """
    data = _as_bytes(data)
    if not data:
        return b"", b""
    cap = data.count(b"\n") + 1
    out_b = ffi.new("uint8_t[]", cap * 16)
    out_m = ffi.new("uint8_t[]", cap)
    n = lib.zcidr_ipv6_parse_lines(data, len(data), out_b, out_m, cap)
    if n < 0:  # pragma: no cover
        raise RuntimeError("zcidr_ipv6_parse_lines overflowed its buffer")
    return bytes(ffi.buffer(out_b, n * 16)), bytes(ffi.buffer(out_m, n))


def parse_ipv6_many(addrs) -> tuple[bytes, bytes]:
    """Like :func:`parse_ipv6_lines` but over an iterable of address strings."""
    return parse_ipv6_lines("\n".join(addrs))


def format_ipv6_many(packed) -> bytes:
    """Format a buffer of packed 16-byte records as newline-separated strings.

    ``packed`` is any buffer whose length is a multiple of 16. Returns ``bytes``
    (no trailing newline).
    """
    src = ffi.from_buffer(packed)
    nbytes = len(src)
    if nbytes % 16:
        raise ValueError("packed buffer length must be a multiple of 16 bytes")
    n = nbytes // 16
    if n == 0:
        return b""
    bptr = ffi.cast("uint8_t *", src)
    cap = n * 46  # max canonical length + newline
    out = ffi.new("uint8_t[]", cap)
    total = lib.zcidr_ipv6_format_lines(bptr, n, out, cap)
    if total < 0:  # pragma: no cover
        raise RuntimeError("format buffer too small")
    return bytes(ffi.buffer(out, total))


# --- longest-prefix-match --------------------------------------------------


class _Handle:
    """Opaque matcher handle. Frees its native trie on GC or via free()."""

    __slots__ = ("_ptr", "_finalizer", "__weakref__")

    def __init__(self, ptr) -> None:
        self._ptr = ptr
        self._finalizer = weakref.finalize(self, lib.zcidr_trie_destroy, ptr)


def _ptr(handle: _Handle):
    fin = getattr(handle, "_finalizer", None)
    if fin is None or not fin.alive:
        raise ValueError("matcher handle has been freed")
    return handle._ptr


def _insert(ptr, cidr: str, value: int) -> None:
    if not 0 <= value <= _U64_MAX:
        raise ValueError(f"value out of uint64 range: {value}")
    data = _encode(cidr)
    rc = lib.zcidr_trie_insert_cidr(ptr, data, len(data), value)
    if rc == ERR_INVALID:
        raise AddressError(f"invalid CIDR: {cidr!r}")
    if rc != OK:  # pragma: no cover
        raise MemoryError("could not insert into trie")


def build(cidrs, values=None) -> _Handle:
    """Build a longest-prefix-match matcher from CIDR networks.

    ``cidrs`` is an iterable of strings (``"10.0.0.0/8"``, ``"2001:db8::/32"``).
    ``values`` is an optional parallel iterable of uint64 values returned on a
    match; if omitted, each network's value is its index in ``cidrs``. Returns an
    opaque handle for :func:`match` / :func:`contains` / the ``*_many`` lookups.
    """
    ptr = lib.zcidr_trie_create()
    if ptr == ffi.NULL:
        raise MemoryError("could not allocate trie")
    handle = _Handle(ptr)  # owns the trie; frees it if we raise below
    if values is None:
        for i, cidr in enumerate(cidrs):
            _insert(ptr, cidr, i)
    else:
        for cidr, value in zip(cidrs, values):
            _insert(ptr, cidr, value)
    return handle


def free(handle: _Handle) -> None:
    """Eagerly release a matcher's native memory. Idempotent."""
    fin = getattr(handle, "_finalizer", None)
    if fin is not None:
        fin()


def match(handle: _Handle, ip: str):
    """Return the value of the longest prefix matching ``ip``, or ``None``."""
    ptr = _ptr(handle)
    if ":" in ip:
        addr = parse_ipv6(ip)
        is_v6 = 1
    else:
        addr = parse_ipv4(ip).to_bytes(4, "big")
        is_v6 = 0
    out = ffi.new("uint64_t *")
    rc = lib.zcidr_trie_lookup(ptr, is_v6, addr, out)
    if rc == OK:
        return int(out[0])
    if rc == ERR_NOTFOUND:
        return None
    raise AddressError(f"invalid address: {ip!r}")


def contains(handle: _Handle, ip: str) -> bool:
    """Return True if any network in the matcher contains ``ip``."""
    return match(handle, ip) is not None


def match_ipv4_many(handle: _Handle, keys) -> tuple[array, bytes]:
    """Batch longest-prefix-match over a uint32 IPv4 key buffer.

    ``keys`` is any uint32 buffer (e.g. the ``values`` from
    :func:`parse_ipv4_lines`). Returns ``(values: array('Q'), found_mask: bytes)``.
    """
    ptr = _ptr(handle)
    src = ffi.from_buffer(keys)
    nbytes = len(src)
    if nbytes % 4:
        raise ValueError("keys buffer length must be a multiple of 4 bytes")
    n = nbytes // 4
    if n == 0:
        return array("Q"), b""
    kptr = ffi.cast("uint32_t *", src)
    out_v = ffi.new("uint64_t[]", n)
    out_f = ffi.new("uint8_t[]", n)
    lib.zcidr_trie_lookup_v4_many(ptr, kptr, n, out_v, out_f)
    return _to_array("Q", out_v, 8 * n), bytes(ffi.buffer(out_f, n))


def match_ipv6_many(handle: _Handle, keys) -> tuple[array, bytes]:
    """Batch longest-prefix-match over packed 16-byte IPv6 keys.

    ``keys`` is any buffer of packed 16-byte records (e.g. the ``packed`` output
    of :func:`parse_ipv6_lines`). Returns ``(values: array('Q'), found_mask: bytes)``.
    """
    ptr = _ptr(handle)
    src = ffi.from_buffer(keys)
    nbytes = len(src)
    if nbytes % 16:
        raise ValueError("keys buffer length must be a multiple of 16 bytes")
    n = nbytes // 16
    if n == 0:
        return array("Q"), b""
    kptr = ffi.cast("uint8_t *", src)
    out_v = ffi.new("uint64_t[]", n)
    out_f = ffi.new("uint8_t[]", n)
    lib.zcidr_trie_lookup_v6_many(ptr, kptr, n, out_v, out_f)
    return _to_array("Q", out_v, 8 * n), bytes(ffi.buffer(out_f, n))
