"""zcidr — a fast, functional IP / CIDR toolkit backed by a native Zig core.

The API is deliberately functional: simple values in, simple values out, no
address objects. Scalar helpers cover one-off use; the batch functions cross
the native boundary once for a whole workload and are where the speed lives.

Two batch conventions, by suffix:
  * ``*_lines`` — the text side. Input is newline-delimited address text:
    ``str``, any bytes-like buffer (``bytes``, ``mmap``, ``memoryview``, NumPy
    — zero-copy, no NumPy dependency), or any iterable of strings (a list, a
    generator, an open text file). Iterables are consumed in bounded chunks,
    so unbounded streams work; a string that itself contains a newline is an
    error, never a silent record shift.
  * ``*_many`` — the binary side. Input is a buffer of fixed-width records:
    uint32 values for IPv4, packed 16-byte records for IPv6.

Partial failure is vectorized, not raised: parse results are
``(values, valid_mask)`` and lookups are ``(values, found_mask)``, where each
mask is a ``bytes`` of 1/0 per record (invalid records parse to 0 / all-zero).
IPv4 values are an ``array('I')`` (uint32); IPv6 addresses are packed 16-byte
records in a single ``bytes``; lookup values are an ``array('Q')`` (uint64).

Longest-prefix-match uses an opaque *matcher* built with :func:`build`; free
functions (:func:`match`, :func:`contains`, :func:`match_lines`, ``*_many``)
operate on it. The matcher frees its native memory when garbage collected,
eagerly via :func:`free`, or scoped as a context manager
(``with build(...) as m:``).

All native calls release the GIL, so batch calls from multiple threads run
truly in parallel. The matcher itself is not synchronized: don't insert
concurrently with lookups (building happens only inside :func:`build`, so any
fully built matcher is safe to share between threads).
"""

from __future__ import annotations

import weakref
from array import array
from itertools import islice

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
    # batch: text in, binary out
    "parse_ipv4_lines",
    "parse_ipv6_lines",
    # batch: binary in, text out
    "format_ipv4_lines",
    "format_ipv6_lines",
    # longest-prefix-match
    "build",
    "free",
    "match",
    "contains",
    "match_lines",
    "match_ipv4_many",
    "match_ipv6_many",
]

__version__ = "0.2.0"

# Iterables of strings are consumed in chunks of this many lines: large enough
# to amortize the native call, small enough to bound memory on huge streams.
_CHUNK_LINES = 1 << 16

_SENTINEL = object()


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


def _text_chunks(data):
    """Yield ``(src, nbytes, nrecords, items)`` chunks of newline-joined text.

    ``data`` is a str / bytes-like blob (one zero-copy chunk, ``items`` is
    None) or an iterable of strings (bounded chunks; ``items`` is the chunk's
    list, kept for error reporting). ``src`` is safe to pass as ``uint8_t *``.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")  # non-ASCII lines become invalid records
    try:
        src = data if isinstance(data, bytes) else ffi.from_buffer(data)
    except TypeError:
        pass  # not a buffer: treat as an iterable of strings below
    else:
        nbytes = len(src)
        yield src, nbytes, lib.zcidr_line_count(src, nbytes), None
        return
    it = iter(data)
    while True:
        items = list(islice(it, _CHUNK_LINES))
        if not items:
            return
        blob = "".join(s if s.endswith("\n") else s + "\n" for s in items).encode("utf-8")
        n = lib.zcidr_line_count(blob, len(blob))
        if n != len(items):
            raise ValueError("input strings must not contain interior newlines")
        yield blob, len(blob), n, items


def _to_array(typecode: str, cdata, nbytes: int) -> array:
    a = array(typecode)
    a.frombytes(ffi.buffer(cdata, nbytes))
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
    if n < 0:  # pragma: no cover - buffer is always large enough
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
    if n < 0:  # pragma: no cover - buffer is always large enough
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
    """Parse IPv4 addresses in bulk: one native call per workload.

    ``data`` is newline-delimited text (``str`` or any bytes-like buffer,
    zero-copy) or any iterable of address strings (list, generator, open text
    file). Returns ``(values: array('I'), valid_mask: bytes)`` with one entry
    per record; CRLF and a trailing newline are handled.
    """
    values = array("I")
    mask = bytearray()
    for src, nbytes, nrec, _items in _text_chunks(data):
        if nrec == 0:
            continue
        out_v = ffi.new("uint32_t[]", nrec)
        out_m = ffi.new("uint8_t[]", nrec)
        n = lib.zcidr_ipv4_parse_lines(src, nbytes, out_v, out_m, nrec)
        if n < 0:  # pragma: no cover - nrec is the exact record count
            raise RuntimeError("zcidr_ipv4_parse_lines overflowed its buffer")
        values.frombytes(ffi.buffer(out_v, 4 * n))
        mask += ffi.buffer(out_m, n)
    return values, bytes(mask)


def parse_ipv6_lines(data) -> tuple[bytes, bytes]:
    """Parse IPv6 addresses in bulk (same inputs as :func:`parse_ipv4_lines`).

    Returns ``(packed: bytes, valid_mask: bytes)`` where ``packed`` holds 16
    network-order bytes per record contiguously.
    """
    packed = bytearray()
    mask = bytearray()
    for src, nbytes, nrec, _items in _text_chunks(data):
        if nrec == 0:
            continue
        out_b = ffi.new("uint8_t[]", nrec * 16)
        out_m = ffi.new("uint8_t[]", nrec)
        n = lib.zcidr_ipv6_parse_lines(src, nbytes, out_b, out_m, nrec)
        if n < 0:  # pragma: no cover - nrec is the exact record count
            raise RuntimeError("zcidr_ipv6_parse_lines overflowed its buffer")
        packed += ffi.buffer(out_b, n * 16)
        mask += ffi.buffer(out_m, n)
    return bytes(packed), bytes(mask)


def format_ipv4_lines(values) -> bytes:
    """Format uint32 IPv4 values as newline-separated dotted-decimal ``bytes``.

    ``values`` is any uint32 buffer (``array('I')``, NumPy ``uint32``, raw
    ``bytes`` whose length is a multiple of 4) or an iterable of ints. No
    trailing newline.
    """
    try:
        src = ffi.from_buffer(values)
    except TypeError:
        values = array("I", values)
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


def format_ipv6_lines(packed) -> bytes:
    """Format packed 16-byte IPv6 records as newline-separated ``bytes``.

    ``packed`` is any buffer whose length is a multiple of 16, or an iterable
    of 16-byte ``bytes``. No trailing newline.
    """
    try:
        src = ffi.from_buffer(packed)
    except TypeError:
        packed = b"".join(packed)
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


class _Matcher:
    """Opaque matcher handle. Frees its native trie on GC, free(), or exit
    from a ``with`` block."""

    __slots__ = ("_ptr", "_finalizer", "__weakref__")

    def __init__(self, ptr) -> None:
        self._ptr = ptr
        self._finalizer = weakref.finalize(self, lib.zcidr_trie_destroy, ptr)

    def __enter__(self) -> "_Matcher":
        return self

    def __exit__(self, *exc) -> None:
        self._finalizer()


def _ptr(matcher: _Matcher):
    fin = getattr(matcher, "_finalizer", None)
    if fin is None or not fin.alive:
        raise ValueError("matcher has been freed")
    return matcher._ptr


def _bad_record(src, nbytes, items, i) -> str:
    """Recover record ``i`` of a chunk for an error message (slow path)."""
    if items is not None:
        return repr(items[i])
    blob = src if isinstance(src, bytes) else bytes(ffi.buffer(src, nbytes))
    return repr(blob.split(b"\n")[i].rstrip(b"\r").decode("utf-8", "replace"))


def build(cidrs, values=None) -> _Matcher:
    """Build a longest-prefix-match matcher from CIDR networks.

    ``cidrs`` takes the same inputs as :func:`parse_ipv4_lines` — newline-
    delimited text (str or bytes-like buffer) or any iterable of strings —
    and families can be mixed (``"10.0.0.0/8"``, ``"2001:db8::/32"``; a bare
    address is a host route). Insertion is one native call per workload.

    ``values`` optionally assigns each network the uint64 returned on a
    match: a uint64 buffer (``array('Q')``, NumPy ``uint64``) or an iterable
    of ints, with exactly one value per network. If omitted, each network's
    value is its index in ``cidrs``.

    An invalid CIDR raises :class:`AddressError` naming the record — rule
    sets are curated inputs, unlike bulk address logs. The result works with
    :func:`match` / :func:`contains` / :func:`match_lines` / the ``*_many``
    lookups, and can be used as a context manager.
    """
    if values is None:
        vptr, viter, nvals = None, None, 0
    else:
        try:
            vbuf = ffi.from_buffer(values)
        except TypeError:
            vptr, viter = None, iter(values)
        else:
            if len(vbuf) % 8:
                raise ValueError("values buffer length must be a multiple of 8 bytes")
            vptr, viter, nvals = ffi.cast("uint64_t *", vbuf), None, len(vbuf) // 8

    ptr = lib.zcidr_trie_create()
    if ptr == ffi.NULL:  # pragma: no cover
        raise MemoryError("could not allocate trie")
    matcher = _Matcher(ptr)  # owns the trie; frees it if we raise below

    total = 0
    for src, nbytes, nrec, items in _text_chunks(cidrs):
        if nrec == 0:
            continue
        if vptr is not None:
            if total + nrec > nvals:
                raise ValueError("fewer values than cidrs")
            chunk_values = vptr + total
        elif viter is not None:
            try:
                chunk = array("Q", islice(viter, nrec))
            except OverflowError as exc:
                raise ValueError(f"value out of uint64 range: {exc}") from exc
            if len(chunk) != nrec:
                raise ValueError("fewer values than cidrs")
            chunk_values = ffi.cast("uint64_t *", ffi.from_buffer(chunk))
        else:
            chunk_values = ffi.NULL
        out_valid = ffi.new("uint8_t[]", nrec)
        n = lib.zcidr_trie_insert_lines(ptr, src, nbytes, chunk_values, total, out_valid, nrec)
        if n < 0:  # pragma: no cover
            raise MemoryError("could not insert into trie")
        bad = bytes(ffi.buffer(out_valid, n)).find(0)
        if bad != -1:
            raise AddressError(
                f"invalid CIDR at index {total + bad}: {_bad_record(src, nbytes, items, bad)}"
            )
        total += n

    if values is not None:
        leftover = (nvals > total) if vptr is not None else next(viter, _SENTINEL) is not _SENTINEL
        if leftover:
            raise ValueError("more values than cidrs")
    return matcher


def free(matcher: _Matcher) -> None:
    """Eagerly release a matcher's native memory. Idempotent."""
    fin = getattr(matcher, "_finalizer", None)
    if fin is not None:
        fin()


def match(matcher: _Matcher, ip: str):
    """Return the value of the longest prefix matching ``ip``, or ``None``."""
    ptr = _ptr(matcher)
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
    raise AddressError(f"invalid address: {ip!r}")  # pragma: no cover


def contains(matcher: _Matcher, ip: str) -> bool:
    """Return True if any network in the matcher contains ``ip``."""
    return match(matcher, ip) is not None


def match_lines(matcher: _Matcher, data) -> tuple[array, bytes]:
    """Fused batch parse + longest-prefix-match over IP address text.

    ``data`` takes the same inputs as :func:`parse_ipv4_lines`, and IPv4/IPv6
    lines can be mixed — each record's family is auto-detected. One native
    pass parses and matches; nothing intermediate is materialized. Returns
    ``(values: array('Q'), found_mask: bytes)``; a record that is invalid or
    matches no network is simply not-found.
    """
    ptr = _ptr(matcher)
    values = array("Q")
    found = bytearray()
    for src, nbytes, nrec, _items in _text_chunks(data):
        if nrec == 0:
            continue
        out_v = ffi.new("uint64_t[]", nrec)
        out_f = ffi.new("uint8_t[]", nrec)
        n = lib.zcidr_trie_match_lines(ptr, src, nbytes, out_v, out_f, nrec)
        if n < 0:  # pragma: no cover - nrec is the exact record count
            raise RuntimeError("zcidr_trie_match_lines overflowed its buffer")
        values.frombytes(ffi.buffer(out_v, 8 * n))
        found += ffi.buffer(out_f, n)
    return values, bytes(found)


def match_ipv4_many(matcher: _Matcher, keys) -> tuple[array, bytes]:
    """Batch longest-prefix-match over a uint32 IPv4 key buffer.

    ``keys`` is any uint32 buffer (e.g. the ``values`` from
    :func:`parse_ipv4_lines`). Returns ``(values: array('Q'), found_mask: bytes)``.
    """
    ptr = _ptr(matcher)
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


def match_ipv6_many(matcher: _Matcher, keys) -> tuple[array, bytes]:
    """Batch longest-prefix-match over packed 16-byte IPv6 keys.

    ``keys`` is any buffer of packed 16-byte records (e.g. the ``packed``
    output of :func:`parse_ipv6_lines`). Returns
    ``(values: array('Q'), found_mask: bytes)``.
    """
    ptr = _ptr(matcher)
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
