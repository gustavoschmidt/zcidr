"""znetaddress — a fast IP / CIDR toolkit backed by a native Zig core.

Address helpers (``parse_ipv4``, ``format_ipv6``, ``normalize`` …) plus
``PrefixMap`` / ``PrefixSet`` for longest-prefix-match over large CIDR rule
sets.
"""

from __future__ import annotations

from ._core import (
    ERR_INVALID,
    ERR_NOTFOUND,
    OK,
    ffi,
    lib,
)

__all__ = [
    "__version__",
    "version",
    "AddressError",
    "parse_ipv4",
    "format_ipv4",
    "parse_ipv6",
    "format_ipv6",
    "normalize",
    "is_valid",
    "PrefixMap",
    "PrefixSet",
]


class AddressError(ValueError):
    """Raised when a string is not a valid IP address or CIDR network."""


def version() -> tuple[int, int, int]:
    """Return the native core version as a ``(major, minor, patch)`` tuple."""
    v = lib.znet_version()
    return ((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)


__version__ = "0.1.0"


def _encode(s: str) -> bytes:
    try:
        return s.encode("ascii")
    except (UnicodeEncodeError, AttributeError) as exc:
        raise AddressError(f"invalid address: {s!r}") from exc


# --- IPv4 ------------------------------------------------------------------


def parse_ipv4(s: str) -> int:
    """Parse a dotted-decimal IPv4 address into its 32-bit integer value."""
    data = _encode(s)
    out = ffi.new("uint32_t *")
    if lib.znet_ipv4_parse(data, len(data), out) != OK:
        raise AddressError(f"invalid IPv4 address: {s!r}")
    return int(out[0])


def format_ipv4(value: int) -> str:
    """Format a 32-bit integer as a dotted-decimal IPv4 address."""
    if not 0 <= value <= 0xFFFFFFFF:
        raise AddressError(f"IPv4 value out of range: {value}")
    buf = ffi.new("uint8_t[16]")
    n = lib.znet_ipv4_format(value, buf, len(buf))
    if n < 0:
        raise AddressError(f"could not format IPv4 value: {value}")
    return bytes(ffi.buffer(buf, n)).decode("ascii")


# --- IPv6 ------------------------------------------------------------------


def parse_ipv6(s: str) -> bytes:
    """Parse an IPv6 address into 16 network-order bytes."""
    data = _encode(s)
    out = ffi.new("uint8_t[16]")
    if lib.znet_ipv6_parse(data, len(data), out) != OK:
        raise AddressError(f"invalid IPv6 address: {s!r}")
    return bytes(ffi.buffer(out, 16))


def format_ipv6(packed: bytes) -> str:
    """Format 16 network-order bytes as an RFC 5952 canonical IPv6 string."""
    if len(packed) != 16:
        raise AddressError("IPv6 packed form must be exactly 16 bytes")
    src = ffi.new("uint8_t[16]", list(packed))
    buf = ffi.new("uint8_t[46]")
    n = lib.znet_ipv6_format(src, buf, len(buf))
    if n < 0:
        raise AddressError("could not format IPv6 bytes")
    return bytes(ffi.buffer(buf, n)).decode("ascii")


# --- Family-agnostic helpers ----------------------------------------------


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


# --- Longest-prefix-match --------------------------------------------------

_MISSING = object()


class PrefixMap:
    """Longest-prefix-match map from CIDR networks to integer values.

    Add networks with :meth:`add`, then query an address with :meth:`get` /
    ``in``; the value of the most specific (longest) matching prefix wins.
    Values are unsigned 64-bit integers. Backed by a native radix trie whose
    memory is released on :meth:`close`, ``__del__``, or context-manager exit.
    """

    __slots__ = ("_t",)

    def __init__(self) -> None:
        t = lib.znet_trie_create()
        if t == ffi.NULL:
            raise MemoryError("could not allocate prefix trie")
        self._t = t

    def add(self, cidr: str, value: int = 0) -> None:
        """Insert a CIDR network (e.g. ``"10.0.0.0/8"``) with an integer value."""
        if self._t == ffi.NULL:
            raise ValueError("PrefixMap is closed")
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"value out of uint64 range: {value}")
        data = _encode(cidr)
        rc = lib.znet_trie_insert_cidr(self._t, data, len(data), value)
        if rc == ERR_INVALID:
            raise AddressError(f"invalid CIDR: {cidr!r}")
        if rc != OK:
            raise MemoryError("could not insert into prefix trie")

    def get(self, ip: str, default=None):
        """Return the value of the longest prefix matching ``ip``, else ``default``."""
        if self._t == ffi.NULL:
            raise ValueError("PrefixMap is closed")
        if ":" in ip:
            addr = parse_ipv6(ip)
            is_v6 = 1
        else:
            addr = parse_ipv4(ip).to_bytes(4, "big")
            is_v6 = 0
        out = ffi.new("uint64_t *")
        rc = lib.znet_trie_lookup(self._t, is_v6, addr, out)
        if rc == OK:
            return int(out[0])
        if rc == ERR_NOTFOUND:
            return default
        raise AddressError(f"invalid address: {ip!r}")

    def __contains__(self, ip: str) -> bool:
        return self.get(ip, _MISSING) is not _MISSING

    def close(self) -> None:
        if getattr(self, "_t", ffi.NULL) != ffi.NULL:
            lib.znet_trie_destroy(self._t)
            self._t = ffi.NULL

    def __enter__(self) -> "PrefixMap":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class PrefixSet:
    """Set of CIDR networks for fast membership tests (``ip in set``)."""

    __slots__ = ("_map",)

    def __init__(self, cidrs=None) -> None:
        self._map = PrefixMap()
        if cidrs:
            for cidr in cidrs:
                self.add(cidr)

    def add(self, cidr: str) -> None:
        self._map.add(cidr, 1)

    def __contains__(self, ip: str) -> bool:
        return ip in self._map

    def close(self) -> None:
        self._map.close()

    def __enter__(self) -> "PrefixSet":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
