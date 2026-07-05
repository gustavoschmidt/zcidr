"""Batch parse/format API: correctness, buffer-protocol I/O, edge cases."""

import ipaddress
from array import array

import pytest

import zcidr as z


def test_parse_ipv4_lines_values_and_mask():
    values, mask = z.parse_ipv4_lines("1.2.3.4\nbad\n8.8.8.8")
    assert list(mask) == [1, 0, 1]
    assert values[0] == int(ipaddress.IPv4Address("1.2.3.4"))
    assert values[2] == int(ipaddress.IPv4Address("8.8.8.8"))
    assert isinstance(values, array) and values.typecode == "I"


def test_parse_ipv4_lines_accepts_bytes_and_crlf():
    values, mask = z.parse_ipv4_lines(b"1.1.1.1\r\n2.2.2.2\r\n")
    assert list(mask) == [1, 1]
    assert values[0] == int(ipaddress.IPv4Address("1.1.1.1"))


def test_parse_ipv4_many_iterable():
    values, mask = z.parse_ipv4_many(["10.0.0.1", "10.0.0.2"])
    assert list(mask) == [1, 1]
    assert values[1] == int(ipaddress.IPv4Address("10.0.0.2"))


def test_ipv4_batch_roundtrip():
    addrs = ["0.0.0.0", "192.168.1.1", "255.255.255.255", "8.8.8.8"]
    values, mask = z.parse_ipv4_many(addrs)
    assert all(mask)
    out = z.format_ipv4_many(values)
    assert out.decode().split("\n") == addrs


def test_empty_inputs():
    values, mask = z.parse_ipv4_lines("")
    assert len(values) == 0 and mask == b""
    assert z.format_ipv4_many(values) == b""
    packed, mask6 = z.parse_ipv6_lines("")
    assert packed == b"" and mask6 == b""


def test_parse_ipv6_lines_and_format():
    packed, mask = z.parse_ipv6_lines("::1\nnope\n2001:db8::1")
    assert list(mask) == [1, 0, 1]
    assert len(packed) == 3 * 16
    assert packed[:16] == ipaddress.IPv6Address("::1").packed
    # format the two valid records (record 1 is zeroed)
    valid_pack = packed[:16] + packed[32:]
    assert z.format_ipv6_many(valid_pack).decode().split("\n") == ["::1", "2001:db8::1"]


def test_format_ipv4_many_accepts_raw_bytes_buffer():
    # A raw uint32 buffer (native order) also works via the buffer protocol.
    values, _ = z.parse_ipv4_many(["1.2.3.4", "8.8.8.8"])
    out = z.format_ipv4_many(values.tobytes())
    assert out == b"1.2.3.4\n8.8.8.8"


def test_bad_buffer_length():
    with pytest.raises(ValueError):
        z.format_ipv4_many(b"\x01\x02\x03")  # not a multiple of 4
    with pytest.raises(ValueError):
        z.format_ipv6_many(b"\x00" * 15)  # not a multiple of 16


def test_numpy_interop_if_available():
    np = pytest.importorskip("numpy")
    values, _ = z.parse_ipv4_many(["1.2.3.4", "8.8.8.8"])
    arr = np.frombuffer(values, dtype=np.uint32)
    # numpy array is a valid input buffer (zero-copy), no numpy dependency in zcidr
    out = z.format_ipv4_many(arr)
    assert out == b"1.2.3.4\n8.8.8.8"
