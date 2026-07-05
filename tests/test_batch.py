"""Batch parse/format API: correctness, buffer-protocol I/O, edge cases."""

import ipaddress
import mmap
from array import array

import pytest

import zcidr


def test_parse_ipv4_lines_values_and_mask():
    values, mask = zcidr.parse_ipv4_lines("1.2.3.4\nbad\n8.8.8.8")
    assert list(mask) == [1, 0, 1]
    assert values[0] == int(ipaddress.IPv4Address("1.2.3.4"))
    assert values[2] == int(ipaddress.IPv4Address("8.8.8.8"))
    assert isinstance(values, array) and values.typecode == "I"


def test_parse_ipv4_lines_accepts_bytes_and_crlf():
    values, mask = zcidr.parse_ipv4_lines(b"1.1.1.1\r\n2.2.2.2\r\n")
    assert list(mask) == [1, 1]
    assert values[0] == int(ipaddress.IPv4Address("1.1.1.1"))


def test_parse_ipv4_lines_accepts_iterables():
    values, mask = zcidr.parse_ipv4_lines(["10.0.0.1", "10.0.0.2"])
    assert list(mask) == [1, 1]
    assert values[1] == int(ipaddress.IPv4Address("10.0.0.2"))
    # generators work too
    values, mask = zcidr.parse_ipv4_lines(f"10.0.0.{i}" for i in range(1, 4))
    assert list(mask) == [1, 1, 1]


def test_parse_ipv4_lines_accepts_open_text_file(tmp_path):
    p = tmp_path / "ips.txt"
    p.write_text("1.2.3.4\nbad\n8.8.8.8\n")
    with open(p) as f:  # iterating a text file yields lines with trailing \n
        values, mask = zcidr.parse_ipv4_lines(f)
    assert list(mask) == [1, 0, 1]
    assert values[2] == int(ipaddress.IPv4Address("8.8.8.8"))


def test_parse_ipv4_lines_mmap_zero_copy(tmp_path):
    p = tmp_path / "ips.txt"
    p.write_bytes(b"1.2.3.4\n8.8.8.8")
    with open(p, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        values, mask = zcidr.parse_ipv4_lines(mm)
    assert list(mask) == [1, 1]
    assert values[1] == int(ipaddress.IPv4Address("8.8.8.8"))


def test_parse_lines_rejects_embedded_newlines():
    # A stray newline inside an element must raise, never silently shift
    # every subsequent record against its mask index.
    with pytest.raises(ValueError, match="newline"):
        zcidr.parse_ipv4_lines(["1.1.1.1\n2.2.2.2", "3.3.3.3"])


def test_parse_lines_iterable_chunking(monkeypatch):
    monkeypatch.setattr(zcidr, "_CHUNK_LINES", 3)  # force several chunks
    addrs = [f"10.0.0.{i}" for i in range(8)] + ["bad"]
    values, mask = zcidr.parse_ipv4_lines(iter(addrs))
    assert len(values) == 9
    assert list(mask) == [1] * 8 + [0]
    assert values[7] == int(ipaddress.IPv4Address("10.0.0.7"))


def test_ipv4_batch_roundtrip():
    addrs = ["0.0.0.0", "192.168.1.1", "255.255.255.255", "8.8.8.8"]
    values, mask = zcidr.parse_ipv4_lines(addrs)
    assert all(mask)
    out = zcidr.format_ipv4_lines(values)
    assert out.decode().split("\n") == addrs


def test_empty_inputs():
    values, mask = zcidr.parse_ipv4_lines("")
    assert len(values) == 0 and mask == b""
    assert zcidr.format_ipv4_lines(values) == b""
    packed, mask6 = zcidr.parse_ipv6_lines("")
    assert packed == b"" and mask6 == b""
    values, mask = zcidr.parse_ipv4_lines([])
    assert len(values) == 0 and mask == b""


def test_parse_ipv6_lines_and_format():
    packed, mask = zcidr.parse_ipv6_lines("::1\nnope\n2001:db8::1")
    assert list(mask) == [1, 0, 1]
    assert len(packed) == 3 * 16
    assert packed[:16] == ipaddress.IPv6Address("::1").packed
    # format the two valid records (record 1 is zeroed)
    valid_pack = packed[:16] + packed[32:]
    assert zcidr.format_ipv6_lines(valid_pack).decode().split("\n") == ["::1", "2001:db8::1"]


def test_format_ipv4_lines_accepts_raw_bytes_and_ints():
    # A raw uint32 buffer (native order) works via the buffer protocol.
    values, _ = zcidr.parse_ipv4_lines(["1.2.3.4", "8.8.8.8"])
    assert zcidr.format_ipv4_lines(values.tobytes()) == b"1.2.3.4\n8.8.8.8"
    # So does a plain iterable of ints.
    assert zcidr.format_ipv4_lines([int(ipaddress.IPv4Address("1.2.3.4"))]) == b"1.2.3.4"


def test_format_ipv6_lines_accepts_iterable_of_packed():
    packed = [ipaddress.IPv6Address("::1").packed, ipaddress.IPv6Address("2001:db8::1").packed]
    assert zcidr.format_ipv6_lines(packed).decode().split("\n") == ["::1", "2001:db8::1"]


def test_non_ascii_lines_are_invalid_not_fatal():
    values, mask = zcidr.parse_ipv4_lines("1.2.3.4\n1.2.3.é\n8.8.8.8")
    assert list(mask) == [1, 0, 1]


def test_bad_buffer_length():
    with pytest.raises(ValueError):
        zcidr.format_ipv4_lines(b"\x01\x02\x03")  # not a multiple of 4
    with pytest.raises(ValueError):
        zcidr.format_ipv6_lines(b"\x00" * 15)  # not a multiple of 16


def test_numpy_interop_if_available():
    np = pytest.importorskip("numpy")
    values, _ = zcidr.parse_ipv4_lines(["1.2.3.4", "8.8.8.8"])
    arr = np.frombuffer(values, dtype=np.uint32)
    # numpy array is a valid input buffer (zero-copy), no numpy dependency in zcidr
    out = zcidr.format_ipv4_lines(arr)
    assert out == b"1.2.3.4\n8.8.8.8"
