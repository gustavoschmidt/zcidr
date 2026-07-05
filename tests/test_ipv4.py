import ipaddress

import pytest

import zcidr


def test_parse_basic():
    assert zcidr.parse_ipv4("1.2.3.4") == 0x01020304
    assert zcidr.parse_ipv4("0.0.0.0") == 0
    assert zcidr.parse_ipv4("255.255.255.255") == 0xFFFFFFFF
    assert zcidr.parse_ipv4("192.168.0.1") == int(ipaddress.IPv4Address("192.168.0.1"))


def test_format_roundtrip():
    for s in ["0.0.0.0", "8.8.8.8", "192.168.1.1", "255.255.255.255", "10.0.0.1"]:
        assert zcidr.format_ipv4(zcidr.parse_ipv4(s)) == s


@pytest.mark.parametrize(
    "bad",
    ["", "1.2.3", "1.2.3.4.5", "256.0.0.1", "01.2.3.4", "1.2.3.04",
     " 1.2.3.4", "1.2.3.4 ", "1.2.3.", "1..2.3", "a.b.c.d", "::1"],
)
def test_parse_rejects(bad):
    with pytest.raises(zcidr.AddressError):
        zcidr.parse_ipv4(bad)


def test_format_out_of_range():
    with pytest.raises(zcidr.AddressError):
        zcidr.format_ipv4(-1)
    with pytest.raises(zcidr.AddressError):
        zcidr.format_ipv4(0x1_0000_0000)


def test_differential_vs_stdlib():
    # Every value stdlib accepts (canonical dotted-decimal), we agree on.
    for v in [0, 1, 0xC0A80001, 0xFFFFFFFF, 0x7F000001, 0x08080808]:
        s = str(ipaddress.IPv4Address(v))
        assert zcidr.parse_ipv4(s) == v
        assert zcidr.format_ipv4(v) == s
