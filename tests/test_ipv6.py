import ipaddress

import pytest

import znetaddress as z


def test_parse_roundtrip_bytes():
    assert z.parse_ipv6("::") == b"\x00" * 16
    assert z.parse_ipv6("::1") == b"\x00" * 15 + b"\x01"
    assert z.parse_ipv6("::ffff:1.2.3.4") == bytes(ipaddress.IPv6Address("::ffff:1.2.3.4").packed)


def test_canonical_matches_stdlib():
    cases = [
        "::", "::1", "1::", "2001:0db8:0000:0000:0000:0000:0000:0001",
        "2001:db8:0:0:1:0:0:1", "FE80::0202:B3FF:FE1E:8329",
        "0:0:0:0:0:ffff:1.2.3.4", "2001:db8:0:1:1:1:1:1", "1:0:0:0:0:0:0:1",
        "64:ff9b::192.0.2.33",
    ]
    for s in cases:
        assert z.normalize(s) == str(ipaddress.IPv6Address(s))


@pytest.mark.parametrize(
    "bad",
    ["", ":", ":::", "1:::2", "1::2::3", "12345::", "1:2:3:4:5:6:7",
     "1:2:3:4:5:6:7:8:9", "gggg::", "1.2.3.4", "::1.2.3", "1.2.3.4::",
     "1:2:3:4:5:6:7:8::"],
)
def test_parse_rejects(bad):
    with pytest.raises(z.AddressError):
        z.parse_ipv6(bad)


def test_format_bad_length():
    with pytest.raises(z.AddressError):
        z.format_ipv6(b"\x00" * 15)


def test_format_matches_stdlib_from_bytes():
    for text in ["::", "::1", "2001:db8::1", "fe80::1", "ff02::fb"]:
        packed = ipaddress.IPv6Address(text).packed
        assert z.format_ipv6(packed) == str(ipaddress.IPv6Address(packed))
