import ipaddress

import pytest

import znetaddress as z


def test_longest_prefix_match():
    m = z.PrefixMap()
    m.add("10.0.0.0/8", 1)
    m.add("10.1.0.0/16", 2)
    m.add("10.1.2.0/24", 3)
    assert m.get("10.1.2.5") == 3
    assert m.get("10.1.9.9") == 2
    assert m.get("10.9.9.9") == 1
    assert m.get("11.0.0.1") is None
    assert m.get("11.0.0.1", "x") == "x"


def test_default_route_and_overwrite():
    m = z.PrefixMap()
    m.add("0.0.0.0/0", 42)
    m.add("192.168.0.0/16", 7)
    assert m.get("8.8.8.8") == 42
    assert m.get("192.168.5.5") == 7
    m.add("192.168.0.0/16", 99)  # overwrite
    assert m.get("192.168.5.5") == 99


def test_ipv6_and_family_isolation():
    m = z.PrefixMap()
    m.add("2001:db8::/32", 10)
    m.add("2001:db8:abcd::/48", 20)
    m.add("10.0.0.0/8", 1)
    assert m.get("2001:db8:abcd::1") == 20
    assert m.get("2001:db8:1::1") == 10
    assert m.get("2001:dead::1") is None
    assert m.get("10.5.5.5") == 1


def test_contains_and_prefixset():
    s = z.PrefixSet(["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"])
    assert "10.1.2.3" in s
    assert "192.168.1.1" in s
    assert "2001:db8::1" in s
    assert "8.8.8.8" not in s


def test_bad_cidr_and_value():
    m = z.PrefixMap()
    with pytest.raises(z.AddressError):
        m.add("not-a-cidr")
    with pytest.raises(z.AddressError):
        m.add("10.0.0.0/33")
    with pytest.raises(ValueError):
        m.add("10.0.0.0/8", -1)


def test_context_manager_and_close():
    with z.PrefixMap() as m:
        m.add("10.0.0.0/8", 1)
        assert m.get("10.1.1.1") == 1
    with pytest.raises(ValueError):
        m.get("10.1.1.1")  # closed


def test_uint64_values():
    m = z.PrefixMap()
    big = 0xFFFFFFFFFFFFFFFF
    m.add("10.0.0.0/8", big)
    assert m.get("10.1.1.1") == big
