import pytest

import zcidr as z


def test_longest_prefix_match_default_index_values():
    m = z.build(["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"])
    # default values are the index in the cidrs list
    assert z.match(m, "10.1.2.5") == 2
    assert z.match(m, "10.1.9.9") == 1
    assert z.match(m, "10.9.9.9") == 0
    assert z.match(m, "11.0.0.1") is None


def test_custom_values_and_overwrite():
    m = z.build(["0.0.0.0/0", "192.168.0.0/16"], values=[42, 7])
    assert z.match(m, "8.8.8.8") == 42
    assert z.match(m, "192.168.5.5") == 7


def test_ipv6_and_family_isolation():
    m = z.build(
        ["2001:db8::/32", "2001:db8:abcd::/48", "10.0.0.0/8"],
        values=[10, 20, 1],
    )
    assert z.match(m, "2001:db8:abcd::1") == 20
    assert z.match(m, "2001:db8:1::1") == 10
    assert z.match(m, "2001:dead::1") is None
    assert z.match(m, "10.5.5.5") == 1


def test_contains():
    m = z.build(["10.0.0.0/8", "2001:db8::/32"])
    assert z.contains(m, "10.1.2.3")
    assert z.contains(m, "2001:db8::1")
    assert not z.contains(m, "8.8.8.8")


def test_uint64_values():
    big = 0xFFFFFFFFFFFFFFFF
    m = z.build(["10.0.0.0/8"], values=[big])
    assert z.match(m, "10.1.1.1") == big


def test_invalid_cidr_and_value():
    with pytest.raises(z.AddressError):
        z.build(["not-a-cidr"])
    with pytest.raises(z.AddressError):
        z.build(["10.0.0.0/33"])
    with pytest.raises(ValueError):
        z.build(["10.0.0.0/8"], values=[-1])


def test_free_is_idempotent_and_guards():
    m = z.build(["10.0.0.0/8"])
    assert z.match(m, "10.1.1.1") == 0
    z.free(m)
    z.free(m)  # idempotent, no crash
    with pytest.raises(ValueError):
        z.match(m, "10.1.1.1")


def test_batch_match_ipv4():
    m = z.build(["10.0.0.0/8", "10.1.2.0/24"])  # values 0, 1
    keys, valid = z.parse_ipv4_lines("10.1.2.9\n10.9.9.9\n8.8.8.8")
    values, found = z.match_ipv4_many(m, keys)
    assert list(found) == [1, 1, 0]
    assert values[0] == 1  # /24
    assert values[1] == 0  # /8
    # value at a miss is unspecified but found flag is 0
    assert found[2] == 0


def test_batch_match_ipv6():
    m = z.build(["2001:db8::/32"], values=[99])
    packed, _ = z.parse_ipv6_lines("2001:db8::1\n::1")
    values, found = z.match_ipv6_many(m, packed)
    assert list(found) == [1, 0]
    assert values[0] == 99


def test_batch_match_empty():
    m = z.build(["10.0.0.0/8"])
    values, found = z.match_ipv4_many(m, z.parse_ipv4_lines("")[0])
    assert len(values) == 0
    assert found == b""
