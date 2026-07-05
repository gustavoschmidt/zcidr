from array import array

import pytest

import zcidr


def test_build_from_newline_blob_and_match_lines():
    # build() takes the same text inputs as the batch parsers, mixed families.
    m = zcidr.build(b"10.0.0.0/8\n10.1.2.0/24\n2001:db8::/32")
    values, found = zcidr.match_lines(m, "10.1.2.9\n2001:db8::1\n8.8.8.8\ngarbage")
    assert list(found) == [1, 1, 0, 0]
    assert values[0] == 1  # most specific v4
    assert values[1] == 2  # v6
    assert isinstance(values, array) and values.typecode == "Q"


def test_match_lines_iterable_and_freed_matcher():
    m = zcidr.build(["10.0.0.0/8"])
    values, found = zcidr.match_lines(m, (ip for ip in ["10.1.1.1", "9.9.9.9"]))
    assert list(found) == [1, 0]
    zcidr.free(m)
    with pytest.raises(ValueError):
        zcidr.match_lines(m, "10.1.1.1")


def test_build_default_indices_continue_across_chunks(monkeypatch):
    monkeypatch.setattr(zcidr, "_CHUNK_LINES", 2)  # force several insert chunks
    cidrs = [f"10.{i}.0.0/16" for i in range(7)]
    m = zcidr.build(iter(cidrs))
    for i in range(7):
        assert zcidr.match(m, f"10.{i}.1.1") == i


def test_build_invalid_cidr_reports_index_and_text():
    with pytest.raises(zcidr.AddressError, match=r"index 2.*not-a-cidr"):
        zcidr.build(["10.0.0.0/8", "10.1.0.0/16", "not-a-cidr"])
    with pytest.raises(zcidr.AddressError, match=r"index 1.*bad"):
        zcidr.build(b"10.0.0.0/8\nbad/9")


def test_build_values_buffer_and_length_strictness():
    vals = array("Q", [5, 6])
    m = zcidr.build(["10.0.0.0/8", "11.0.0.0/8"], values=vals)  # uint64 buffer
    assert zcidr.match(m, "11.1.1.1") == 6
    with pytest.raises(ValueError, match="fewer values"):
        zcidr.build(["10.0.0.0/8", "11.0.0.0/8"], values=[1])
    with pytest.raises(ValueError, match="more values"):
        zcidr.build(["10.0.0.0/8"], values=[1, 2])
    with pytest.raises(ValueError, match="fewer values"):
        zcidr.build(["10.0.0.0/8", "11.0.0.0/8"], values=array("Q", [1]))
    with pytest.raises(ValueError, match="more values"):
        zcidr.build(["10.0.0.0/8"], values=array("Q", [1, 2]))


def test_matcher_context_manager():
    with zcidr.build(["10.0.0.0/8"]) as m:
        assert zcidr.contains(m, "10.1.1.1")
    with pytest.raises(ValueError):
        zcidr.match(m, "10.1.1.1")  # freed on exit


def test_longest_prefix_match_default_index_values():
    m = zcidr.build(["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"])
    # default values are the index in the cidrs list
    assert zcidr.match(m, "10.1.2.5") == 2
    assert zcidr.match(m, "10.1.9.9") == 1
    assert zcidr.match(m, "10.9.9.9") == 0
    assert zcidr.match(m, "11.0.0.1") is None


def test_custom_values_and_overwrite():
    m = zcidr.build(["0.0.0.0/0", "192.168.0.0/16"], values=[42, 7])
    assert zcidr.match(m, "8.8.8.8") == 42
    assert zcidr.match(m, "192.168.5.5") == 7


def test_ipv6_and_family_isolation():
    m = zcidr.build(
        ["2001:db8::/32", "2001:db8:abcd::/48", "10.0.0.0/8"],
        values=[10, 20, 1],
    )
    assert zcidr.match(m, "2001:db8:abcd::1") == 20
    assert zcidr.match(m, "2001:db8:1::1") == 10
    assert zcidr.match(m, "2001:dead::1") is None
    assert zcidr.match(m, "10.5.5.5") == 1


def test_contains():
    m = zcidr.build(["10.0.0.0/8", "2001:db8::/32"])
    assert zcidr.contains(m, "10.1.2.3")
    assert zcidr.contains(m, "2001:db8::1")
    assert not zcidr.contains(m, "8.8.8.8")


def test_uint64_values():
    big = 0xFFFFFFFFFFFFFFFF
    m = zcidr.build(["10.0.0.0/8"], values=[big])
    assert zcidr.match(m, "10.1.1.1") == big


def test_invalid_cidr_and_value():
    with pytest.raises(zcidr.AddressError):
        zcidr.build(["not-a-cidr"])
    with pytest.raises(zcidr.AddressError):
        zcidr.build(["10.0.0.0/33"])
    with pytest.raises(ValueError):
        zcidr.build(["10.0.0.0/8"], values=[-1])


def test_free_is_idempotent_and_guards():
    m = zcidr.build(["10.0.0.0/8"])
    assert zcidr.match(m, "10.1.1.1") == 0
    zcidr.free(m)
    zcidr.free(m)  # idempotent, no crash
    with pytest.raises(ValueError):
        zcidr.match(m, "10.1.1.1")


def test_batch_match_ipv4():
    m = zcidr.build(["10.0.0.0/8", "10.1.2.0/24"])  # values 0, 1
    keys, valid = zcidr.parse_ipv4_lines("10.1.2.9\n10.9.9.9\n8.8.8.8")
    values, found = zcidr.match_ipv4_many(m, keys)
    assert list(found) == [1, 1, 0]
    assert values[0] == 1  # /24
    assert values[1] == 0  # /8
    # value at a miss is unspecified but found flag is 0
    assert found[2] == 0


def test_batch_match_ipv6():
    m = zcidr.build(["2001:db8::/32"], values=[99])
    packed, _ = zcidr.parse_ipv6_lines("2001:db8::1\n::1")
    values, found = zcidr.match_ipv6_many(m, packed)
    assert list(found) == [1, 0]
    assert values[0] == 99


def test_batch_match_empty():
    m = zcidr.build(["10.0.0.0/8"])
    values, found = zcidr.match_ipv4_many(m, zcidr.parse_ipv4_lines("")[0])
    assert len(values) == 0
    assert found == b""
