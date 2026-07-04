"""Smoke test: the benchmark harness runs and its correctness asserts hold."""

import importlib.util
import os

import pytest

_BENCH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "benchmarks", "bench.py")


@pytest.fixture(scope="module")
def bench():
    spec = importlib.util.spec_from_file_location("bench", _BENCH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_ipv4_parse_runs(bench):
    r = bench.bench_ipv4_parse(n=500)
    assert r["znetaddress"] > 0
    assert "ipaddress" in r


def test_ipv6_parse_runs(bench):
    r = bench.bench_ipv6_parse(n=500)
    assert r["znetaddress"] > 0


def test_membership_runs_and_agrees(bench):
    # The internal `assert zr == ir` inside bench_membership guards correctness.
    r = bench.bench_membership(k=100, m=500)
    assert r["znetaddress"] > 0
