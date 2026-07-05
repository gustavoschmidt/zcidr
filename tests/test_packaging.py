"""Packaging sanity checks.

Validates the wheel/build configuration and that the native library is
discoverable — this passes both in a source checkout (finds ``zig-out/lib``)
and inside an installed wheel (finds the bundled library), which is the
make-or-break "pip install just works" guarantee.
"""

import os

import pytest

import zcidr
from zcidr import _core

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_library_is_discoverable():
    path = _core._find_library()
    assert os.path.isfile(path)
    # It should be either bundled in the package or the dev build output.
    assert path.endswith((".so", ".dylib", ".dll"))


def test_native_core_loads():
    assert zcidr.version() == (0, 2, 0)


@pytest.mark.skipif(tomllib is None, reason="tomllib requires Python 3.11+")
def test_pyproject_build_config():
    with open(os.path.join(_ROOT, "pyproject.toml"), "rb") as fh:
        cfg = tomllib.load(fh)

    build = cfg["build-system"]
    assert build["build-backend"] == "setuptools.build_meta"
    # The Zig toolchain must be a build requirement so wheel builds are hermetic.
    assert any(r.startswith("ziglang") for r in build["requires"])

    project = cfg["project"]
    assert project["name"] == "zcidr"
    assert any(d.startswith("cffi") for d in project["dependencies"])

    # cibuildwheel must run the test suite against each built wheel.
    cibw = cfg["tool"]["cibuildwheel"]
    assert "pytest" in cibw["test-command"]
