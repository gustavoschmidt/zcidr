"""Build glue: compile the Zig core and bundle the shared library into the wheel.

We ship a `cffi` ABI/dlopen binding, not a CPython extension, so the wheel is
platform-specific but Python-version-independent (tagged ``py3-none-<plat>``):
one wheel per platform serves every supported interpreter.

The native toolchain is provided by the ``ziglang`` build requirement; a system
``zig`` is used as a fallback for source builds.
"""

import os
import shutil
import subprocess
import sys

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.dist import Distribution

try:  # setuptools >= 70.1 bundles bdist_wheel; otherwise use the wheel package.
    from setuptools.command.bdist_wheel import bdist_wheel
except ImportError:  # pragma: no cover
    from wheel.bdist_wheel import bdist_wheel

ROOT = os.path.dirname(os.path.abspath(__file__))


def _lib_name() -> str:
    if sys.platform.startswith("linux"):
        return "libzcidr.so"
    if sys.platform == "darwin":
        return "libzcidr.dylib"
    if sys.platform in ("win32", "cygwin"):
        return "zcidr.dll"
    raise RuntimeError(f"unsupported platform: {sys.platform}")


def _zig_cmd() -> list:
    """Prefer the hermetic ``ziglang`` wheel; fall back to a system ``zig``."""
    try:
        import ziglang  # noqa: F401

        return [sys.executable, "-m", "ziglang"]
    except ImportError:  # pragma: no cover
        return ["zig"]


class BuildZig(build_py):
    """Compile the Zig core, then copy the shared library into the package."""

    def run(self) -> None:
        cmd = _zig_cmd() + ["build", "-Doptimize=ReleaseFast"]
        target = os.environ.get("ZCIDR_ZIG_TARGET")
        if target:  # e.g. cross-building manylinux: x86_64-linux-gnu.2.17
            cmd.append(f"-Dtarget={target}")
        print("zcidr: building native core:", " ".join(cmd))
        subprocess.check_call(cmd, cwd=ROOT)

        super().run()  # copies the .py sources into build_lib

        lib = _lib_name()
        src = os.path.join(ROOT, "zig-out", "lib", lib)
        if not os.path.isfile(src):
            raise RuntimeError(f"expected built library not found: {src}")
        dest_dir = os.path.join(self.build_lib, "zcidr")
        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(src, os.path.join(dest_dir, lib))
        print(f"zcidr: bundled {lib} into {dest_dir}")


class WheelABINone(bdist_wheel):
    """Tag wheels ``py3-none-<platform>``: not pure, but ABI-independent."""

    def finalize_options(self) -> None:
        super().finalize_options()
        self.root_is_pure = False  # platform-specific (contains a binary)

    def get_tag(self):
        _python, _abi, plat = super().get_tag()
        return "py3", "none", plat


class BinaryDistribution(Distribution):
    def has_ext_modules(self) -> bool:  # force a platform wheel
        return True


setup(
    cmdclass={"build_py": BuildZig, "bdist_wheel": WheelABINone},
    distclass=BinaryDistribution,
)
