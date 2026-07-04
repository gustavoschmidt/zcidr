"""Low-level cffi (ABI/dlopen mode) binding to the znetaddress Zig core.

We declare the stable C ABI with ``ffi.cdef`` and ``dlopen`` the prebuilt
shared library — no compiler is needed at import/install time. The shared
library is looked up next to this module first (installed wheel), then in the
repository's ``zig-out/lib`` (local development).
"""

from __future__ import annotations

import os
import sys

from cffi import FFI

# Keep this in sync with include/znetaddress.h.
_CDEF = """
uint32_t znet_version(void);

int znet_ipv4_parse(const uint8_t *s, size_t len, uint32_t *out);
intptr_t znet_ipv4_format(uint32_t addr, uint8_t *buf, size_t buflen);

int znet_ipv6_parse(const uint8_t *s, size_t len, uint8_t *out);
intptr_t znet_ipv6_format(const uint8_t *in, uint8_t *buf, size_t buflen);

int znet_cidr_parse(const uint8_t *s, size_t len, int *is_v6,
                    uint8_t *out_bytes, uint8_t *out_prefix);

typedef struct znet_trie znet_trie;
znet_trie *znet_trie_create(void);
void znet_trie_destroy(znet_trie *t);
int znet_trie_insert(znet_trie *t, int is_v6, const uint8_t *addr,
                     uint8_t prefix_len, uint64_t value);
int znet_trie_insert_cidr(znet_trie *t, const uint8_t *s, size_t len,
                          uint64_t value);
int znet_trie_lookup(znet_trie *t, int is_v6, const uint8_t *addr,
                     uint64_t *out_value);
"""

# Status codes (mirror src/abi.zig).
OK = 0
ERR_INVALID = -1
ERR_BUFFER = -2
ERR_NOMEM = -3
ERR_NOTFOUND = -4


def _lib_filenames() -> list[str]:
    if sys.platform == "darwin":
        return ["libznetaddress.dylib"]
    if sys.platform == "win32":
        return ["znetaddress.dll", "libznetaddress.dll"]
    return ["libznetaddress.so"]


def _find_library() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(here)
    search_dirs = [
        here,  # bundled inside the installed package
        os.path.join(repo_root, "zig-out", "lib"),  # local `zig build`
    ]
    env = os.environ.get("ZNETADDRESS_LIB")
    if env:
        if os.path.isfile(env):
            return env
        search_dirs.insert(0, env)  # treat as a directory
    for d in search_dirs:
        for name in _lib_filenames():
            candidate = os.path.join(d, name)
            if os.path.isfile(candidate):
                return candidate
    raise OSError(
        "Could not locate the znetaddress shared library. Build it with "
        "`zig build`, or set ZNETADDRESS_LIB to its path. Searched: "
        + ", ".join(search_dirs)
    )


ffi = FFI()
ffi.cdef(_CDEF)
lib = ffi.dlopen(_find_library())
