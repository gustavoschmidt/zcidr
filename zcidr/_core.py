"""Low-level cffi (ABI/dlopen mode) binding to the zcidr Zig core.

We declare the stable C ABI with ``ffi.cdef`` and ``dlopen`` the prebuilt
shared library — no compiler is needed at import/install time. The shared
library is looked up next to this module first (installed wheel), then in the
repository's ``zig-out/lib`` (local development).
"""

from __future__ import annotations

import os
import sys

from cffi import FFI

# Keep this in sync with include/zcidr.h.
_CDEF = """
uint32_t zcidr_version(void);
size_t zcidr_line_count(const uint8_t *data, size_t len);

int zcidr_ipv4_parse(const uint8_t *s, size_t len, uint32_t *out);
intptr_t zcidr_ipv4_format(uint32_t addr, uint8_t *buf, size_t buflen);
intptr_t zcidr_ipv4_parse_lines(const uint8_t *data, size_t len,
                                uint32_t *out_values, uint8_t *out_valid,
                                size_t cap);
intptr_t zcidr_ipv4_format_lines(const uint32_t *values, size_t n,
                                 uint8_t *out, size_t cap);

int zcidr_ipv6_parse(const uint8_t *s, size_t len, uint8_t *out);
intptr_t zcidr_ipv6_format(const uint8_t *in, uint8_t *buf, size_t buflen);
intptr_t zcidr_ipv6_parse_lines(const uint8_t *data, size_t len,
                                uint8_t *out_bytes, uint8_t *out_valid,
                                size_t cap);
intptr_t zcidr_ipv6_format_lines(const uint8_t *bytes, size_t n,
                                 uint8_t *out, size_t cap);

int zcidr_cidr_parse(const uint8_t *s, size_t len, int *is_v6,
                     uint8_t *out_bytes, uint8_t *out_prefix);

typedef struct zcidr_trie zcidr_trie;
zcidr_trie *zcidr_trie_create(void);
void zcidr_trie_destroy(zcidr_trie *t);
int zcidr_trie_insert(zcidr_trie *t, int is_v6, const uint8_t *addr,
                      uint8_t prefix_len, uint64_t value);
int zcidr_trie_insert_cidr(zcidr_trie *t, const uint8_t *s, size_t len,
                           uint64_t value);
int zcidr_trie_lookup(zcidr_trie *t, int is_v6, const uint8_t *addr,
                      uint64_t *out_value);
int zcidr_trie_lookup_v4_many(zcidr_trie *t, const uint32_t *keys, size_t n,
                              uint64_t *out_values, uint8_t *out_found);
int zcidr_trie_lookup_v6_many(zcidr_trie *t, const uint8_t *keys, size_t n,
                              uint64_t *out_values, uint8_t *out_found);
intptr_t zcidr_trie_insert_lines(zcidr_trie *t, const uint8_t *data,
                                 size_t len, const uint64_t *values,
                                 uint64_t first_value, uint8_t *out_valid,
                                 size_t cap);
intptr_t zcidr_trie_match_lines(zcidr_trie *t, const uint8_t *data,
                                size_t len, uint64_t *out_values,
                                uint8_t *out_found, size_t cap);
"""

# Status codes (mirror src/abi.zig).
OK = 0
ERR_INVALID = -1
ERR_BUFFER = -2
ERR_NOMEM = -3
ERR_NOTFOUND = -4


def _lib_filenames() -> list[str]:
    if sys.platform == "darwin":
        return ["libzcidr.dylib"]
    if sys.platform == "win32":
        return ["zcidr.dll", "libzcidr.dll"]
    return ["libzcidr.so"]


def _find_library() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(here)
    search_dirs = [
        here,  # bundled inside the installed package
        os.path.join(repo_root, "zig-out", "lib"),  # local `zig build`
    ]
    env = os.environ.get("ZCIDR_LIB")
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
        "Could not locate the zcidr shared library. Build it with "
        "`zig build`, or set ZCIDR_LIB to its path. Searched: "
        + ", ".join(search_dirs)
    )


ffi = FFI()
ffi.cdef(_CDEF)
lib = ffi.dlopen(_find_library())
