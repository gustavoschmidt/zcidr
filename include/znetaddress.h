/*
 * znetaddress — C ABI for a fast IP / CIDR toolkit backed by a Zig core.
 *
 * The boundary is deliberately narrow: bytes / ints / bools in, simple values
 * out. All functions are thread-compatible; the prefix trie is not internally
 * synchronized (guard a shared trie with your own lock).
 */
#ifndef ZNETADDRESS_H
#define ZNETADDRESS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Packed library version: (major << 16) | (minor << 8) | patch. */
uint32_t znet_version(void);

#ifdef __cplusplus
}
#endif

#endif /* ZNETADDRESS_H */
