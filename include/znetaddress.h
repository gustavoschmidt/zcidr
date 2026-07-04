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

/* Status codes. Length-returning functions return a non-negative count on
 * success, or one of these negative values on failure. */
#define ZNET_OK 0
#define ZNET_ERR_INVALID (-1)  /* not a valid address / CIDR */
#define ZNET_ERR_BUFFER (-2)   /* output buffer too small */
#define ZNET_ERR_NOMEM (-3)    /* allocation failed */
#define ZNET_ERR_NOTFOUND (-4) /* no matching entry */

/* Packed library version: (major << 16) | (minor << 8) | patch. */
uint32_t znet_version(void);

/* ---- IPv4 --------------------------------------------------------------
 * Addresses are host-order uint32 (first octet is the MSB). */
int znet_ipv4_parse(const uint8_t *s, size_t len, uint32_t *out);
/* Writes dotted-decimal (no NUL) into buf; returns bytes written or <0. */
intptr_t znet_ipv4_format(uint32_t addr, uint8_t *buf, size_t buflen);

/* ---- IPv6 --------------------------------------------------------------
 * Addresses are 16 network-order bytes. */
int znet_ipv6_parse(const uint8_t *s, size_t len, uint8_t out[16]);
/* Writes RFC 5952 canonical form (no NUL); returns bytes written or <0. */
intptr_t znet_ipv6_format(const uint8_t in[16], uint8_t *buf, size_t buflen);

/* ---- CIDR --------------------------------------------------------------
 * Parses "addr/prefix" (family inferred). Writes 0/1 to *is_v6, up to 16
 * network-order bytes to out_bytes, and the prefix length to *out_prefix. */
int znet_cidr_parse(const uint8_t *s, size_t len, int *is_v6,
                    uint8_t out_bytes[16], uint8_t *out_prefix);

/* ---- Longest-prefix-match trie -----------------------------------------
 * Opaque; not internally synchronized. */
typedef struct znet_trie znet_trie;
znet_trie *znet_trie_create(void);
void znet_trie_destroy(znet_trie *t);
/* addr: 4 bytes for IPv4, 16 for IPv6. */
int znet_trie_insert(znet_trie *t, int is_v6, const uint8_t *addr,
                     uint8_t prefix_len, uint64_t value);
int znet_trie_insert_cidr(znet_trie *t, const uint8_t *s, size_t len,
                          uint64_t value);
/* On a hit writes the value to *out_value and returns OK; miss -> NOTFOUND. */
int znet_trie_lookup(znet_trie *t, int is_v6, const uint8_t *addr,
                     uint64_t *out_value);

#ifdef __cplusplus
}
#endif

#endif /* ZNETADDRESS_H */
