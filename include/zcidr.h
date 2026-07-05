/*
 * zcidr — C ABI for a fast IP / CIDR toolkit backed by a Zig core.
 *
 * The boundary is deliberately narrow: bytes / ints / bools in, simple values
 * out. All functions are thread-compatible; the prefix trie is not internally
 * synchronized (guard a shared trie with your own lock).
 */
#ifndef ZCIDR_H
#define ZCIDR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. Length-returning functions return a non-negative count on
 * success, or one of these negative values on failure. */
#define ZCIDR_OK 0
#define ZCIDR_ERR_INVALID (-1)  /* not a valid address / CIDR */
#define ZCIDR_ERR_BUFFER (-2)   /* output buffer too small */
#define ZCIDR_ERR_NOMEM (-3)    /* allocation failed */
#define ZCIDR_ERR_NOTFOUND (-4) /* no matching entry */

/* Packed library version: (major << 16) | (minor << 8) | patch. */
uint32_t zcidr_version(void);

/* ---- IPv4 --------------------------------------------------------------
 * Addresses are host-order uint32 (first octet is the MSB). */
int zcidr_ipv4_parse(const uint8_t *s, size_t len, uint32_t *out);
/* Writes dotted-decimal (no NUL) into buf; returns bytes written or <0. */
intptr_t zcidr_ipv4_format(uint32_t addr, uint8_t *buf, size_t buflen);
/* Batch: parse newline-delimited addresses. Writes up to `cap` host-order
 * values + validity bytes (1/0). Returns record count, or ERR_BUFFER. */
intptr_t zcidr_ipv4_parse_lines(const uint8_t *data, size_t len,
                                uint32_t *out_values, uint8_t *out_valid,
                                size_t cap);
/* Batch: format n values as newline-separated dotted-decimal (no trailing
 * newline). Returns bytes written, or ERR_BUFFER. */
intptr_t zcidr_ipv4_format_lines(const uint32_t *values, size_t n,
                                 uint8_t *out, size_t cap);

/* ---- IPv6 --------------------------------------------------------------
 * Addresses are 16 network-order bytes. */
int zcidr_ipv6_parse(const uint8_t *s, size_t len, uint8_t out[16]);
/* Writes RFC 5952 canonical form (no NUL); returns bytes written or <0. */
intptr_t zcidr_ipv6_format(const uint8_t in[16], uint8_t *buf, size_t buflen);
/* Batch: parse newline-delimited addresses. Writes up to `cap` records of 16
 * network-order bytes (packed) + validity bytes. Returns count, or ERR_BUFFER. */
intptr_t zcidr_ipv6_parse_lines(const uint8_t *data, size_t len,
                                uint8_t *out_bytes, uint8_t *out_valid,
                                size_t cap);
/* Batch: format n records (16 bytes each) as newline-separated canonical
 * strings (no trailing newline). Returns bytes written, or ERR_BUFFER. */
intptr_t zcidr_ipv6_format_lines(const uint8_t *bytes, size_t n,
                                 uint8_t *out, size_t cap);

/* ---- CIDR --------------------------------------------------------------
 * Parses "addr/prefix" (family inferred). Writes 0/1 to *is_v6, up to 16
 * network-order bytes to out_bytes, and the prefix length to *out_prefix. */
int zcidr_cidr_parse(const uint8_t *s, size_t len, int *is_v6,
                    uint8_t out_bytes[16], uint8_t *out_prefix);

/* ---- Longest-prefix-match trie -----------------------------------------
 * Opaque; not internally synchronized. */
typedef struct zcidr_trie zcidr_trie;
zcidr_trie *zcidr_trie_create(void);
void zcidr_trie_destroy(zcidr_trie *t);
/* addr: 4 bytes for IPv4, 16 for IPv6. */
int zcidr_trie_insert(zcidr_trie *t, int is_v6, const uint8_t *addr,
                     uint8_t prefix_len, uint64_t value);
int zcidr_trie_insert_cidr(zcidr_trie *t, const uint8_t *s, size_t len,
                          uint64_t value);
/* On a hit writes the value to *out_value and returns OK; miss -> NOTFOUND. */
int zcidr_trie_lookup(zcidr_trie *t, int is_v6, const uint8_t *addr,
                     uint64_t *out_value);
/* Batch LPM: for each of n keys, writes the matched value + a found byte (1/0).
 * v4 keys are host-order uint32; v6 keys are 16 network-order bytes, packed. */
int zcidr_trie_lookup_v4_many(zcidr_trie *t, const uint32_t *keys, size_t n,
                              uint64_t *out_values, uint8_t *out_found);
int zcidr_trie_lookup_v6_many(zcidr_trie *t, const uint8_t *keys, size_t n,
                              uint64_t *out_values, uint8_t *out_found);

#ifdef __cplusplus
}
#endif

#endif /* ZCIDR_H */
