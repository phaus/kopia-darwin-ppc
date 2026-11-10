/* kopia_hpack.c — HPACK (RFC 7541): literal encoder + full decoder (dynamic table, Huffman). */

#define _POSIX_C_SOURCE 200809L /* strdup under -std=c99 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kopia_internal.h"

#include "hpack_huffman.h"

/* ---- static table (RFC 7541 Appendix A) — names only needed for decode lookups ---- */
static const char *static_table[61][2] = {
    { ":authority", "" }, { ":method", "GET" }, { ":method", "POST" },
    { ":path", "/" }, { ":path", "/index.html" }, { ":scheme", "http" },
    { ":scheme", "https" }, { ":status", "200" }, { ":status", "204" },
    { ":status", "206" }, { ":status", "304" }, { ":status", "400" },
    { ":status", "404" }, { ":status", "500" }, { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" }, { "accept-language", "" },
    { "accept-ranges", "" }, { "accept", "" }, { "access-control-allow-origin", "" },
    { "age", "" }, { "allow", "" }, { "authorization", "" },
    { "cache-control", "" }, { "content-disposition", "" },
    { "content-encoding", "" }, { "content-language", "" },
    { "content-length", "" }, { "content-location", "" },
    { "content-range", "" }, { "content-type", "" }, { "cookie", "" },
    { "date", "" }, { "etag", "" }, { "expect", "" }, { "expires", "" },
    { "from", "" }, { "host", "" }, { "if-match", "" },
    { "if-modified-since", "" }, { "if-none-match", "" },
    { "if-range", "" }, { "if-unmodified-since", "" }, { "last-modified", "" },
    { "link", "" }, { "location", "" }, { "max-forwards", "" },
    { "proxy-authenticate", "" }, { "proxy-authorization", "" },
    { "range", "" }, { "referer", "" }, { "refresh", "" },
    { "retry-after", "" }, { "server", "" }, { "set-cookie", "" },
    { "strict-transport-security", "" }, { "transfer-encoding", "" },
    { "user-agent", "" }, { "vary", "" }, { "via", "" }, { "www-authenticate", "" },
};

/* ---- decoder ---- */

void hpack_dec_init(hpack_dec_t *d) {
    memset(d, 0, sizeof(*d));
    d->dyn_max = 4096;
}

void hpack_dec_free(hpack_dec_t *d) {
    for (int i = 0; i < d->dyn_count; i++) {
        free(d->dyn[i].name);
        free(d->dyn[i].value);
    }
    memset(d, 0, sizeof(*d));
}

void hpack_dec_clear(hpack_dec_t *d) {
    for (int i = 0; i < d->count; i++) {
        free(d->hdrs[i].name);
        free(d->hdrs[i].value);
        d->hdrs[i].name = d->hdrs[i].value = NULL;
    }
    d->count = 0;
}

static void dyn_add(hpack_dec_t *d, const char *name, const char *value) {
    size_t sz = strlen(name) + strlen(value) + 32;
    if (sz > d->dyn_max) { /* evict all */
        for (int i = 0; i < d->dyn_count; i++) { free(d->dyn[i].name); free(d->dyn[i].value); }
        d->dyn_count = 0; d->dyn_size = 0;
        return;
    }
    while (d->dyn_size + sz > d->dyn_max && d->dyn_count > 0) {
        d->dyn_count--;
        d->dyn_size -= d->dyn[d->dyn_count].size;
        free(d->dyn[d->dyn_count].name);
        free(d->dyn[d->dyn_count].value);
    }
    if (d->dyn_count >= 128) { /* hard cap */
        d->dyn_count--;
        d->dyn_size -= d->dyn[d->dyn_count].size;
        free(d->dyn[d->dyn_count].name);
        free(d->dyn[d->dyn_count].value);
        memmove(&d->dyn[1], &d->dyn[0], d->dyn_count * sizeof(d->dyn[0]));
    } else {
        memmove(&d->dyn[1], &d->dyn[0], d->dyn_count * sizeof(d->dyn[0]));
    }
    d->dyn[0].name = strdup(name);
    d->dyn[0].value = strdup(value);
    d->dyn[0].size = sz;
    d->dyn_count++;
    d->dyn_size += sz;
}

/* dynamic index i (1-based) */
static int dyn_get(hpack_dec_t *d, int i, const char **name, const char **value) {
    if (i < 1 || i > d->dyn_count) return -1;
    *name = d->dyn[i - 1].name;
    *value = d->dyn[i - 1].value;
    return 0;
}

static int lookup_index(hpack_dec_t *d, int index, const char **name, const char **value) {
    if (index >= 1 && index <= 61) {
        *name = (char *)static_table[index - 1][0];
        *value = (char *)static_table[index - 1][1];
        return 0;
    }
    return dyn_get(d, index - 61, name, value);
}

static int huff_decode(const unsigned char *in, size_t in_len,
                       unsigned char *out, size_t out_cap, size_t *out_len) {
    uint64_t acc = 0;
    int nbits = 0;
    size_t o = 0;

    for (size_t i = 0; i < in_len; i++) {
        acc = (acc << 8) | in[i];
        nbits += 8;
        for (;;) {
            int matched = 0;
            for (int sym = 0; sym < 257; sym++) {
                int L = hpack_huff_len[sym];
                if (L > nbits) continue;
                uint32_t prefix = (uint32_t)((acc >> (nbits - L)) << (32 - L));
                if (hpack_huff_code[sym] == prefix) {
                    if (sym == 256) return -1; /* EOS in string */
                    if (o >= out_cap) return -1;
                    out[o++] = (unsigned char)sym;
                    nbits -= L;
                    matched = 1;
                    break;
                }
            }
            if (!matched) break;
        }
        if (nbits > 31) return -1; /* no match possible */
    }
    /* remaining bits must be < 8 and all ones (padding) */
    for (int b = 0; b < nbits; b++) {
        if (!((acc >> (nbits - 1 - b)) & 1)) return -1;
    }
    *out_len = o;
    return 0;
}

static int read_str(const unsigned char *buf, size_t len, size_t *pos,
                    unsigned char **out, size_t *out_len) {
    if (*pos >= len) return -1;
    int huff = buf[*pos] & 0x80;
    uint64_t v = 0;
    int shift = 0;
    unsigned char mask = 0x7f;
    size_t p = *pos;
    v = buf[p] & mask;
    p++;
    if (v == mask) {
        int m;
        shift = 0;
        do {
            if (p >= len) return -1;
            m = buf[p++];
            v += (uint64_t)(m & 0x7f) << shift;
            shift += 7;
        } while (m & 0x80);
    }
    if (p + v > len) return -1;

    if (huff) {
        size_t cap = v * 2 + 16;
        unsigned char *dec = malloc(cap);
        if (huff_decode(buf + p, v, dec, cap, out_len) != 0) { free(dec); return -1; }
        *out = dec;
    } else {
        unsigned char *raw = malloc(v + 1);
        memcpy(raw, buf + p, v);
        raw[v] = '\0';
        *out = raw;
        *out_len = v;
    }
    *pos = p + v;
    return 0;
}

int hpack_decode(hpack_dec_t *d, const unsigned char *buf, size_t len) {
    size_t p = 0;
    while (p < len) {
        unsigned char b = buf[p];
        if (b & 0x80) { /* indexed */
            uint64_t idx = b & 0x7f;
            p++;
            if (idx == 0x7f) {
                int m, sh = 0;
                do { if (p >= len) return -1; m = buf[p++]; idx += (uint64_t)(m & 0x7f) << sh; sh += 7; } while (m & 0x80);
            }
            const char *n, *v;
            if (lookup_index(d, (int)idx, &n, &v) != 0) return -1;
            if (d->count < HPACK_MAX_HEADERS) {
                d->hdrs[d->count].name = strdup(n);
                d->hdrs[d->count].value = strdup(v);
                d->count++;
            }
        } else if (b & 0xc0) { /* 01xxxxxx literal with incremental indexing */
            uint64_t idx = b & 0x3f;
            p++;
            if (idx == 0x3f) {
                int m, sh = 0;
                do { if (p >= len) return -1; m = buf[p++]; idx += (uint64_t)(m & 0x7f) << sh; sh += 7; } while (m & 0x80);
            }
            char *name = NULL;
            if (idx == 0) {
                unsigned char *n; size_t nl;
                if (read_str(buf, len, &p, &n, &nl) != 0) return -1;
                name = (char *)n;
            } else {
                const char *n, *v;
                if (lookup_index(d, (int)idx, &n, &v) != 0) return -1;
                name = strdup(n);
            }
            unsigned char *val; size_t vl;
            if (read_str(buf, len, &p, &val, &vl) != 0) { free(name); return -1; }
            dyn_add(d, name, (char *)val);
            if (d->count < HPACK_MAX_HEADERS) {
                d->hdrs[d->count].name = name;
                d->hdrs[d->count].value = (char *)val;
                d->count++;
            } else { free(name); free(val); }
        } else if (b == 0x30 || b == 0x20 || ((b & 0xe0) == 0x20)) { /* dynamic table size update */
            uint64_t v = b & 0x1f;
            p++;
            if (v == 0x1f) {
                int m, sh = 0;
                do { if (p >= len) return -1; m = buf[p++]; v += (uint64_t)(m & 0x7f) << sh; sh += 7; } while (m & 0x80);
            }
            (void)v; /* we accept but ignore resize (server won't exceed our 4096) */
        } else { /* 0000xxxx / 0001xxxx literal without indexing / never indexed */
            uint64_t idx = b & 0x0f;
            p++;
            if (idx == 0x0f) {
                int m, sh = 0;
                do { if (p >= len) return -1; m = buf[p++]; idx += (uint64_t)(m & 0x7f) << sh; sh += 7; } while (m & 0x80);
            }
            char *name = NULL;
            if (idx == 0) {
                unsigned char *n; size_t nl;
                if (read_str(buf, len, &p, &n, &nl) != 0) return -1;
                name = (char *)n;
            } else {
                const char *n, *v;
                if (lookup_index(d, (int)idx, &n, &v) != 0) return -1;
                name = strdup(n);
            }
            unsigned char *val; size_t vl;
            if (read_str(buf, len, &p, &val, &vl) != 0) { free(name); return -1; }
            if (d->count < HPACK_MAX_HEADERS) {
                d->hdrs[d->count].name = name;
                d->hdrs[d->count].value = (char *)val;
                d->count++;
            } else { free(name); free(val); }
        }
    }
    return 0;
}

/* ---- encoder: literal without indexing, no huffman ---- */

static void put_int(unsigned char *buf, size_t *len, uint64_t v, unsigned char prefix_mask,
                    unsigned char first_bits) {
    if (v < prefix_mask) {
        buf[(*len)++] = first_bits | (unsigned char)v;
        return;
    }
    buf[(*len)++] = first_bits | prefix_mask;
    v -= prefix_mask;
    while (v >= 0x80) {
        buf[(*len)++] = (unsigned char)((v & 0x7f) | 0x80);
        v >>= 7;
    }
    buf[(*len)++] = (unsigned char)v;
}

int hpack_encode(const char **names, const char **values, int n,
                 unsigned char **out, size_t *out_len) {
    size_t cap = 4096;
    unsigned char *buf = malloc(cap);
    size_t len = 0;

    for (int i = 0; i < n; i++) {
        const char *nm = names[i], *vl = values[i];
        size_t nl = strlen(nm), vallen = strlen(vl);
        size_t need = len + nl + vallen + 16;
        if (need > cap) {
            while (need > cap) cap *= 2;
            buf = realloc(buf, cap);
        }
        buf[len++] = 0x00;                   /* literal without indexing, NEW name */
        put_int(buf, &len, nl, 0x7f, 0x00);  /* name length, 7-bit prefix */
        memcpy(buf + len, nm, nl);
        len += nl;
        put_int(buf, &len, vallen, 0x7f, 0x00);
        memcpy(buf + len, vl, vallen);
        len += vallen;
    }
    *out = buf;
    *out_len = len;
    return 0;
}
