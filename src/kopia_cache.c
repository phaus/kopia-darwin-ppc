/* kopia_cache.c — incremental transfer cache. See include/kopia_cache.h.
 *
 * File format (explicit little-endian, portable across the ppc/x86 boundary):
 *   "KPPC1" | u64 fnv(server_url) | u64 fnv(repo_user) | u64 fnv(repo_hostname)
 *           | u64 fnv(source_real)
 *   per dir:  u8 'D' | u32 len relpath | relpath | u32 len oid | oid
 *             | 32B sha256(json) | u32 n | n * entry
 *   entry:    u8 'f' | u32 len name | name | i64 size | u32 len mtime | mtime
 *             | u32 len oid | oid
 */

#include "kopia_cache.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h> /* unlink */

#define KCACHE_MAGIC "KPPC1"
#define KCACHE_HEADER_LEN (5 + 8 * 4)

#define MAX_NAME 512
#define MAX_OID  256
#define MAX_MTIME 64

typedef struct {
    char *name;
    long long size;
    char *mtime;
    char *oid;
} cache_ent_t;

typedef struct {
    char *relpath;
    cache_ent_t *ents;
    int n;
    char oid[MAX_OID];
    unsigned char sha[32];
} cache_dir_t;

/* ---- previous-run map ---- */
static cache_dir_t **g_dirs;
static unsigned      g_dirs_mask;      /* power of two - 1 */
static unsigned      g_table_size;

/* copy a length-prefixed slice into a NUL-terminated string (malloc'd) */
static int term_str(char **out, const unsigned char *s, unsigned l) {
    char *d = malloc((size_t)l + 1);
    if (!d) return -1;
    memcpy(d, s, l);
    d[l] = '\0';
    *out = d;
    return 0;
}

static void cache_reset(void) {
    if (g_dirs) {
        for (unsigned i = 0; i < g_table_size; i++) {
            if (g_dirs[i]) {
                for (int e = 0; e < g_dirs[i]->n; e++) {
                    free(g_dirs[i]->ents[e].name);
                    free(g_dirs[i]->ents[e].mtime);
                    free(g_dirs[i]->ents[e].oid);
                }
                free(g_dirs[i]->ents);
                free(g_dirs[i]->relpath);
                free(g_dirs[i]);
            }
        }
        free(g_dirs);
        g_dirs = NULL;
    }
}

/* ---- pending writer ---- */
static FILE *g_tmp;
static char  g_tmp_path[1024];
static char  g_final_path[1024];
static int   g_enabled = 0;

/* ---- little-endian helpers ---- */
static void put_u32le(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}
static unsigned get_u32le(const unsigned char *p) {
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}
static void put_i64le(unsigned char *p, long long v) {
    for (int i = 0; i < 8; i++) p[i] = (unsigned char)((unsigned long long)v >> (8 * i));
}
static long long get_i64le(const unsigned char *p) {
    unsigned long long v = 0;
    for (int i = 0; i < 8; i++) v |= (unsigned long long)p[i] << (8 * i);
    return (long long)v;
}

static unsigned long long fnv1a64(const char *s) {
    unsigned long long h = 0xcbf29ce484222325ULL;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 0x100000001b3ULL; }
    return h;
}

static unsigned long long fnv1a64_buf(const unsigned char *s, size_t n) {
    unsigned long long h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= s[i]; h *= 0x100000001b3ULL; }
    return h;
}

/* ---- identity + paths ---- */

static unsigned long long fnv1a64_key(const kopia_config_t *cfg, const char *source_real) {
    char key[1600];
    snprintf(key, sizeof(key), "%s|%s|%s|%s",
             cfg->server_url, cfg->repo_user, cfg->repo_hostname, source_real);
    return fnv1a64(key);
}

/* ---- previous-run map: hash table over relpath ---- */

static cache_dir_t *map_find(const char *relpath) {
    if (!g_dirs) return NULL;
    unsigned i = (unsigned)fnv1a64_buf((const unsigned char *)relpath, strlen(relpath)) & g_dirs_mask;
    while (g_dirs[i]) {
        if (strcmp(g_dirs[i]->relpath, relpath) == 0) return g_dirs[i];
        i = (i + 1) & g_dirs_mask;
    }
    return NULL;
}

static void map_insert(cache_dir_t *d) {
    unsigned i = (unsigned)fnv1a64_buf((const unsigned char *)d->relpath, strlen(d->relpath)) & g_dirs_mask;
    while (g_dirs[i]) i = (i + 1) & g_dirs_mask;
    g_dirs[i] = d;
}

/* ---- writer ---- */

static void w_u8(unsigned char v) { fwrite(&v, 1, 1, g_tmp); }

static void w_u32(unsigned v) {
    unsigned char b[4];
    put_u32le(b, v);
    fwrite(b, 1, 4, g_tmp);
}

static void w_i64(long long v) {
    unsigned char b[8];
    put_i64le(b, v);
    fwrite(b, 1, 8, g_tmp);
}

static void w_str(const char *s) {
    size_t n = strlen(s);
    w_u32((unsigned)n);
    fwrite(s, 1, n, g_tmp);
}

/* ---- loader ---- */

typedef struct { const unsigned char *p, *end; } cur_t;

static int cur_need(cur_t *c, size_t n) { return (size_t)(c->end - c->p) >= n; }
static int cur_u8(cur_t *c, unsigned char *v) {
    if (!cur_need(c, 1)) return -1;
    if (v) *v = *c->p;
    c->p++; return 0;
}
static int cur_u32(cur_t *c, unsigned *v) {
    if (!cur_need(c, 4)) return -1;
    if (v) *v = get_u32le(c->p);
    c->p += 4; return 0;
}
static int cur_i64(cur_t *c, long long *v) {
    if (!cur_need(c, 8)) return -1;
    if (v) *v = get_i64le(c->p);
    c->p += 8; return 0;
}
static int cur_str(cur_t *c, const unsigned char **s, unsigned *len) {
    unsigned l;
    if (cur_u32(c, &l) != 0 || !cur_need(c, l)) return -1;
    if (s) *s = c->p;
    if (len) *len = l;
    c->p += l; return 0;
}

static int load_cache_file(const char *path, const kopia_config_t *cfg,
                           const char *source_real) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0; /* no cache yet: not an error */

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < (long)KCACHE_HEADER_LEN || sz > (long)(400u << 20)) { fclose(f); return -1; }
    rewind(f);

    unsigned char *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return -1; }
    fclose(f);
    cur_t c = { buf, buf + sz };
    /* header + identity */
    if (!cur_need(&c, 5) || memcmp(c.p, KCACHE_MAGIC, 5) != 0) { free(buf); return -1; }
    c.p += 5;
    unsigned long long want[4] = {
        fnv1a64(cfg->server_url), fnv1a64(cfg->repo_user),
        fnv1a64(cfg->repo_hostname), fnv1a64(source_real),
    };
    for (int i = 0; i < 4; i++) {
        long long got;
        if (cur_i64(&c, &got) != 0) { free(buf); return -1; }
        if (got != (long long)want[i]) { free(buf); return 0; }
    }
    /* identity mismatch (0): silently ignore — full push, fresh cache */

    /* validate structure + count dir records */
    int ndirs = 0;
    cur_t v = c;
    for (;;) {
        unsigned char tag;
        unsigned l, n;
        if (cur_u8(&v, &tag) != 0) break;
        if (tag != 'D') { free(buf); return -1; }
        if (cur_str(&v, NULL, &l) != 0) { free(buf); return -1; } /* relpath */
        if (cur_str(&v, NULL, &l) != 0) { free(buf); return -1; } /* oid */
        if (!cur_need(&v, 32)) { free(buf); return -1; }          /* sha */
        v.p += 32;
        if (cur_u32(&v, &n) != 0) { free(buf); return -1; }
        for (unsigned e = 0; e < n; e++) {
            unsigned char t;
            if (cur_u8(&v, &t) != 0 || t != 'f') { free(buf); return -1; }
            if (cur_str(&v, NULL, &l) != 0) { free(buf); return -1; } /* name */
            if (cur_i64(&v, NULL) != 0) { free(buf); return -1; }     /* size */
            if (cur_str(&v, NULL, &l) != 0) { free(buf); return -1; } /* mtime */
            if (cur_str(&v, NULL, &l) != 0) { free(buf); return -1; } /* oid */
        }
        ndirs++;
    }

    if (ndirs == 0) { free(buf); return 0; }

    unsigned tsize = 16;
    while (tsize < (unsigned)ndirs * 2) tsize <<= 1;
    g_dirs = calloc(tsize, sizeof(cache_dir_t *));
    if (!g_dirs) { free(buf); return -1; }
    g_dirs_mask = tsize - 1;
    g_table_size = tsize;

    /* second pass: parse into structs (strings copied, NUL-terminated) */
    for (int d = 0; d < ndirs; d++) {
        cache_dir_t *cd = calloc(1, sizeof(*cd));
        if (!cd) { free(buf); cache_reset(); return -1; }
        unsigned l, n;
        unsigned char tag;
        const unsigned char *s;
        cur_u8(&c, &tag);
        if (cur_str(&c, &s, &l) != 0 || term_str(&cd->relpath, s, l) != 0) {
            free(buf); cache_reset(); return -1;
        }
        if (cur_str(&c, &s, &l) != 0) { free(buf); cache_reset(); return -1; }
        size_t oidn = l < MAX_OID ? l : MAX_OID - 1;
        memcpy(cd->oid, s, oidn); cd->oid[oidn] = '\0';
        if (!cur_need(&c, 32)) { free(buf); cache_reset(); return -1; }
        memcpy(cd->sha, c.p, 32); c.p += 32;
        if (cur_u32(&c, &n) != 0) { free(buf); cache_reset(); return -1; }
        cd->ents = calloc(n ? n : 1, sizeof(cache_ent_t));
        if (!cd->ents) { free(buf); cache_reset(); return -1; }
        cd->n = 0;
        for (unsigned e = 0; e < n; e++) {
            unsigned char t;
            cur_u8(&c, &t);
            if (t != 'f' || cur_str(&c, &s, &l) != 0 ||
                term_str(&cd->ents[cd->n].name, s, l) != 0 ||
                cur_i64(&c, &cd->ents[cd->n].size) != 0 ||
                cur_str(&c, &s, &l) != 0 ||
                term_str(&cd->ents[cd->n].mtime, s, l) != 0 ||
                cur_str(&c, &s, &l) != 0 ||
                term_str(&cd->ents[cd->n].oid, s, l) != 0) {
                free(buf); cache_reset(); return -1;
            }
            cd->n++;
        }
        map_insert(cd);
    }
    free(buf);
    return 1;
}

/* ---- public API ---- */

int kcache_begin(const kopia_config_t *cfg, const char *source_real) {
    cache_reset(); /* fresh table per run (also clears a failed previous load) */

    const char *dir = getenv("KOPIA_CACHE_DIR");
    if (!dir) dir = "/var/db/kopia-darwin-ppc";
    mkdir(dir, 0755); /* ok if it exists; failure surfaces at fopen */

    char stem[1024];
    snprintf(stem, sizeof(stem), "%s/cache-%016llx", dir,
             fnv1a64_key(cfg, source_real));
    snprintf(g_final_path, sizeof(g_final_path), "%s.dat", stem);
    snprintf(g_tmp_path, sizeof(g_tmp_path), "%s.tmp", stem);

    int rc = load_cache_file(g_final_path, cfg, source_real);
    if (rc < 0) {
        fprintf(stderr, "diag: incremental cache unreadable, full push\n");
        cache_reset();
    } else if (rc == 1) {
        fprintf(stderr, "diag: incremental cache loaded\n");
    }

    g_tmp = fopen(g_tmp_path, "wb");
    if (!g_tmp) return -1; /* unwritable dir: cache disabled, full push */

    unsigned char hdr[KCACHE_HEADER_LEN];
    memcpy(hdr, KCACHE_MAGIC, 5);
    put_u32le(hdr + 5,  (unsigned)fnv1a64(cfg->server_url));
    put_u32le(hdr + 9,  (unsigned)(fnv1a64(cfg->server_url) >> 32));
    put_u32le(hdr + 13, (unsigned)fnv1a64(cfg->repo_user));
    put_u32le(hdr + 17, (unsigned)(fnv1a64(cfg->repo_user) >> 32));
    put_u32le(hdr + 21, (unsigned)fnv1a64(cfg->repo_hostname));
    put_u32le(hdr + 25, (unsigned)(fnv1a64(cfg->repo_hostname) >> 32));
    put_u32le(hdr + 29, (unsigned)fnv1a64(source_real));
    put_u32le(hdr + 33, (unsigned)(fnv1a64(source_real) >> 32));
    fwrite(hdr, 1, KCACHE_HEADER_LEN, g_tmp);

    g_enabled = 1;
    return 0;
}

int kcache_lookup_file(const char *relpath, const char *name,
                       long long size, const char *mtime,
                       char *oid, size_t oid_len) {
    if (!g_dirs) return 0;
    cache_dir_t *cd = map_find(relpath);
    if (!cd || cd->n == 0) return 0;

    int lo = 0, hi = cd->n - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        int c = strcmp(cd->ents[mid].name, name);
        if (c == 0) {
            if (cd->ents[mid].size != size || strcmp(cd->ents[mid].mtime, mtime) != 0)
                return 0;
            snprintf(oid, oid_len, "%s", cd->ents[mid].oid);
            return 1;
        }
        if (c < 0) lo = mid + 1; else hi = mid - 1;
    }
    return 0;
}

int kcache_lookup_dir(const char *relpath, const unsigned char json_sha[32],
                      char *oid, size_t oid_len) {
    if (!g_dirs) return 0;
    cache_dir_t *cd = map_find(relpath);
    if (!cd) return 0;
    if (memcmp(cd->sha, json_sha, 32) != 0) return 0;
    snprintf(oid, oid_len, "%s", cd->oid);
    return 1;
}

void kcache_record_dir(const char *relpath, const dir_entry_t *entries, int n,
                       const char *dir_oid, const unsigned char json_sha[32]) {
    if (!g_enabled || !g_tmp) return;

    w_u8('D');
    w_str(relpath);
    w_str(dir_oid);
    fwrite(json_sha, 1, 32, g_tmp);
    /* count regular files first */
    int nf = 0;
    for (int i = 0; i < n; i++)
        if (entries[i].type[0] == 'f') nf++;
    w_u32((unsigned)nf);
    for (int i = 0; i < n; i++) {
        if (entries[i].type[0] != 'f') continue;
        w_u8('f');
        w_str(entries[i].name);
        w_i64(entries[i].size);
        w_str(entries[i].mtime);
        w_str(entries[i].oid);
    }
}

void kcache_commit(void) {
    if (!g_tmp) return;
    fflush(g_tmp);
    if (ferror(g_tmp)) { fclose(g_tmp); g_tmp = NULL; unlink(g_tmp_path); return; }
    fclose(g_tmp);
    g_tmp = NULL;
    if (rename(g_tmp_path, g_final_path) != 0)
        fprintf(stderr, "diag: cache commit failed: %s\n", strerror(errno));
}
