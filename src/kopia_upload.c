/* kopia_upload.c — buzhash chunking, file/dir upload, snapshot manifest.
 * Formats per docs/kopia-protocol.md (DirManifest, indirect objects, snapshot JSON).
 */

#define _GNU_SOURCE /* fmemopen, st_mtim, gmtime_r */

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "kopia_internal.h"
#include "kopia_json.h"

#define SPLITTER_WINDOW 64
#define SPLITTER_MIN (2u << 20)
#define SPLITTER_AVG (4u << 20)
#define SPLITTER_MAX (8u << 20)
#define SPLITTER_MASK (SPLITTER_AVG - 1)

/* buzhash32 table — Go rand.NewSource(1), chmduquesne/rollinghash GenerateHashes(1) */
static const uint32_t buzhash_table[256] = {
    0x07fcfd52U, 0x5f3f164fU, 0x6695721dU, 0x7b4d7c03U,
    0x49c6e2d1U, 0x0d1d68d8U, 0x7916001eU, 0x22c4d294U,
    0x392907a0U, 0x189deb99U, 0xf3875d04U, 0x95e94627U,
    0xba517936U, 0x83c471d4U, 0x7cb3ad0bU, 0xa42655d9U,
    0x7c4e0b68U, 0xd4491d1bU, 0x25632186U, 0xa9d78d73U,
    0x169c1121U, 0xbb158644U, 0xb68e6a3fU, 0x759805f5U,
    0x2cdf5b8aU, 0x57d29245U, 0xc5d6d268U, 0x6b83d0e2U,
    0x7674cb74U, 0xb068d9dbU, 0xbb9457d8U, 0xa15d523bU,
    0x794209ffU, 0x9da1d7ebU, 0x5a25e0cbU, 0xf840ec4bU,
    0x36d4ff9bU, 0xf4a5ee3bU, 0x5ad145f4U, 0xf6740304U,
    0x3f71f8cbU, 0x91018d7cU, 0xfccae224U, 0xb186b51fU,
    0x7d9e8fbcU, 0x93f93f33U, 0xf63a5b6fU, 0x19476c36U,
    0xbc897d06U, 0x169873f5U, 0x724c7af1U, 0x581eeb39U,
    0x2257bb7dU, 0x6f269a28U, 0xbe8e9981U, 0x7039374bU,
    0x25416fedU, 0xded7e411U, 0x6678e7aaU, 0x244fcd36U,
    0x56aa6b86U, 0xde4561adU, 0x3e99b0a8U, 0xbed80a3aU,
    0xe58348b0U, 0xaf63e58dU, 0x406aec9dU, 0xc233f007U,
    0xa5ead0bdU, 0x050143a6U, 0x738b6829U, 0x3699caf3U,
    0x967cd710U, 0x06f665a6U, 0x25fd3d7fU, 0x0fd6e479U,
    0x26fbf29bU, 0x16de4c35U, 0x2bf3394bU, 0x4af864baU,
    0x1cb9e6c6U, 0x41439089U, 0x69a39144U, 0xc34f182dU,
    0x421657ffU, 0xf9fc6568U, 0x8b02c917U, 0x6c9c64b7U,
    0x83d17909U, 0xea3d4ca5U, 0xaf635d47U, 0x7fc78769U,
    0xbe14186fU, 0x3539b1eaU, 0xe9174548U, 0xc051e18aU,
    0x07b73658U, 0x29ec300cU, 0xa250bf34U, 0xa7ed5d97U,
    0xfe3dea79U, 0xb8b352f7U, 0xc9b344e9U, 0x8e5f0475U,
    0x1941e52aU, 0x2694763dU, 0x6b40eabcU, 0x8485d68bU,
    0x336eaccaU, 0x4399a363U, 0x67149b9cU, 0xae10a901U,
    0x5a5ffefbU, 0x563b26deU, 0x6f00f02bU, 0x9f06397dU,
    0x545836c4U, 0x31d6416bU, 0x12f4128dU, 0x752f33ffU,
    0x4a305605U, 0x0c8dc214U, 0x72521a90U, 0x8eb3e4a1U,
    0x83efc6c6U, 0x090ec04fU, 0xc1540864U, 0xec2c8aaaU,
    0x70ab53baU, 0x38d3b494U, 0x878d4063U, 0xa317ae3fU,
    0x3cb62f07U, 0xf360412cU, 0x4ffbf3a9U, 0x22d554b4U,
    0x3f190476U, 0x0796a710U, 0xf5c353cfU, 0x04f59bb7U,
    0x2d230176U, 0xe2d6a9ceU, 0x3f1d7427U, 0xafd915bbU,
    0xb01aa47dU, 0xcde2c269U, 0x7417bf38U, 0x1e094f9aU,
    0x55ece0eaU, 0xcb94539bU, 0x13d346b5U, 0x54e0c0c1U,
    0x6db30e37U, 0xdc02b390U, 0xa6e222f5U, 0xe2f8c1feU,
    0x2e166bdfU, 0x67588a74U, 0x21898f34U, 0x4c330f1dU,
    0x19af53baU, 0x70658b94U, 0x133c9673U, 0x4efeeaddU,
    0x0f212551U, 0x070f0914U, 0x6f241c57U, 0xf13e41b7U,
    0x3be70cb0U, 0xf4b6f47fU, 0x20f31127U, 0x6551cb89U,
    0x289cbd2cU, 0x8946f23dU, 0x40a79c3bU, 0x03c6d982U,
    0x0365790cU, 0x0cf52517U, 0x0bb131e8U, 0x3da5475cU,
    0x139efccaU, 0xbcd44eb4U, 0xa54af747U, 0xb73c32edU,
    0x9f6c47acU, 0xe8ba8f22U, 0x54043a66U, 0x3b0a7f20U,
    0xb4926431U, 0xe17c02d5U, 0x8f0d2558U, 0x014fbff2U,
    0x7f803594U, 0x79b76fbeU, 0x33fe2656U, 0x792c8ee8U,
    0x6b41292dU, 0xfdff9c32U, 0x82093298U, 0x59483870U,
    0xb2d5a113U, 0x2dd96e5aU, 0x5b8e56a9U, 0xebd9dda9U,
    0x04f9ce92U, 0xcb440950U, 0xa67e52b1U, 0x49f6d261U,
    0x92417fc3U, 0x1c3b6bd9U, 0xb027b7e0U, 0x1f765a41U,
    0x44c9ab40U, 0x45d99121U, 0xfd7a84afU, 0x99b75788U,
    0xe3abff4aU, 0xa88aa67fU, 0x736e41ccU, 0x9cbcbe5eU,
    0x7b3ccebcU, 0xe1b7fa93U, 0x315ae6afU, 0x9cced2e2U,
    0x19ea0f2fU, 0xa9770722U, 0x84a6bfdcU, 0x88f03f07U,
    0xa44a03a4U, 0x27a6b885U, 0xb580c8baU, 0x018153daU,
    0xb648e604U, 0x51180278U, 0x893a310fU, 0x728f5f4cU,
    0x37f5198bU, 0x3cc0ea9bU, 0xe39d02dbU, 0x13883142U,
    0xca599392U, 0xc12d154eU, 0xc176163dU, 0x5c92e2b8U,
    0xf9f95edeU, 0xb802bdfcU, 0x8a928585U, 0xdca6e10bU,
    0x887953e8U, 0x48b9e962U, 0xe533e9a3U, 0x5e0ce6e5U,
    0x1dba77aeU, 0xc8214b8aU, 0x53b428d7U, 0x4cf20a65U,
};

typedef struct {
    uint32_t h;
    unsigned char window[SPLITTER_WINDOW];
    int oldest;
    long count;
} splitter_t;

static void splitter_init(splitter_t *sp) {
    sp->h = 0;
    sp->oldest = 0;
    sp->count = 0;
    /* kopia: s.Write(make([]byte, 64)) — 64 zero bytes */
    for (int i = 0; i < SPLITTER_WINDOW; i++) {
        sp->h = (sp->h << 1) | (sp->h >> 31);
        sp->h ^= buzhash_table[0];
    }
}

static int splitter_should_split(splitter_t *sp, unsigned char byte) {
    /* roll: sum = rotl(sum,1) ^ rotl(T[out], nRotate=0) ^ T[in] */
    unsigned char out = sp->window[sp->oldest];
    sp->window[sp->oldest] = byte;
    sp->oldest = (sp->oldest + 1) % SPLITTER_WINDOW;
    sp->h = ((sp->h << 1) | (sp->h >> 31)) ^ buzhash_table[out] ^ buzhash_table[byte];
    sp->count++;

    if (sp->count >= SPLITTER_MAX) {
        sp->count = 0;
        return 1;
    }
    if (sp->count >= SPLITTER_MIN && (sp->h & SPLITTER_MASK) == 0) {
        sp->count = 0;
        return 1;
    }
    return 0;
}

/* ---- object upload ---- */

typedef struct {
    FILE *f;                       /* set for file sources */
    const unsigned char *buf;      /* set for in-memory sources */
    size_t len, pos;
} ksrc_t;

static size_t src_read(ksrc_t *src, unsigned char *out, size_t n) {
    if (src->f) return fread(out, 1, n, src->f);
    size_t rem = src->len - src->pos;
    if (rem == 0) return 0;
    size_t take = n < rem ? n : rem;
    memcpy(out, src->buf + src->pos, take);
    src->pos += take;
    return take;
}

typedef struct {
    uint64_t start;
    uint64_t length;
    char     oid[256];
} chunk_entry_t;

/* Upload a stream: chunk + WriteContent each; returns object ID string.
 * content_prefix: "" for file data, "k" for directory objects, "x" for indirect. */
static int upload_stream(kopia_session_t *s, ksrc_t *src, const char *content_prefix,
                         char *oid, size_t oid_len) {
    chunk_entry_t *chunks = NULL;
    int nchunks = 0, cap = 0;
    unsigned char buf[65536];
    splitter_t sp;
    splitter_init(&sp);

    unsigned char *cur = NULL;
    size_t cur_len = 0, cur_cap = 0;
    uint64_t offset = 0;

    /* read whole stream, split on boundaries */
    size_t n;
    while ((n = src_read(src, buf, sizeof(buf))) > 0) {
        for (size_t i = 0; i < n; i++) {
            if (cur_len + 1 > cur_cap) {
                cur_cap = cur_cap ? cur_cap * 2 : 65536;
                cur = realloc(cur, cur_cap);
            }
            cur[cur_len++] = buf[i];
            if (splitter_should_split(&sp, buf[i])) {
                if (nchunks >= cap) {
                    cap = cap ? cap * 2 : 8;
                    chunks = realloc(chunks, (size_t)cap * sizeof(*chunks));
                }
                chunks[nchunks].start = offset;
                chunks[nchunks].length = cur_len;
                chunks[nchunks].oid[0] = '\0';
                int rc = ksess_write_content(s, content_prefix, cur, cur_len,
                                             chunks[nchunks].oid, sizeof(chunks[nchunks].oid));
                if (rc != 0) {
                    fprintf(stderr, "diag: chunk %d write failed rc=%d (%zu bytes)\n",
                            nchunks, rc, cur_len);
                    free(cur); free(chunks); return -1;
                }
                nchunks++;
                offset += cur_len;
                cur_len = 0;
            }
        }
    }
    if (cur_len > 0 || nchunks == 0) {
        if (nchunks >= cap) {
            cap = cap ? cap * 2 : 8;
            chunks = realloc(chunks, (size_t)cap * sizeof(*chunks));
        }
        chunks[nchunks].start = offset;
        chunks[nchunks].length = cur_len;
        chunks[nchunks].oid[0] = '\0';
        int rc = ksess_write_content(s, content_prefix, cur ? cur : (const unsigned char *)"",
                                     cur_len, chunks[nchunks].oid, sizeof(chunks[nchunks].oid));
        if (rc != 0) {
            fprintf(stderr, "diag: final flush write failed rc=%d (%zu bytes)\n", rc, cur_len);
            free(cur); free(chunks); return -1;
        }
        nchunks++;
    }
    free(cur);

    if (nchunks == 1) {
        snprintf(oid, oid_len, "%s", chunks[0].oid);
        free(chunks);
        return 0;
    }

    /* multi-chunk: write indirect object (prefix "x") */
    strbuf_t sb;
    sb_init(&sb);
    sb_puts(&sb, "{\"stream\":\"kopia:indirect\",\"entries\":[");
    for (int i = 0; i < nchunks; i++) {
        if (i) sb_puts(&sb, ",");
        sb_printf(&sb, "{\"s\":%llu,\"l\":%llu,\"o\":\"%s\"}",
                  (unsigned long long)chunks[i].start,
                  (unsigned long long)chunks[i].length, chunks[i].oid);
    }
    sb_puts(&sb, "]}\n");

    char indirect_cid[256];
    int rc = ksess_write_content(s, "x", (const unsigned char *)sb.buf, sb.len,
                                 indirect_cid, sizeof(indirect_cid));
    sb_free(&sb);
    free(chunks);
    if (rc != 0) {
        fprintf(stderr, "diag: indirect write failed rc=%d\n", rc);
        return -1;
    }
    snprintf(oid, oid_len, "I%s", indirect_cid);
    return 0;
}

/* ---- directory upload ---- */

typedef struct {
    char name[512];
    char type[2];   /* "f","d" */
    int  mode;
    long long size;
    char mtime[64];
    char oid[256];
} dir_entry_t;

static void format_mtime_rfc3339(long long epoch_s, long nsec, char *out, size_t outlen) {
    time_t t = (time_t)epoch_s;
    struct tm g;
#ifdef __APPLE__
    gmtime_r(&t, &g);
#else
    gmtime_r(&t, &g);
#endif
    snprintf(out, outlen, "%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ",
             g.tm_year + 1900, g.tm_mon + 1, g.tm_mday,
             g.tm_hour, g.tm_min, g.tm_sec, nsec);
}

/* aggregate summary for the most recently built directory + root file size */
static long long g_total_size, g_files, g_dirs;
static char g_maxtime[64] = "";

static int cmp_entry(const void *a, const void *b) {
    return strcmp(((const dir_entry_t *)a)->name, ((const dir_entry_t *)b)->name);
}

static int mtime_of(const char *path, char *out, size_t outlen) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
#ifdef __APPLE__
    long long s = (long long)st.st_mtimespec.tv_sec;
    long ns = st.st_mtimespec.tv_nsec;
#else
    long long s = (long long)st.st_mtim.tv_sec;
    long ns = st.st_mtim.tv_nsec;
#endif
    format_mtime_rfc3339(s, ns, out, outlen);
    return 0;
}

/* recursive tree stats — aggregated up from children so the root summary
 * (shown by the kopia server UI) reflects the whole tree */
typedef struct {
    long long size;
    long long files;
    long long dirs;
    char maxtime[64];
} dir_stats_t;

static long long g_skipped_files = 0, g_skipped_dirs = 0;

static int upload_dir_recursive(kopia_session_t *s, const char *path, char *oid, size_t oid_len,
                                dir_stats_t *stats);

static int upload_file_entry(kopia_session_t *s, const char *fullpath, char *oid, size_t oid_len) {
    FILE *f = fopen(fullpath, "rb");
    if (!f) {
        fprintf(stderr, "diag: fopen failed for %s: %s\n", fullpath, strerror(errno));
        return -1;
    }
    ksrc_t src = {0};
    src.f = f;
    int rc = upload_stream(s, &src, "", oid, oid_len);
    fclose(f);
    return rc;
}

static int build_dir_json(kopia_session_t *s, const char *path, char **json_out,
                          dir_stats_t *stats) {
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "diag: opendir failed: %s\n", path);
        return -1;
    }

    memset(stats, 0, sizeof(*stats));
    dir_entry_t *entries = NULL;
    int n = 0, cap = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, de->d_name);
        struct stat st;
        if (lstat(fullpath, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue; /* MVP: skip symlinks */

        if (n >= cap) {
            cap = cap ? cap * 2 : 16;
            entries = realloc(entries, (size_t)cap * sizeof(*entries));
        }
        dir_entry_t *e = &entries[n];
        snprintf(e->name, sizeof(e->name), "%s", de->d_name);
        e->mode = (int)(st.st_mode & 07777);
        e->size = 0;
        e->oid[0] = '\0';

        if (S_ISDIR(st.st_mode)) {
            strcpy(e->type, "d");
            char suboid[256];
            mtime_of(fullpath, e->mtime, sizeof(e->mtime));
            dir_stats_t child;
            if (upload_dir_recursive(s, fullpath, suboid, sizeof(suboid), &child) != 0) {
                fprintf(stderr, "diag: skipping unreadable subdir %s\n", fullpath);
                g_skipped_dirs++;
                continue; /* omit from snapshot, keep walking */
            }
            snprintf(e->oid, sizeof(e->oid), "%s", suboid);
            e->size = 0;
            stats->size += child.size;
            stats->files += child.files;
            stats->dirs += child.dirs + 1;
            if (child.maxtime[0] &&
                (stats->maxtime[0] == '\0' || strcmp(child.maxtime, stats->maxtime) > 0))
                snprintf(stats->maxtime, sizeof(stats->maxtime), "%s", child.maxtime);
        } else if (S_ISREG(st.st_mode)) {
            strcpy(e->type, "f");
            e->size = (long long)st.st_size;
            mtime_of(fullpath, e->mtime, sizeof(e->mtime));
            if (upload_file_entry(s, fullpath, e->oid, sizeof(e->oid)) != 0) {
                fprintf(stderr, "diag: skipping file %s (upload failed)\n", fullpath);
                g_skipped_files++;
                continue; /* omit from snapshot, keep walking */
            }
            stats->size += e->size;
            stats->files++;
        } else {
            continue; /* special files skipped */
        }
        if (e->mtime[0] &&
            (stats->maxtime[0] == '\0' || strcmp(e->mtime, stats->maxtime) > 0))
            snprintf(stats->maxtime, sizeof(stats->maxtime), "%s", e->mtime);
        n++;
    }
    closedir(d);

    qsort(entries, (size_t)n, sizeof(dir_entry_t), cmp_entry);

    if (stats->maxtime[0] == '\0') format_mtime_rfc3339(0, 0, stats->maxtime, sizeof(stats->maxtime));

    /* remember summary — the outermost (root) dir finishes last */
    g_total_size = total_size;
    g_files = files;
    g_dirs = dirs;
    snprintf(g_maxtime, sizeof(g_maxtime), "%s", maxtime);

    strbuf_t sb;
    sb_init(&sb);
    sb_puts(&sb, "{\"stream\":\"kopia:directory\",\"entries\":[");
    for (int i = 0; i < n; i++) {
        if (i) sb_puts(&sb, ",");
        sb_puts(&sb, "{\"name\":");
        sb_puts_json(&sb, entries[i].name);
        sb_printf(&sb, ",\"type\":\"%s\",\"mode\":\"0%o\"", entries[i].type, entries[i].mode);
        if (entries[i].size) sb_printf(&sb, ",\"size\":%lld", entries[i].size);
        sb_printf(&sb, ",\"mtime\":\"%s\"", entries[i].mtime);
        sb_printf(&sb, ",\"obj\":\"%s\"", entries[i].oid);
        sb_puts(&sb, "}");
    }
    sb_puts(&sb, "],\"summary\":{\"size\":");
    sb_printf(&sb, "%lld", stats->size);
    sb_printf(&sb, ",\"files\":%lld,\"dirs\":%lld,\"maxTime\":\"%s\"}",
              stats->files, stats->dirs, stats->maxtime);
    sb_puts(&sb, "}\n");

    free(entries);
    *json_out = sb.buf;
    (void)s;
    return 0;
}

static int upload_dir_recursive(kopia_session_t *s, const char *path, char *oid, size_t oid_len,
                                dir_stats_t *stats) {
    char *json = NULL;
    if (build_dir_json(s, path, &json, stats) != 0) {
        fprintf(stderr, "diag: build_dir_json failed for %s\n", path);
        return -1;
    }

    ksrc_t src = {0};
    src.buf = (const unsigned char *)json;
    src.len = strlen(json);
    int rc = upload_stream(s, &src, "k", oid, oid_len);
    free(json);
    if (rc != 0) fprintf(stderr, "diag: dir upload_stream failed for %s\n", path);
    return rc;
}

int kup_upload_path(kopia_session_t *s, const char *path, char *object_id, size_t oid_len) {
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "diag: stat failed for %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (S_ISDIR(st.st_mode)) {
        dir_stats_t stats;
        int rc = upload_dir_recursive(s, path, object_id, oid_len, &stats);
        if (rc == 0) {
            /* root summary feeds the snapshot manifest */
            g_total_size = stats.size;
            g_files = stats.files;
            g_dirs = stats.dirs;
            snprintf(g_maxtime, sizeof(g_maxtime), "%s", stats.maxtime);
            if (g_skipped_files || g_skipped_dirs)
                fprintf(stderr, "diag: completed with %lld skipped files, %lld skipped dirs\n",
                        g_skipped_files, g_skipped_dirs);
        }
        return rc;
    }
    return upload_file_entry(s, path, object_id, oid_len);
}

int kup_snapshot(kopia_session_t *s, const char *source_path,
                 const char *root_object_id, char *manifest_id, size_t id_len) {
    /* resolve to absolute path */
    char abspath[4096];
    if (realpath(source_path, abspath) == NULL) {
        snprintf(abspath, sizeof(abspath), "%s", source_path);
    }

    char mt[64];
    format_mtime_rfc3339((long long)time(NULL), 0, mt, sizeof(mt));

    /* root entry */
    struct stat st;
    char rootname[512];
    const char *base = strrchr(abspath, '/');
    snprintf(rootname, sizeof(rootname), "%s", base ? base + 1 : abspath);
    int mode = 0;
    int is_dir = 0;
    long long root_size = 0;
    if (stat(abspath, &st) == 0) {
        mode = (int)(st.st_mode & 07777);
        is_dir = S_ISDIR(st.st_mode) ? 1 : 0;
        if (!is_dir) {
            root_size = (long long)st.st_size;
            g_total_size = root_size;
            g_files = 1;
            g_dirs = 0;
        }
    }

    strbuf_t sb;
    sb_init(&sb);
    sb_puts(&sb, "{\"source\":{\"host\":");
    sb_puts_json(&sb, s->cfg.repo_hostname);
    sb_puts(&sb, ",\"userName\":");
    sb_puts_json(&sb, s->cfg.repo_user);
    sb_puts(&sb, ",\"path\":");
    sb_puts_json(&sb, abspath);
    sb_printf(&sb, "},\"description\":\"kopia-darwin-ppc\",\"startTime\":\"%s\",\"endTime\":\"%s\",", mt, mt);
    sb_printf(&sb, "\"stats\":{\"totalSize\":%lld,\"fileCount\":%lld,\"dirCount\":%lld},",
              g_total_size, g_files, g_dirs);
    sb_puts(&sb, "\"rootEntry\":{\"name\":");
    sb_puts_json(&sb, rootname);
    if (is_dir) {
        /* dirs carry a summary; file size goes on the entry itself */
        sb_printf(&sb, ",\"type\":\"d\",\"mode\":\"0%o\",\"mtime\":\"%s\","
                     "\"summ\":{\"size\":%lld,\"files\":%lld,\"dirs\":%lld,\"maxTime\":\"%s\"}",
                  mode, mt, g_total_size, g_files, g_dirs, g_maxtime);
        sb_printf(&sb, ",\"obj\":\"%s\"}}", root_object_id);
    } else {
        sb_printf(&sb, ",\"type\":\"f\",\"mode\":\"0%o\",\"size\":%lld,\"mtime\":\"%s\",\"obj\":\"%s\"}}",
                  mode, root_size, mt, root_object_id);
    }

    const char *labels[8] = {
        "type", "snapshot",
        "hostname", s->cfg.repo_hostname,
        "username", s->cfg.repo_user,
        "path", abspath,
    };
    int rc = ksess_put_manifest(s, sb.buf, labels, 8, manifest_id, id_len);
    sb_free(&sb);
    return rc;
}
