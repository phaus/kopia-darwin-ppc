/* Unit test for kopia_cache.c — compile and run on any host:
 *   cc -std=c99 -Iinclude tests/cache-test.c src/kopia_cache.c src/kopia_sha256.c -o /tmp/cache-test && /tmp/cache-test
 */
#define _DEFAULT_SOURCE /* setenv */
#include "kopia_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int failures = 0;
static void check(int cond, const char *what) {
    if (!cond) { printf("FAIL: %s\n", what); failures++; }
}

/* same hash as the module (fnv1a64 over "url|user|host|source") */
static unsigned long long fnv1a64(const char *s) {
    unsigned long long h = 0xcbf29ce484222325ULL;
    for (; *s; s++) { h ^= (unsigned char)*s; h *= 0x100000001b3ULL; }
    return h;
}

static void make_cfg(kopia_config_t *c, const char *url) {
    memset(c, 0, sizeof(*c));
    snprintf(c->server_url, sizeof(c->server_url), "%s", url);
    strcpy(c->repo_user, "test");
    strcpy(c->repo_hostname, "testhost");
}

static void cache_path(const kopia_config_t *cfg, const char *source,
                       const char *dir, char *out, size_t outlen) {
    char key[1600];
    snprintf(key, sizeof(key), "%s|%s|%s|%s",
             cfg->server_url, cfg->repo_user, cfg->repo_hostname, source);
    snprintf(out, outlen, "%s/cache-%016llx.dat", dir, fnv1a64(key));
}

int main(void) {
    system("rm -rf /tmp/kpp-cache-test && mkdir -p /tmp/kpp-cache-test");
    setenv("KOPIA_CACHE_DIR", "/tmp/kpp-cache-test", 1);

    kopia_config_t cfg;
    make_cfg(&cfg, "https://kopia.test:51515");

    dir_entry_t e[3];
    memset(e, 0, sizeof(e));
    strcpy(e[0].name, "a.txt"); strcpy(e[0].type, "f"); e[0].size = 12;
    strcpy(e[0].mtime, "2026-11-12T10:00:00.000000000Z"); strcpy(e[0].oid, "kaaa");
    strcpy(e[1].name, "b.log"); strcpy(e[1].type, "f"); e[1].size = 99;
    strcpy(e[1].mtime, "2026-11-12T10:00:01.000000000Z"); strcpy(e[1].oid, "kbbb");
    strcpy(e[2].name, "sub");   strcpy(e[2].type, "d");

    unsigned char sha[32];
    memset(sha, 0xAB, 32);
    char oid[256];

    /* run 1: no previous cache, record two dirs */
    check(kcache_begin(&cfg, "/src") == 0, "begin run1");
    check(kcache_lookup_file("", "a.txt", 12, e[0].mtime, oid, sizeof(oid)) == 0,
          "no reuse without previous cache");
    kcache_record_dir("", e, 3, "kroot", sha);
    kcache_record_dir("sub", e, 1, "ksub", sha);
    kcache_commit();

    /* run 2: load + reuse */
    check(kcache_begin(&cfg, "/src") == 0, "begin run2 loads cache");
    check(kcache_lookup_file("", "a.txt", 12, e[0].mtime, oid, sizeof(oid)) == 1 &&
          strcmp(oid, "kaaa") == 0, "file reused (root)");
    check(kcache_lookup_file("", "b.log", 99, e[1].mtime, oid, sizeof(oid)) == 1 &&
          strcmp(oid, "kbbb") == 0, "file reused sorted b");
    check(kcache_lookup_file("", "a.txt", 13, e[0].mtime, oid, sizeof(oid)) == 0,
          "size mismatch -> no reuse");
    check(kcache_lookup_file("", "a.txt", 12, "2026-11-12T10:00:02.000000000Z", oid, sizeof(oid)) == 0,
          "mtime mismatch -> no reuse");
    check(kcache_lookup_file("", "zz.txt", 12, e[0].mtime, oid, sizeof(oid)) == 0,
          "unknown file -> no reuse");
    check(kcache_lookup_file("sub", "a.txt", 12, e[0].mtime, oid, sizeof(oid)) == 1 &&
          strcmp(oid, "kaaa") == 0, "file reused in subdir");
    check(kcache_lookup_file("other", "a.txt", 12, e[0].mtime, oid, sizeof(oid)) == 0,
          "unknown dir -> no reuse");
    check(kcache_lookup_dir("", sha, oid, sizeof(oid)) == 1 && strcmp(oid, "kroot") == 0,
          "dir oid reused on identical sha");
    check(kcache_lookup_dir("sub", sha, oid, sizeof(oid)) == 1 && strcmp(oid, "ksub") == 0,
          "subdir oid reused");
    unsigned char sha2[32];
    memset(sha2, 0xCD, 32);
    check(kcache_lookup_dir("", sha2, oid, sizeof(oid)) == 0, "dir not reused on different sha");
    kcache_commit();

    /* foreign identity: same cache dir, different source -> no reuse */
    check(kcache_begin(&cfg, "/other-source") == 0, "begin with foreign identity");
    check(kcache_lookup_file("", "a.txt", 12, e[0].mtime, oid, sizeof(oid)) == 0,
          "foreign identity -> no reuse");
    kcache_commit();

    /* corrupt cache file -> ignored, lookups return 0, run stays enabled */
    {
        char p[512];
        cache_path(&cfg, "/corrupt", "/tmp/kpp-cache-test", p, sizeof(p));
        FILE *f = fopen(p, "wb");
        fwrite("GARBAGE-GARBAGE-GARBAGE", 1, 23, f);
        fclose(f);
        check(kcache_begin(&cfg, "/corrupt") == 0, "begin tolerates corrupt cache");
        check(kcache_lookup_file("", "a.txt", 12, e[0].mtime, oid, sizeof(oid)) == 0,
              "corrupt cache -> no reuse");
        /* and a fresh cache is still written */
        kcache_record_dir("", e, 1, "kroot2", sha);
        kcache_commit();
        check(kcache_begin(&cfg, "/corrupt") == 0, "begin after corrupt-cache recovery");
        check(kcache_lookup_dir("", sha, oid, sizeof(oid)) == 1 && strcmp(oid, "kroot2") == 0,
              "recovered cache works");
    }

    /* truncated cache: header only */
    {
        char p[512];
        cache_path(&cfg, "/trunc", "/tmp/kpp-cache-test", p, sizeof(p));
        FILE *f = fopen(p, "wb");
        fwrite("KPPC1", 1, 5, f);
        fclose(f);
        check(kcache_begin(&cfg, "/trunc") == 0, "begin tolerates truncated cache");
        check(kcache_lookup_file("", "a.txt", 12, e[0].mtime, oid, sizeof(oid)) == 0,
              "truncated cache -> no reuse");
        kcache_commit();
    }

    printf(failures ? "%d FAILURES\n" : "PASS: all cache tests\n", failures);
    return failures != 0;
}
