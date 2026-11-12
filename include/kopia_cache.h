#ifndef KOPIA_CACHE_H
#define KOPIA_CACHE_H

/*
 * Incremental transfer cache (v0.5): the client remembers, per directory of
 * the source tree, the entries of the last successful run (name, size, mtime,
 * object id) plus each directory object's id and the SHA-256 of its JSON.
 *
 * Next run:
 *   - a file whose size+mtime match the cache is NOT read, chunked or
 *     uploaded — the previous object id is reused (content-addressed, the
 *     server still has it because the last snapshot references it)
 *   - a directory whose rebuilt JSON hashes to the cached value reuses the
 *     previous directory object id — unchanged subtrees cost nothing
 *
 * No local index database: one binary cache file per source under
 * $KOPIA_CACHE_DIR (default /var/db/kopia-darwin-ppc), written atomically
 * (tmp + rename) after a fully successful push. Missing, stale, corrupt or
 * foreign-identity caches are ignored and the run is a full push.
 *
 * Tradeoff (same as kopia itself): a file modified without changing its
 * size or mtime is not detected.
 */

#include "kopia_internal.h"

#include <stddef.h>

/* Called by kup_upload_path before walking a directory source. Returns 0 if
 * a cache was loaded (or none exists but one can be written), -1 if the
 * cache is disabled for this run. */
int kcache_begin(const kopia_config_t *cfg, const char *source_real);

/* Previous-run entry for a file: 1 + oid if name/size/mtime match, else 0. */
int kcache_lookup_file(const char *relpath, const char *name,
                       long long size, const char *mtime,
                       char *oid, size_t oid_len);

/* Previous-run dir object: 1 + oid if the rebuilt JSON hashes identically. */
int kcache_lookup_dir(const char *relpath, const unsigned char json_sha[32],
                      char *oid, size_t oid_len);

/* Record a completed directory (post-order, entries sorted by name) for the
 * next run. No-op when disabled. */
void kcache_record_dir(const char *relpath, const dir_entry_t *entries, int n,
                       const char *dir_oid, const unsigned char json_sha[32]);

/* Promote the pending cache file after a fully successful push. */
void kcache_commit(void);

#endif /* KOPIA_CACHE_H */
