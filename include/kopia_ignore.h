#ifndef KOPIA_IGNORE_H
#define KOPIA_IGNORE_H

/*
 * gitignore-style ignore rules for the walker (kopia_upload.c).
 *
 * Supported syntax (documented subset of gitignore, kopia-compatible):
 *   - one pattern per line; blank lines and "# comments" are skipped;
 *     trailing whitespace is trimmed
 *   - "!" prefix negates a previous match (last matching pattern wins)
 *   - trailing "/" marks a directory-only pattern
 *   - a pattern with an interior separator ("/") is anchored to the source
 *     root; a bare name matches a basename at any depth
 *   - "*" matches within one path segment, "?" a single char within a
 *     segment, "**" as a whole segment matches zero or more segments
 *   - paths are matched relative to the source root, "/"-separated
 *   - as in git, a file cannot be re-included ("!") once its parent
 *     directory is excluded
 *
 * Excluded directories are pruned (not walked), so ignore rules are also a
 * performance feature: matched subtrees cost nothing.
 */

/* Add one pattern. Returns 0 on success, -1 on malformed/oversized pattern. */
int kignore_add_pattern(const char *pattern);

/* Load patterns from a file. Returns number added, -1 if unreadable. */
int kignore_add_file(const char *path);

/* Load <source>/.kopiaignore if it exists. Returns 1 loaded, 0 absent, -1 error. */
int kignore_load_source_default(const char *source_path);

/* Number of active rules. */
int kignore_count(void);

/* 1 = ignore this relative path ("/"-separated, no leading slash). */
int kignore_match(const char *relpath, int is_dir);

void kignore_reset(void);

#endif /* KOPIA_IGNORE_H */
