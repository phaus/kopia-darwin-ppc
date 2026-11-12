/* kopia_ignore.c — gitignore-subset matcher for the upload walker.
 * See include/kopia_ignore.h for the supported syntax.
 */

#include "kopia_ignore.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PATTERN 1024
#define MAX_RULES   256

typedef struct {
    char pat[MAX_PATTERN]; /* without leading '!', trailing '/' and leading '/' */
    int  neg;              /* "!pattern" */
    int  dir_only;         /* "pattern/" */
    int  anchored;         /* '/' at the start or in the middle: match from root only */
} rule_t;

static rule_t g_rules[MAX_RULES];
static int    g_nrules = 0;

/* 1 = rule added, 0 = line skipped (empty/comment), -1 = error */
static int add_rule(const char *pat) {
    size_t rawlen = strlen(pat);
    if (rawlen >= MAX_PATTERN) return -1; /* refuse, never truncate */

    char buf[MAX_PATTERN];
    memcpy(buf, pat, rawlen + 1);
    /* trailing whitespace trim */
    size_t len = rawlen;
    while (len > 0 && isspace((unsigned char)buf[len - 1])) buf[--len] = '\0';
    if (len == 0 || buf[0] == '#') return 0; /* blank line or comment */

    if (g_nrules >= MAX_RULES) return -1;

    rule_t *r = &g_rules[g_nrules];
    r->neg = 0;
    r->dir_only = 0;
    /* a separator anywhere but the very end anchors the pattern to the root */
    r->anchored = len > 0 && memchr(buf, '/', len - 1) != NULL;

    const char *p = buf;
    if (*p == '!') { r->neg = 1; p++; }
    if (*p == '/') p++; /* leading slash: anchored (recorded above) */

    size_t plen = strlen(p);
    if (plen > 0 && p[plen - 1] == '/') { r->dir_only = 1; plen--; }
    if (plen == 0 || plen >= sizeof(r->pat)) return -1;

    memcpy(r->pat, p, plen);
    r->pat[plen] = '\0';
    g_nrules++;
    return 1;
}

int kignore_add_pattern(const char *pattern) {
    return add_rule(pattern) < 0 ? -1 : 0;
}

int kignore_add_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[MAX_PATTERN + 4];
    int added = 0;
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        int oversized = (len == sizeof(line) - 1 && line[len - 1] != '\n');
        if (oversized) { /* consume the rest of the overlong line */
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') {}
        }
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
        if (len > 0 && line[len - 1] == '\r') line[--len] = '\0';
        if (oversized) { fclose(f); return -1; } /* refuse rather than mis-match */
        int rc = add_rule(line);
        if (rc < 0) { fclose(f); return -1; }
        added += rc;
    }
    fclose(f);
    return added;
}

int kignore_load_source_default(const char *source_path) {
    char p[4096];
    snprintf(p, sizeof(p), "%s/.kopiaignore", source_path);
    FILE *f = fopen(p, "r");
    if (!f) return 0; /* absent is normal */
    fclose(f);
    int n = kignore_add_file(p);
    return n < 0 ? -1 : 1;
}

int kignore_count(void) { return g_nrules; }

void kignore_reset(void) { g_nrules = 0; }

/* ---- glob matching ---- */

/* Match one pattern segment (length patlen, no '/') against a path segment
 * (length seglen, not NUL-terminated). '*' and '?' never cross '/'. */
static int seg_match(const char *pat, size_t patlen, const char *seg, size_t seglen) {
    if (patlen == 0) return seglen == 0;
    if (*pat == '*') {
        for (size_t i = 0;; i++) {
            if (seg_match(pat + 1, patlen - 1, seg + i, seglen - i)) return 1;
            if (i >= seglen) break;
        }
        return 0;
    }
    if (seglen == 0) return 0;
    if (*pat == '?' || *pat == *seg)
        return seg_match(pat + 1, patlen - 1, seg + 1, seglen - 1);
    return 0;
}

/* Match an anchored pattern against the path starting at 'path'. */
static int path_match(const char *pat, const char *path) {
    const char *pslash = strchr(pat, '/');
    size_t plen = pslash ? (size_t)(pslash - pat) : strlen(pat);

    /* "**" segment: zero or more path segments */
    if (plen == 2 && pat[0] == '*' && pat[1] == '*') {
        if (!pslash) return 1; /* trailing ** matches all remaining */
        const char *rest = pslash + 1;
        if (path_match(rest, path)) return 1; /* zero segments */
        for (const char *t = strchr(path, '/'); t; t = strchr(t + 1, '/'))
            if (path_match(rest, t + 1)) return 1;
        return 0;
    }

    size_t slen = strcspn(path, "/");
    if (!seg_match(pat, plen, path, slen)) return 0;
    if (!pslash) return path[slen] == '\0'; /* pattern consumed: path must be too */
    if (path[slen] == '\0') return 0;       /* pattern continues but path ended */
    return path_match(pslash + 1, path + slen + 1);
}

int kignore_match(const char *relpath, int is_dir) {
    if (g_nrules == 0) return 0;

    int ignored = 0;
    for (int i = 0; i < g_nrules; i++) {
        const rule_t *r = &g_rules[i];
        if (r->dir_only && !is_dir) continue;

        int m;
        if (r->anchored) {
            m = path_match(r->pat, relpath);
        } else {
            /* bare name: match at any depth (each segment-boundary suffix) */
            m = 0;
            const char *t = relpath;
            for (;;) {
                if (path_match(r->pat, t)) { m = 1; break; }
                t = strchr(t, '/');
                if (!t) break;
                t++;
            }
        }
        if (m) ignored = !r->neg; /* last matching pattern wins */
    }
    return ignored;
}
