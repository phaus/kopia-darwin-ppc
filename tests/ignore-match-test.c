/* Unit test for kopia_ignore.c — compile and run on any host:
 *   cc -std=c99 -I../include tests/ignore-match-test.c src/kopia_ignore.c -o /tmp/ignore-test && /tmp/ignore-test
 */
#include "kopia_ignore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(int cond, const char *what) {
    if (!cond) { printf("FAIL: %s\n", what); failures++; }
}

static void expect_ignored(const char *pat_or_file_line, const char *rel, int is_dir, int want,
                           const char *label) {
    kignore_reset();
    if (kignore_add_pattern(pat_or_file_line) != 0) { printf("FAIL: add %s\n", label); failures++; return; }
    int got = kignore_match(rel, is_dir);
    if (got != want) { printf("FAIL: %s: match(%s, dir=%d) = %d, want %d\n", label, rel, is_dir, got, want); failures++; }
}

static void expect_two(const char *p1, const char *p2, const char *rel, int is_dir, int want,
                       const char *label) {
    kignore_reset();
    kignore_add_pattern(p1);
    kignore_add_pattern(p2);
    int got = kignore_match(rel, is_dir);
    if (got != want) { printf("FAIL: %s: match(%s, dir=%d) = %d, want %d\n", label, rel, is_dir, got, want); failures++; }
}

int main(void) {
    /* bare names match at any depth, files and dirs */
    expect_ignored("foo", "foo", 0, 1, "bare self");
    expect_ignored("foo", "a/foo", 0, 1, "bare nested");
    expect_ignored("foo", "a/b/foo", 1, 1, "bare deep dir");
    expect_ignored("foo", "a/foobar", 0, 0, "bare not prefix");
    expect_ignored("foo", "a/foo/b", 0, 0, "bare not parent");

    /* suffix wildcards */
    expect_ignored("*.log", "x.log", 0, 1, "star self");
    expect_ignored("*.log", "a/b/x.log", 0, 1, "star nested");
    expect_ignored("*.log", "a/b/x.log.gz", 0, 0, "star no cross-ext");
    expect_ignored("*.log", "logs", 0, 0, "star not name");

    /* '*' and '?' stay within one segment */
    expect_ignored("a*", "a/b", 0, 0, "star no slash-cross");
    expect_ignored("a/*", "a/x", 0, 1, "star one level");
    expect_ignored("a/*", "a/x/y", 0, 0, "star not two levels");
    expect_ignored("te?t", "test", 0, 1, "qmark hit");
    expect_ignored("te?t", "te/t", 0, 0, "qmark no slash");
    expect_ignored("te?t", "tst", 0, 0, "qmark miss");

    /* anchored patterns */
    expect_ignored("foo/bar", "foo/bar", 0, 1, "mid-slash anchored");
    expect_ignored("foo/bar", "x/foo/bar", 0, 0, "mid-slash not suffix-anchored");
    expect_ignored("Library/Caches", "Library/Caches", 1, 1, "anchored dir");
    expect_ignored("Library/Caches", "x/Library/Caches", 1, 0, "anchored not elsewhere");
    expect_ignored("Library/Caches", "Library/Caches/com.apple/y", 0, 0, "anchored not children");
    expect_ignored("/foo", "foo", 0, 1, "leading slash anchored");
    expect_ignored("/foo", "a/foo", 0, 0, "leading slash not nested");

    /* ** segments */
    expect_ignored("**/foo", "foo", 0, 1, "dblstar lead zero");
    expect_ignored("**/foo", "a/b/foo", 0, 1, "dblstar lead many");
    expect_ignored("a/**/b", "a/b", 0, 1, "dblstar mid zero");
    expect_ignored("a/**/b", "a/x/y/b", 0, 1, "dblstar mid many");
    expect_ignored("a/**/b", "a/x", 0, 0, "dblstar mid miss");
    expect_ignored("a/**", "a/x", 0, 1, "dblstar tail one");
    expect_ignored("a/**", "a/x/y", 0, 1, "dblstar tail deep");
    expect_ignored("a/**", "a", 0, 0, "dblstar tail not self");
    expect_ignored("**", "anything/at/all", 0, 1, "dblstar all");

    /* common cases */
    expect_ignored("**/Cache*", "Library/Caches", 1, 1, "dblstar + star");
    expect_ignored(".svn", "a/.svn", 1, 1, "dotfile dir");
    expect_ignored("ünicode", "ünicode", 0, 1, "utf8 bytes");

    /* dir-only patterns */
    expect_ignored("build/", "build", 1, 1, "dir-only dir");
    expect_ignored("build/", "a/build", 1, 1, "dir-only nested dir");
    expect_ignored("build/", "build", 0, 0, "dir-only vs file");

    /* negation: last match wins */
    expect_two("*.log", "!keep.log", "x.log", 0, 1, "neg plain kept-ignored");
    expect_two("*.log", "!keep.log", "keep.log", 0, 0, "neg plain");
    expect_two("*.log", "!keep.log", "a/keep.log", 0, 0, "neg nested");
    expect_two("!keep.log", "*.log", "keep.log", 0, 1, "neg order matters");
    expect_two("data", "!data/keep.txt", "data/keep.txt", 0, 0, "re-include under pruned dir (matcher-level)");

    /* add_pattern errors */
    kignore_reset();
    check(kignore_add_pattern("") == 0 && kignore_count() == 0, "empty pattern skipped");
    check(kignore_add_pattern("   ") == 0 && kignore_count() == 0, "blank pattern skipped");
    {
        char big[1200]; memset(big, 'a', sizeof(big)); big[sizeof(big) - 1] = '\0';
        check(kignore_add_pattern(big) == -1, "oversize pattern rejected");
    }

    /* file loading: comments, blanks, negation, trailing-space trim; CRLF tolerated */
    {
        FILE *f = fopen("/tmp/kpp-ignore-test.txt", "w");
        fprintf(f, "# comment line\n\n*.log   \r\n!keep.log\r\n# another comment\n");
        fclose(f);
        kignore_reset();
        int n = kignore_add_file("/tmp/kpp-ignore-test.txt");
        check(n == 2, "file: two rules added");
        check(kignore_match("x.log", 0) == 1, "file: x.log ignored");
        check(kignore_match("keep.log", 0) == 0, "file: keep.log kept");
        kignore_reset();
        check(kignore_count() == 0, "reset works");
    }
    {
        FILE *f = fopen("/tmp/kpp-ignore-big.txt", "w");
        for (int i = 0; i < 1100; i++) fputc('a', f);
        fputc('\n', f);
        fclose(f);
        kignore_reset();
        check(kignore_add_file("/tmp/kpp-ignore-big.txt") == -1, "oversize line rejected");
    }

    /* default .kopiaignore discovery */
    {
        system("mkdir -p /tmp/kpp-ignore-src && printf '*.tmp\\n' > /tmp/kpp-ignore-src/.kopiaignore");
        kignore_reset();
        check(kignore_load_source_default("/tmp/kpp-ignore-src") == 1, "default file found");
        check(kignore_match("a/x.tmp", 0) == 1, "default file rule applied");
        check(kignore_load_source_default("/tmp") == 0, "absent default is not an error");
    }

    printf(failures ? "%d FAILURES\n" : "PASS: all ignore matcher tests\n", failures);
    return failures != 0;
}
