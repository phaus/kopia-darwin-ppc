/* kopia_json.c — minimal JSON string builder + escaping (no deps) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kopia_json.h"

void sb_init(strbuf_t *sb) {
    sb->buf = malloc(1024);
    sb->cap = 1024;
    sb->len = 0;
    sb->buf[0] = '\0';
}

void sb_free(strbuf_t *sb) {
    free(sb->buf);
    sb->buf = NULL;
    sb->cap = sb->len = 0;
}

static void sb_grow(strbuf_t *sb, size_t need) {
    if (sb->len + need + 1 > sb->cap) {
        while (sb->len + need + 1 > sb->cap) sb->cap *= 2;
        sb->buf = realloc(sb->buf, sb->cap);
    }
}

void sb_puts(strbuf_t *sb, const char *s) {
    size_t n = strlen(s);
    sb_grow(sb, n);
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
}

/* JSON string literal with escaping: "..." */
void sb_puts_json(strbuf_t *sb, const char *s) {
    sb_grow(sb, strlen(s) * 6 + 2);
    sb->buf[sb->len++] = '"';
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
        case '"':  memcpy(sb->buf + sb->len, "\\\"", 2); sb->len += 2; break;
        case '\\': memcpy(sb->buf + sb->len, "\\\\", 2); sb->len += 2; break;
        case '\b': memcpy(sb->buf + sb->len, "\\b", 2); sb->len += 2; break;
        case '\f': memcpy(sb->buf + sb->len, "\\f", 2); sb->len += 2; break;
        case '\n': memcpy(sb->buf + sb->len, "\\n", 2); sb->len += 2; break;
        case '\r': memcpy(sb->buf + sb->len, "\\r", 2); sb->len += 2; break;
        case '\t': memcpy(sb->buf + sb->len, "\\t", 2); sb->len += 2; break;
        default:
            if (*p < 0x20) {
                sb->len += sprintf(sb->buf + sb->len, "\\u%04x", *p);
            } else {
                sb->buf[sb->len++] = *p;
            }
        }
    }
    sb->buf[sb->len++] = '"';
    sb->buf[sb->len] = '\0';
}

void sb_printf(strbuf_t *sb, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { va_end(ap2); return; }
    sb_grow(sb, (size_t)n);
    vsnprintf(sb->buf + sb->len, (size_t)n + 1, fmt, ap2);
    sb->len += (size_t)n;
    va_end(ap2);
}
