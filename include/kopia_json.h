#ifndef KOPIA_JSON_H
#define KOPIA_JSON_H

/* Minimal JSON string builder used to assemble API requests and objects. */

#include <stdarg.h>
#include <stddef.h>

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} strbuf_t;

void sb_init(strbuf_t *sb);
void sb_free(strbuf_t *sb);
void sb_puts(strbuf_t *sb, const char *s);
void sb_puts_json(strbuf_t *sb, const char *s); /* writes "..." escaped literal */
void sb_printf(strbuf_t *sb, const char *fmt, ...);

#endif /* KOPIA_JSON_H */
