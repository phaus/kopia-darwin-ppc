/* kopia_h2.c — minimal HTTP/2 client: preface, SETTINGS, HEADERS/DATA frames,
 * HPACK decode of responses, gRPC message extraction. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kopia_internal.h"

#define F_DATA 0
#define F_HEADERS 1
#define F_PRIORITY 2
#define F_RST 3
#define F_SETTINGS 4
#define F_PING 6
#define F_GOAWAY 7
#define F_WINDOW_UPDATE 8
#define F_CONTINUATION 9

#define FLAG_ACK 0x1
#define FLAG_END_STREAM 0x1
#define FLAG_END_HEADERS 0x4

static int write_all(h2_conn_t *c, const unsigned char *p, size_t n) {
    while (n > 0) {
        int w = ktls_write(&c->tls, p, (int)n);
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int h2_write_frame(h2_conn_t *c, int type, int flags, int stream_id,
                          const unsigned char *payload, size_t len) {
    unsigned char hdr[9];
    hdr[0] = (unsigned char)(len >> 16);
    hdr[1] = (unsigned char)(len >> 8);
    hdr[2] = (unsigned char)len;
    hdr[3] = (unsigned char)type;
    hdr[4] = (unsigned char)flags;
    hdr[5] = (unsigned char)(stream_id >> 24) & 0x7f;
    hdr[6] = (unsigned char)(stream_id >> 16);
    hdr[7] = (unsigned char)(stream_id >> 8);
    hdr[8] = (unsigned char)stream_id;

    if (write_all(c, hdr, 9) != 0) {
        fprintf(stderr, "diag: frame hdr write failed (type=%d)\n", type);
        return -1;
    }
    if (len && write_all(c, payload, len) != 0) {
        fprintf(stderr, "diag: frame payload write failed (type=%d len=%zu)\n", type, len);
        return -1;
    }
    return 0;
}

static int h2_read_exact(h2_conn_t *c, unsigned char *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int r = ktls_read(&c->tls, buf + got, (int)(len - got));
        if (r <= 0) {
            fprintf(stderr, "diag: tls read failed r=%d\n", r);
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

int h2_connect(h2_conn_t *c, const char *host, const char *port,
               const unsigned char *fingerprint, char *err, size_t err_len) {
    memset(c, 0, sizeof(*c));
    hpack_dec_init(&c->dec);
    c->peer_max_frame = 16384;      /* spec default */
    c->conn_send_window = 65535;    /* spec default */
    c->stream_send_window = 65535;  /* spec default */

    if (ktls_connect(&c->tls, host, port, fingerprint, err, err_len) != 0) return -1;

    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (ktls_write(&c->tls, (const unsigned char *)preface, 24) != 24) {
        snprintf(err, err_len, "preface write failed");
        return -1;
    }

    /* empty SETTINGS, then expect server SETTINGS + ACK it */
    if (h2_write_frame(c, F_SETTINGS, 0, 0, NULL, 0) != 0) {
        snprintf(err, err_len, "settings write failed");
        return -1;
    }

    unsigned char hdr[9], payload[16384];
    for (;;) {
        if (h2_read_exact(c, hdr, 9) != 0) { snprintf(err, err_len, "no server settings"); return -1; }
        size_t plen = ((size_t)hdr[0] << 16) | ((size_t)hdr[1] << 8) | hdr[2];
        int type = hdr[3];
        if (plen > sizeof(payload)) { snprintf(err, err_len, "frame too large"); return -1; }
        if (plen && h2_read_exact(c, payload, plen) != 0) { snprintf(err, err_len, "frame read failed"); return -1; }
        if (type == F_SETTINGS) {
            if (!(hdr[4] & FLAG_ACK)) {
                if (h2_write_frame(c, F_SETTINGS, FLAG_ACK, 0, NULL, 0) != 0) return -1;
                break;
            }
        }
        /* ignore anything else pre-ack */
    }
    c->handshake_done = 1;
    c->next_stream_id = 1;
    return 0;
}

void h2_close(h2_conn_t *c) {
    if (c->handshake_done) ktls_close(&c->tls);
    hpack_dec_free(&c->dec);
    free(c->data_buf);
    memset(c, 0, sizeof(*c));
}

static void append_data(h2_conn_t *c, const unsigned char *p, size_t n) {
    if (c->data_len + n > c->data_cap) {
        size_t ncap = c->data_cap ? c->data_cap * 2 : 65536;
        while (ncap < c->data_len + n) ncap *= 2;
        c->data_buf = realloc(c->data_buf, ncap);
        c->data_cap = ncap;
    }
    memcpy(c->data_buf + c->data_len, p, n);
    c->data_len += n;
}

static const char *find_hdr(h2_conn_t *c, const char *name) {
    for (int i = 0; i < c->dec.count; i++) {
        if (strcmp(c->dec.hdrs[i].name, name) == 0) return c->dec.hdrs[i].value;
    }
    return NULL;
}

static void send_window_update(h2_conn_t *c, int stream_id, size_t n) {
    unsigned char p[4];
    uint32_t inc = (uint32_t)n;
    p[0] = (unsigned char)(inc >> 24);
    p[1] = (unsigned char)(inc >> 16);
    p[2] = (unsigned char)(inc >> 8);
    p[3] = (unsigned char)inc;
    h2_write_frame(c, F_WINDOW_UPDATE, 0, stream_id, p, 4);
}

int h2_send_headers(h2_conn_t *c, const char *path, const char *authority,
                    const char **names, const char **values, int n) {
    int pairs = 4 + n;
    const char **all = malloc(sizeof(char *) * (size_t)(pairs * 2));
    const char **nm = all;               /* first half: names */
    const char **vl = all + pairs;       /* second half: values */

    nm[0] = ":method";    vl[0] = "POST";
    nm[1] = ":scheme";    vl[1] = "https";
    nm[2] = ":path";      vl[2] = path;
    nm[3] = ":authority"; vl[3] = authority;
    for (int i = 0; i < n; i++) {
        nm[4 + i] = names[i];
        vl[4 + i] = values[i];
    }

    unsigned char *block = NULL;
    size_t blen = 0;
    hpack_encode(nm, vl, pairs, &block, &blen);
    free(all);

    if (getenv("HPACK_DEBUG")) {
        fprintf(stderr, "diag: hpack block (%zu):", blen);
        for (size_t i = 0; i < blen; i++) fprintf(stderr, " %02x", block[i]);
        fprintf(stderr, "\n");
    }

    int sid = c->next_stream_id;
    c->next_stream_id += 2;

    int rc = h2_write_frame(c, F_HEADERS, FLAG_END_HEADERS, sid, block, blen);
    free(block);
    return rc;
}

int h2_send_data(h2_conn_t *c, int stream_id, const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        /* wait until both windows allow at least 1 byte; process frames meanwhile */
        while (c->conn_send_window <= 0 || c->stream_send_window <= 0) {
            int got_data = 0;
            int prc = h2_read_frame(c, stream_id, &got_data);
            if (prc != 0) {
                fprintf(stderr, "diag: send-wait pump rc=%d\n", prc);
                return -1;
            }
            if (got_data || c->trailers_seen) return -2;
        }
        size_t avail = (size_t)(c->conn_send_window < c->stream_send_window
                                    ? c->conn_send_window
                                    : c->stream_send_window);
        size_t n = len - off;
        if (n > avail) n = avail;
        if (n > c->peer_max_frame) n = c->peer_max_frame;

        if (h2_write_frame(c, F_DATA, 0, stream_id, buf + off, n) != 0) return -3;
        c->conn_send_window -= (int32_t)n;
        c->stream_send_window -= (int32_t)n;
        off += n;
    }
    return 0;
}

int h2_send_eof(h2_conn_t *c, int stream_id) {
    return h2_write_frame(c, F_DATA, FLAG_END_STREAM, stream_id, NULL, 0);
}

int h2_read_frame(h2_conn_t *c, int stream_id, int *got_data) {
    unsigned char hdr[9], payload[65536];
    *got_data = 0;

    if (h2_read_exact(c, hdr, 9) != 0) return -1;
    size_t plen = ((size_t)hdr[0] << 16) | ((size_t)hdr[1] << 8) | hdr[2];
    int type = hdr[3], flags = hdr[4];
    int sid = (int)(((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) |
                    ((uint32_t)hdr[7] << 8) | (uint32_t)hdr[8]) & 0x7fffffff;

    if (plen > sizeof(payload)) return -1;
    if (plen && h2_read_exact(c, payload, plen) != 0) return -1;

    switch (type) {
    case F_SETTINGS: {
        if (!(flags & FLAG_ACK)) {
            for (size_t i = 0; i + 6 <= plen; i += 6) {
                int id = (payload[i] << 8) | payload[i + 1];
                uint32_t val = ((uint32_t)payload[i + 2] << 24) | ((uint32_t)payload[i + 3] << 16) |
                               ((uint32_t)payload[i + 4] << 8) | payload[i + 5];
                if (id == 4) { /* INITIAL_WINDOW_SIZE */
                    c->stream_send_window = (int32_t)val;
                } else if (id == 5) { /* MAX_FRAME_SIZE */
                    c->peer_max_frame = val;
                }
            }
            h2_write_frame(c, F_SETTINGS, FLAG_ACK, 0, NULL, 0);
        }
        break;
    }
    case F_PING:
        if (!(flags & FLAG_ACK))
            h2_write_frame(c, F_PING, FLAG_ACK, 0, payload, plen);
        break;
    case F_WINDOW_UPDATE: {
        if (plen >= 4) {
            uint32_t inc = ((uint32_t)payload[0] << 24) | ((uint32_t)payload[1] << 16) |
                           ((uint32_t)payload[2] << 8) | payload[3];
            if (sid == 0) c->conn_send_window += (int32_t)inc;
            else if (sid == stream_id) c->stream_send_window += (int32_t)inc;
        }
        break;
    }
    case F_PRIORITY:
        break;
    case F_GOAWAY:
        fprintf(stderr, "diag: GOAWAY\n");
        return -2;
    case F_RST:
        if (sid == stream_id) {
            fprintf(stderr, "diag: RST_STREAM sid=%d\n", sid);
            return -3;
        }
        break;
    case F_HEADERS: {
        hpack_dec_clear(&c->dec);
        if (hpack_decode(&c->dec, payload, plen) != 0) {
            fprintf(stderr, "diag: hpack decode failed (%zu bytes)\n", plen);
            return -4;
        }
        if (sid == stream_id) {
            const char *status = find_hdr(c, ":status");
            if (getenv("KOPIA_DEBUG"))
                fprintf(stderr, "diag: HEADERS sid=%d status=%s count=%d\n", sid, status ? status : "?", c->dec.count);
            if (status && strcmp(status, "200") != 0) return -5;
            const char *gs = find_hdr(c, "grpc-status");
            if (gs) {
                c->grpc_status = strtol(gs, NULL, 10);
                c->trailers_seen = 1;
            }
            const char *gm = find_hdr(c, "grpc-message");
            if (gm && c->grpc_status != 0) {
                snprintf(c->grpc_msg, sizeof(c->grpc_msg), "%s", gm);
            }
        }
        if (flags & FLAG_END_STREAM && sid == stream_id) {
            c->trailers_seen = 1;
            return 0;
        }
        break;
    }
    case F_DATA:
        if (sid == stream_id) {
            append_data(c, payload, plen);
            if (plen) send_window_update(c, 0, plen); /* replenish conn window */
            if (flags & FLAG_END_STREAM) { c->trailers_seen = 1; }
            *got_data = 1;
        }
        break;
    default:
        break;
    }

    return 0;
}

int h2_pump(h2_conn_t *c, int stream_id) {
    for (;;) {
        int got_data = 0;
        int rc = h2_read_frame(c, stream_id, &got_data);
        if (rc != 0) return rc;
        if (got_data || c->trailers_seen) return 0;
    }
}

/* ---- gRPC message framing ---- */

int grpc_wrap_message(const unsigned char *msg, size_t len, unsigned char **out, size_t *out_len) {
    *out_len = len + 5;
    *out = malloc(*out_len);
    (*out)[0] = 0; /* uncompressed */
    (*out)[1] = (unsigned char)(len >> 24);
    (*out)[2] = (unsigned char)(len >> 16);
    (*out)[3] = (unsigned char)(len >> 8);
    (*out)[4] = (unsigned char)len;
    memcpy(*out + 5, msg, len);
    return 0;
}

int grpc_next_message(h2_conn_t *c, int stream_id, unsigned char **msg, size_t *msg_len) {
    for (;;) {
        if (c->grpc_status > 0) return -6;
        if (c->data_len >= 5) {
            size_t mlen = ((size_t)c->data_buf[1] << 24) | ((size_t)c->data_buf[2] << 16) |
                          ((size_t)c->data_buf[3] << 8) | (size_t)c->data_buf[4];
            if (c->data_len >= 5 + mlen) {
                *msg = malloc(mlen ? mlen : 1);
                memcpy(*msg, c->data_buf + 5, mlen);
                *msg_len = mlen;
                memmove(c->data_buf, c->data_buf + 5 + mlen, c->data_len - 5 - mlen);
                c->data_len -= 5 + mlen;
                return 0;
            }
        }
        if (c->trailers_seen && c->data_len < 5) return -7; /* stream done, no message */
        c->data_len = 0;
        if (h2_pump(c, stream_id) != 0) return -8;
    }
}
