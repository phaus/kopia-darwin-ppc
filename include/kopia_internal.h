#ifndef KOPIA_INTERNAL_H
#define KOPIA_INTERNAL_H

/*
 * Internal interfaces for the kopia thin client.
 * Layers: ktls (mbedTLS+ALPN h2) -> h2 (HTTP/2 framing+HPACK) -> grpc session
 * Spec notes: docs/kopia-protocol.md
 */

#include <stddef.h>
#include <stdint.h>

#include "kopia.h"

/* ---- transport (kopia_tls.c, mbedTLS) ---- */
typedef struct {
    void *ssl_ctx;   /* mbedtls_ssl_context* */
    void *conf_ctx;  /* mbedtls_ssl_config* */
    void *net_ctx;   /* mbedtls_net_context* */
} ktls_t;

/* Connect + TLS handshake with ALPN h2; pins server cert sha256 (32 bytes) if non-NULL. */
int ktls_connect(ktls_t *t, const char *host, const char *port,
                 const unsigned char *fingerprint, char *err, size_t err_len);
int ktls_read(ktls_t *t, unsigned char *buf, int len);
int ktls_write(ktls_t *t, const unsigned char *buf, int len);
void ktls_close(ktls_t *t);

/* ---- HPACK (kopia_hpack.c) ---- */
#define HPACK_MAX_HEADERS 64

typedef struct {
    char *name;
    char *value;
} hpack_hdr_t;

typedef struct {
    hpack_hdr_t hdrs[HPACK_MAX_HEADERS];
    int         count;
    /* dynamic table */
    struct {
        char *name;
        char *value;
        size_t size;
    } dyn[128];
    int    dyn_count;
    size_t dyn_size;
    size_t dyn_max; /* settings HEADER_TABLE_SIZE */
} hpack_dec_t;

void hpack_dec_init(hpack_dec_t *d);
void hpack_dec_free(hpack_dec_t *d);
int  hpack_decode(hpack_dec_t *d, const unsigned char *buf, size_t len);
void hpack_dec_clear(hpack_dec_t *d); /* clear per-transaction list, keep dyn table */

/* Encode header list as literal-without-indexing (no huffman). Returns malloc'd block. */
int hpack_encode(const char **names, const char **values, int n,
                 unsigned char **out, size_t *out_len);

/* ---- HTTP/2 (kopia_h2.c) ---- */
typedef struct {
    ktls_t      tls;
    hpack_dec_t dec;
    unsigned char rbuf[1 << 16];
    size_t rlen, rpos;
    int      next_stream_id;
    int      handshake_done;

    /* peer-admitted limits */
    uint32_t peer_max_frame;        /* SETTINGS_MAX_FRAME_SIZE */
    int32_t  conn_send_window;      /* connection-level send window */
    int32_t  stream_send_window;    /* per-stream send window (SETTINGS_INITIAL_WINDOW_SIZE) */

    /* current transaction assembly */
    unsigned char *data_buf;
    size_t         data_len, data_cap;
    int            trailers_seen;
    long           grpc_status;      /* -1 = none yet */
    char           grpc_msg[512];
} h2_conn_t;

int h2_connect(h2_conn_t *c, const char *host, const char *port,
               const unsigned char *fingerprint, char *err, size_t err_len);
void h2_close(h2_conn_t *c);

/* Send request headers on a new stream; returns stream id. */
int h2_send_headers(h2_conn_t *c, const char *path, const char *authority,
                    const char **names, const char **values, int n);

/* Send buf as DATA frames (respects peer max frame + flow control). */
int h2_send_data(h2_conn_t *c, int stream_id, const unsigned char *buf, size_t len);

/* Send END_STREAM (empty DATA). */
int h2_send_eof(h2_conn_t *c, int stream_id);

/* Read one frame; *got_data set when DATA for stream appended. Returns 0 ok, <0 error. */
int h2_read_frame(h2_conn_t *c, int stream_id, int *got_data);

/* Read frames until DATA payload for stream arrives (appended to c->data_buf)
 * or trailers seen. Returns 0 ok, <0 error. */
int h2_pump(h2_conn_t *c, int stream_id);

/* ---- protobuf (kopia_pb.c) ---- */
void pb_write_varint(unsigned char *buf, size_t *len, uint64_t v);
void pb_write_tag(unsigned char *buf, size_t *len, int field, int wire);
void pb_write_string(unsigned char *buf, size_t *len, int field, const void *data, size_t n);
void pb_write_msg(unsigned char *buf, size_t *len, int field, const unsigned char *msg, size_t n);

typedef struct {
    int      field;
    int      wire;   /* 0 varint, 2 len-delimited */
    uint64_t vint;
    const unsigned char *ptr;
    size_t   len;
} pb_field_t;

/* Iterate fields in buf; returns number of fields parsed; stops at first unknown wire type error. */
int pb_parse(const unsigned char *buf, size_t len, pb_field_t *out, int max);

/* ---- gRPC framing ---- */
int grpc_wrap_message(const unsigned char *msg, size_t len, unsigned char **out, size_t *out_len);
int grpc_next_message(h2_conn_t *c, int stream_id, unsigned char **msg, size_t *msg_len);

/* ---- session (kopia_session.c) ---- */
typedef struct {
    kopia_config_t cfg;
    h2_conn_t      h2;
    int            stream_id;
    uint64_t       next_request_id;
    int            established;
    char           hash_function[64];
    char           splitter_name[64];
    int            supports_compression;
} kopia_session_t;

int ksess_connect(kopia_session_t *s, const kopia_config_t *cfg, char *err, size_t err_len);
void ksess_close(kopia_session_t *s);
int ksess_write_content(kopia_session_t *s, const char *prefix,
                        const unsigned char *data, size_t len,
                        char *content_id, size_t cid_len);
int ksess_flush(kopia_session_t *s);
int ksess_put_manifest(kopia_session_t *s, const char *json,
                       const char **labels, int nlabels, /* key0,val0,key1,val1... */
                       char *manifest_id, size_t id_len);

/* ---- upload (kopia_upload.c) ---- */
int kup_upload_path(kopia_session_t *s, const char *path,
                    char *object_id, size_t oid_len);
int kup_snapshot(kopia_session_t *s, const char *source_path,
                 const char *root_object_id,
                 char *manifest_id, size_t id_len);

#endif /* KOPIA_INTERNAL_H */
