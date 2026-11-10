/* kopia_session.c — kopia gRPC Session RPC: init, write_content, flush, put_manifest.
 * Wire spec: docs/kopia-protocol.md
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kopia_internal.h"

#define GRPC_PATH "/kopia_repository.KopiaRepository/Session"

/* SessionRequest message field numbers (repository_server.proto) */
#define PB_REQ_ID 1
#define PB_REQ_INITIALIZE 10
#define PB_REQ_WRITE_CONTENT 13
#define PB_REQ_FLUSH 12
#define PB_REQ_PUT_MANIFEST 16

/* InitializeSessionRequest */
#define PB_INIT_PURPOSE 1
#define PB_INIT_READ_ONLY 2

/* WriteContentRequest */
#define PB_WC_PREFIX 1
#define PB_WC_DATA 2
#define PB_WC_COMPRESSION 3

/* SessionResponse */
#define PB_RESP_ID 1
#define PB_RESP_ERROR 2
#define PB_RESP_INIT 10
#define PB_RESP_FLUSH 12
#define PB_RESP_WRITE 13
#define PB_RESP_PUT_MANIFEST 16

/* RepositoryParameters */
#define PB_PARAM_HASH 1
#define PB_PARAM_HMAC_SECRET 2
#define PB_PARAM_SPLITTER 3
#define PB_PARAM_COMPRESSION 4

/* WriteContentResponse */
#define PB_WCR_CONTENT_ID 1

/* PutManifestRequest/Response */
#define PB_PM_JSON 1
#define PB_PM_LABELS 2
#define PB_PM_ID 1

/* ErrorResponse */
#define PB_ERR_CODE 1
#define PB_ERR_MESSAGE 2

static int ksess_rpc(kopia_session_t *s, const unsigned char *req, size_t req_len,
                     unsigned char **resp, size_t *resp_len) {
    (void)resp; (void)resp_len; /* response read via ksess_read_response */
    unsigned char *wrapped;
    size_t wrapped_len;
    grpc_wrap_message(req, req_len, &wrapped, &wrapped_len);
    int rc = h2_send_data(&s->h2, s->stream_id, wrapped, wrapped_len);
    free(wrapped);
    if (rc != 0) {
        fprintf(stderr, "diag: send_data rc=%d\n", rc);
    }
    return rc;
}

static int parse_response_header(const unsigned char *msg, size_t len,
                                 uint64_t *request_id) {
    pb_field_t f[16];
    int n = pb_parse(msg, len, f, 16);
    *request_id = 0;
    for (int i = 0; i < n; i++) {
        if (f[i].field == PB_RESP_ID && f[i].wire == 0) *request_id = f[i].vint;
    }
    return 0;
}

static const pb_field_t *find_field(pb_field_t *f, int n, int field) {
    for (int i = 0; i < n; i++) {
        if (f[i].field == field) return &f[i];
    }
    return NULL;
}

int ksess_connect(kopia_session_t *s, const kopia_config_t *cfg, char *err, size_t err_len) {
    memset(s, 0, sizeof(*s));
    s->cfg = *cfg;

    char host[256] = "", port[16] = "51515";
    const char *url = cfg->server_url;
    if (strncmp(url, "https://", 8) == 0) url += 8;
    else if (strncmp(url, "http://", 7) == 0) url += 7;
    /* strip path, split host:port */
    {
        char tmp[512];
        snprintf(tmp, sizeof(tmp), "%s", url);
        char *slash = strchr(tmp, '/');
        if (slash) *slash = '\0';
        char *colon = strrchr(tmp, ':');
        if (colon) { *colon = '\0'; snprintf(port, sizeof(port), "%s", colon + 1); }
        snprintf(host, sizeof(host), "%s", tmp);
    }

    /* parse pinned fingerprint (colon-separated hex) */
    unsigned char pin[32];
    int have_pin = 0;
    if (cfg->fingerprint[0]) {
        const char *p = cfg->fingerprint;
        int bi = 0;
        while (*p && bi < 32) {
            if (*p == ':') { p++; continue; }
            int hi = *p++, lo = 0;
            if (*p) lo = *p++; else break;
            int hv = (hi >= '0' && hi <= '9') ? hi - '0' : (hi | 32) - 'a' + 10;
            int lv = (lo >= '0' && lo <= '9') ? lo - '0' : (lo | 32) - 'a' + 10;
            if (hv < 0 || hv > 15 || lv < 0 || lv > 15) break;
            pin[bi++] = (unsigned char)((hv << 4) | lv);
        }
        have_pin = (bi == 32);
        if (!have_pin && err) snprintf(err, err_len, "invalid fingerprint");
    }

    if (h2_connect(&s->h2, host, port, have_pin ? pin : NULL, err, err_len) != 0) return -1;
    (void)cfg->insecure;

    /* send gRPC headers on stream 1; keep stream open */
    s->stream_id = 1;
    const char *names[8] = { "content-type", "te", "user-agent",
                             "kopia-username", "kopia-hostname", "kopia-password" };
    const char *vals[8] = { "application/grpc", "trailers", "kopia-darwin-ppc/0.1",
                            cfg->repo_user, cfg->repo_hostname, cfg->repo_password };
    /* repo_user holds "user" part, repo_hostname the host part */
    if (h2_send_headers(&s->h2, GRPC_PATH, host, names, vals, 6) != 0) {
        snprintf(err, err_len, "failed to send headers");
        return -1;
    }

    /* InitializeSessionRequest { purpose: "kopia-darwin-ppc", read_only: false (default) } */
    unsigned char init[256], *resp = NULL;
    size_t ilen = 0, resp_len = 0;
    {
        unsigned char tmp[256];
        size_t tlen = 0;
        pb_write_string(tmp, &tlen, PB_INIT_PURPOSE, "kopia-darwin-ppc", 16);
        pb_write_msg(init, &ilen, PB_REQ_INITIALIZE, tmp, tlen);
    }
    {
        unsigned char req[512];
        size_t rlen = 0;
        pb_write_tag(req, &rlen, PB_REQ_ID, 0);
        pb_write_varint(req, &rlen, 1); /* request_id starts at 1 */
        memcpy(req + rlen, init, ilen);
        rlen += ilen;
        unsigned char *wrapped;
        size_t wrapped_len;
        grpc_wrap_message(req, rlen, &wrapped, &wrapped_len);
        int src = h2_send_data(&s->h2, s->stream_id, wrapped, wrapped_len);
        free(wrapped);
        if (src != 0) {
            snprintf(err, err_len, "initialize send failed");
            return -1;
        }
    }

    uint64_t rid = 0;
    if (ksess_read_response(s, 1, &resp, &resp_len) != 0) {
        snprintf(err, err_len, "initialize rpc failed");
        return -1;
    }
    parse_response_header(resp, resp_len, &rid);
    pb_field_t f[16];
    int n = pb_parse(resp, resp_len, f, 16);
    const pb_field_t *e = find_field(f, n, PB_RESP_ERROR);
    if (e) {
        snprintf(err, err_len, "server error in initialize");
        free(resp);
        return -1;
    }
    const pb_field_t *initresp = find_field(f, n, PB_RESP_INIT);
    if (!initresp) {
        snprintf(err, err_len, "no initialize response");
        free(resp);
        return -1;
    }
    pb_field_t pf[8];
    int pn = pb_parse(initresp->ptr, initresp->len, pf, 8);
    const pb_field_t *params = find_field(pf, pn, 1); /* InitializeSessionResponse.parameters */
    if (!params || params->wire != 2) {
        snprintf(err, err_len, "no repository parameters");
        free(resp);
        return -1;
    }
    pb_field_t pp[8];
    int ppn = pb_parse(params->ptr, params->len, pp, 8);
    for (int i = 0; i < ppn; i++) {
        if (pp[i].field == PB_PARAM_HASH && pp[i].wire == 2)
            snprintf(s->hash_function, sizeof(s->hash_function), "%.*s", (int)pp[i].len, pp[i].ptr);
        if (pp[i].field == PB_PARAM_SPLITTER && pp[i].wire == 2)
            snprintf(s->splitter_name, sizeof(s->splitter_name), "%.*s", (int)pp[i].len, pp[i].ptr);
        if (pp[i].field == PB_PARAM_COMPRESSION && pp[i].wire == 0)
            s->supports_compression = (int)pp[i].vint;
    }
    s->next_request_id = 2;
    s->established = 1;
    free(resp);
    return 0;
}

void ksess_close(kopia_session_t *s) {
    h2_close(&s->h2);
    for (int i = 0; i < s->npending; i++) free(s->pending[i].msg);
    s->npending = 0;
    s->established = 0;
}

int ksess_read_response(kopia_session_t *s, uint64_t request_id,
                        unsigned char **resp, size_t *resp_len) {
    int trace = getenv("KOPIA_TRACE") != NULL;
    /* stash hit? */
    for (int i = 0; i < s->npending; i++) {
        if (s->pending[i].id == request_id) {
            if (trace) fprintf(stderr, "trace: stash hit id=%llu (want %llu)\n",
                               (unsigned long long)s->pending[i].id, (unsigned long long)request_id);
            *resp = s->pending[i].msg;
            *resp_len = s->pending[i].len;
            free(s->pending[i].msg);
            s->pending[i] = s->pending[s->npending - 1];
            s->npending--;
            return 0;
        }
    }

    for (;;) {
        unsigned char *msg = NULL;
        size_t msg_len = 0;
        int rc = grpc_next_message(&s->h2, s->stream_id, &msg, &msg_len);
        if (rc != 0) {
            fprintf(stderr, "diag: next_message rc=%d status=%ld msg=%s\n",
                    rc, s->h2.grpc_status, s->h2.grpc_msg);
            return -1;
        }

        uint64_t rid = 0;
        parse_response_header(msg, msg_len, &rid);
        if (trace) fprintf(stderr, "trace: got resp id=%llu (want %llu) len=%zu\n",
                           (unsigned long long)rid, (unsigned long long)request_id, msg_len);
        if (rid == request_id) {
            *resp = msg;
            *resp_len = msg_len;
            return 0;
        }

        /* out of order — stash */
        if (s->npending >= 64) {
            fprintf(stderr, "diag: response stash overflow\n");
            free(msg);
            return -2;
        }
        if (trace) fprintf(stderr, "trace: stash id=%llu\n", (unsigned long long)rid);
        s->pending[s->npending].id = rid;
        s->pending[s->npending].msg = msg;
        s->pending[s->npending].len = msg_len;
        s->npending++;
    }
}

static int next_request(kopia_session_t *s, uint64_t *request_id,
                        unsigned char *body, size_t body_len,
                        unsigned char **resp, size_t *resp_len) {
    unsigned char req[64];
    size_t rlen = 0;
    *request_id = s->next_request_id++;
    pb_write_tag(req, &rlen, PB_REQ_ID, 0);
    pb_write_varint(req, &rlen, *request_id);
    memcpy(req + rlen, body, body_len);
    rlen += body_len;

    unsigned char *wrapped;
    size_t wrapped_len;
    grpc_wrap_message(req, rlen, &wrapped, &wrapped_len);
    int rc = h2_send_data(&s->h2, s->stream_id, wrapped, wrapped_len);
    free(wrapped);
    if (rc != 0) return -1;
    return ksess_read_response(s, *request_id, resp, resp_len);
}

int ksess_write_content(kopia_session_t *s, const char *prefix,
                        const unsigned char *data, size_t len,
                        char *content_id, size_t cid_len) {
    if (!s->established) return -1;
    unsigned char *resp = NULL;
    size_t resp_len = 0;
    uint64_t my_id = s->next_request_id++;

    /* build: request wrapper { request_id, write_content { prefix, data } } */
    unsigned char *req = malloc(len + 256);
    size_t rlen = 0;
    pb_write_tag(req, &rlen, PB_REQ_ID, 0);
    pb_write_varint(req, &rlen, my_id);
    unsigned char *sub = malloc(len + 64);
    size_t slen = 0;
    if (prefix && *prefix) pb_write_string(sub, &slen, PB_WC_PREFIX, prefix, strlen(prefix));
    pb_write_string(sub, &slen, PB_WC_DATA, data, len);
    pb_write_msg(req, &rlen, PB_REQ_WRITE_CONTENT, sub, slen);
    free(sub);

    unsigned char *wrapped;
    size_t wrapped_len;
    grpc_wrap_message(req, rlen, &wrapped, &wrapped_len);
    if (getenv("KOPIA_TRACE"))
        fprintf(stderr, "trace: sent WC id=%llu prefix=%s size=%zu\n",
                (unsigned long long)my_id, prefix ? prefix : "", len);
    int rc = h2_send_data(&s->h2, s->stream_id, wrapped, wrapped_len);
    free(wrapped);
    free(req);
    if (rc != 0) {
        fprintf(stderr, "diag: write_content send rc=%d\n", rc);
        return -1;
    }

    rc = ksess_read_response(s, my_id, &resp, &resp_len);
    if (rc != 0) return -2;

    uint64_t rid = 0;
    parse_response_header(resp, resp_len, &rid);
    pb_field_t f[16];
    int n = pb_parse(resp, resp_len, f, 16);
    const pb_field_t *e = find_field(f, n, PB_RESP_ERROR);
    if (e) {
        if (e->len) fprintf(stderr, "diag: write_content server error: %.*s\n", (int)e->len, e->ptr);
        free(resp);
        return -3;
    }
    const pb_field_t *wc = find_field(f, n, PB_RESP_WRITE);
    if (!wc) {
        fprintf(stderr, "diag: write_content no response field\n");
        free(resp);
        return -4;
    }
    pb_field_t pf[8];
    int pn = pb_parse(wc->ptr, wc->len, pf, 8);
    for (int i = 0; i < pn; i++) {
        if (pf[i].field == PB_WCR_CONTENT_ID && pf[i].wire == 2) {
            size_t cl = pf[i].len < cid_len - 1 ? pf[i].len : cid_len - 1;
            memcpy(content_id, pf[i].ptr, cl);
            content_id[cl] = '\0';
        }
    }
    free(resp);
    return 0;
}

int ksess_flush(kopia_session_t *s) {
    if (!s->established) return -1;
    unsigned char body[16], *resp = NULL;
    size_t blen = 0, resp_len = 0;
    uint64_t rid = 0;
    pb_write_tag(body, &blen, PB_REQ_FLUSH, 2);
    pb_write_varint(body, &blen, 0);

    if (next_request(s, &rid, body, blen, &resp, &resp_len) != 0) return -1;
    pb_field_t f[16];
    int n = pb_parse(resp, resp_len, f, 16);
    free(resp);
    if (find_field(f, n, PB_RESP_ERROR)) return -2;
    return 0;
}

int ksess_put_manifest(kopia_session_t *s, const char *json,
                       const char **labels, int nlabels,
                       char *manifest_id, size_t id_len) {
    if (!s->established) return -1;
    unsigned char *resp = NULL;
    size_t resp_len = 0;

    /* PutManifestRequest { json_data: 1, labels: 2 (map<string,string>) } */
    unsigned char *body = malloc(strlen(json) + 1024);
    size_t blen = 0;
    pb_write_string(body, &blen, PB_PM_JSON, json, strlen(json));
    for (int i = 0; i + 1 < nlabels; i += 2) {
        const char *k = labels[i], *v = labels[i + 1];
        unsigned char ent[1024];
        size_t elen = 0;
        pb_write_string(ent, &elen, 1, k, strlen(k));
        pb_write_string(ent, &elen, 2, v, strlen(v));
        pb_write_msg(body, &blen, PB_PM_LABELS, ent, elen);
    }

    unsigned char *req = malloc(blen + 32);
    size_t rlen = 0;
    uint64_t my_id = s->next_request_id++;
    pb_write_tag(req, &rlen, PB_REQ_ID, 0);
    pb_write_varint(req, &rlen, my_id);
    pb_write_msg(req, &rlen, PB_REQ_PUT_MANIFEST, body, blen);
    free(body);

    unsigned char *wrapped;
    size_t wrapped_len;
    grpc_wrap_message(req, rlen, &wrapped, &wrapped_len);
    int rc = h2_send_data(&s->h2, s->stream_id, wrapped, wrapped_len);
    free(wrapped);
    free(req);
    if (rc != 0) return -1;

    rc = ksess_read_response(s, my_id, &resp, &resp_len);
    if (rc != 0) return -2;

    pb_field_t f[16];
    int n = pb_parse(resp, resp_len, f, 16);
    const pb_field_t *e = find_field(f, n, PB_RESP_ERROR);
    if (e) {
        if (e->len) fprintf(stderr, "diag: server error: %.*s\n", (int)e->len, e->ptr);
        free(resp);
        return -3;
    }
    const pb_field_t *pm = find_field(f, n, PB_RESP_PUT_MANIFEST);
    if (!pm) { free(resp); return -4; }
    pb_field_t pf[8];
    int pn = pb_parse(pm->ptr, pm->len, pf, 8);
    for (int i = 0; i < pn; i++) {
        if (pf[i].field == PB_PM_ID && pf[i].wire == 2) {
            size_t cl = pf[i].len < id_len - 1 ? pf[i].len : id_len - 1;
            memcpy(manifest_id, pf[i].ptr, cl);
            manifest_id[cl] = '\0';
        }
    }
    free(resp);
    return 0;
}
