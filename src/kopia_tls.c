/* kopia_tls.c — mbedTLS transport with ALPN h2 + certificate pinning. */

#include "kopia_internal.h"

#include <mbedtls/net_sockets.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <stdio.h>
#include <string.h>

/* RNG from /dev/urandom — works on Leopard (no entropy collector needed). */
static FILE *urandom_f;

static int ktls_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    if (!urandom_f) urandom_f = fopen("/dev/urandom", "rb");
    if (!urandom_f) return -1;
    return fread(out, 1, len, urandom_f) == len ? 0 : -1;
}

int ktls_connect(ktls_t *t, const char *host, const char *port,
                 const unsigned char *fingerprint, char *err, size_t err_len) {
    mbedtls_net_context *fd = calloc(1, sizeof(*fd));
    mbedtls_ssl_context *ssl = calloc(1, sizeof(*ssl));
    mbedtls_ssl_config  *conf = calloc(1, sizeof(*conf));

    t->net_ctx = fd;
    t->ssl_ctx = ssl;
    t->conf_ctx = conf;

    int ret = 0;

#define KT_FAIL(msg) do { if (err) snprintf(err, err_len, "%s: -0x%04x", msg, (unsigned)-ret); return -1; } while (0)

    ret = mbedtls_net_connect(fd, host, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) KT_FAIL("tcp connect");

    ret = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) KT_FAIL("ssl defaults");

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
#else
    mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); /* TLS 1.2 */
#endif
    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE); /* pinning below */
    mbedtls_ssl_conf_rng(conf, ktls_rng, NULL);

    const char *alpn[] = { "h2", NULL };
    ret = mbedtls_ssl_conf_alpn_protocols(conf, alpn);
    if (ret != 0) KT_FAIL("alpn");

    ret = mbedtls_ssl_setup(ssl, conf);
    if (ret != 0) KT_FAIL("ssl setup");

    ret = mbedtls_ssl_set_hostname(ssl, host);
    if (ret != 0) KT_FAIL("sni");

    mbedtls_ssl_set_bio(ssl, fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            KT_FAIL("handshake");
        }
    }

    if (mbedtls_ssl_get_alpn_protocol(ssl) == NULL ||
        strcmp(mbedtls_ssl_get_alpn_protocol(ssl), "h2") != 0) {
        if (err) snprintf(err, err_len, "server did not negotiate h2");
        return -1;
    }

    const mbedtls_x509_crt *crt = mbedtls_ssl_get_peer_cert(ssl);
    if (!crt) { if (err) snprintf(err, err_len, "no peer cert"); return -1; }

    unsigned char sha[32];
    mbedtls_sha256(crt->raw.p, crt->raw.len, sha, 0);

    if (fingerprint && memcmp(sha, fingerprint, 32) != 0) {
        if (err) {
            snprintf(err, err_len, "cert fingerprint mismatch (got "
                     "%02x:%02x:%02x:%02x:...)", sha[0], sha[1], sha[2], sha[3]);
        }
        return -1;
    }

    return 0;
#undef KT_FAIL
}

int ktls_read(ktls_t *t, unsigned char *buf, int len) {
    mbedtls_ssl_context *ssl = t->ssl_ctx;
    int ret;
    do {
        ret = mbedtls_ssl_read(ssl, buf, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    return ret;
}

int ktls_write(ktls_t *t, const unsigned char *buf, int len) {
    mbedtls_ssl_context *ssl = t->ssl_ctx;
    int total = 0;
    while (total < len) {
        int ret = mbedtls_ssl_write(ssl, buf + total, len - total);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (ret <= 0) return total > 0 ? total : ret;
        total += ret;
    }
    return total;
}

void ktls_close(ktls_t *t) {
    mbedtls_ssl_context *ssl = t->ssl_ctx;
    mbedtls_ssl_config  *conf = t->conf_ctx;
    mbedtls_net_context *fd = t->net_ctx;
    if (ssl) { mbedtls_ssl_close_notify(ssl); mbedtls_ssl_free(ssl); free(ssl); }
    if (conf) { mbedtls_ssl_config_free(conf); free(conf); }
    if (fd) { mbedtls_net_free(fd); free(fd); }
    memset(t, 0, sizeof(*t));
}
