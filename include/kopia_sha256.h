#ifndef KOPIA_SHA256_H
#define KOPIA_SHA256_H

#include <stddef.h>

void sha256(const unsigned char *data, size_t len, unsigned char out[32]);

void hmac_sha256(const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t len,
                 unsigned char out[32]);

#endif /* KOPIA_SHA256_H */
