/* kopia_sha256.c — SHA-256 + HMAC-SHA256 (public-domain style, no deps).
 *
 * Needed for: verify pass on CAS objects; possibly for API auth token
 * computation depending on the spec. Full implementation pending spec
 * merge; currently a stub.
 */

#include "kopia_sha256.h"

void sha256(const unsigned char *data, size_t len, unsigned char out[32]) {
    (void)data; (void)len; (void)out;
    /* stub */
}

void hmac_sha256(const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t len,
                 unsigned char out[32]) {
    (void)key; (void)key_len; (void)data; (void)len; (void)out;
    /* stub */
}
