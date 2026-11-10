/* kopia_splitter.c — buzhash rolling-hash chunk splitter.
 *
 * Must match kopia's object/splitter buzhash parameters exactly so chunk
 * boundaries line up with standard kopia clients (dedup across writers).
 * Parameters + 64-bit table land here from the spec (docs/kopia-protocol.md).
 */

#include <stddef.h>
#include <stdint.h>

#define KOPIA_BUZHASH_TABLE_SIZE 256
#define KOPIA_WINDOW_SIZE        64

/* Placeholder: table values are copied from kopia object/splitter source. */
static const uint32_t buzhash_table[KOPIA_BUZHASH_TABLE_SIZE] = {0};

typedef struct {
    uint32_t h;
    size_t   count;
} buzhash_t;

/* Returns non-zero when a chunk boundary is hit. */
int buzhash_should_split(buzhash_t *bh, unsigned char byte) {
    (void)byte;
    (void)bh;
    return 0; /* stub */
}
