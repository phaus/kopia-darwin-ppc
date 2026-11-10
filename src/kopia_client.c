/* kopia_client.c — kopia API-server client (thin).
 *
 * Implementation contract: docs/kopia-protocol.md
 * Transport/auth/object/snapshot details land here once the spec extraction
 * (running against kopia v0.23.1 source) is merged. Stubs return errors so
 * the build stays green meanwhile.
 */

#include "kopia.h"

#include <stdio.h>
#include <string.h>

int kopia_connect(kopia_config_t *cfg) {
    (void)cfg;
    fprintf(stderr, "kopia: connect not implemented yet (spec pending)\n");
    return -1;
}

void kopia_disconnect(void) {}

int kopia_upload_file(const char *path, char *object_id, size_t object_id_len) {
    (void)path; (void)object_id; (void)object_id_len;
    return -1;
}

int kopia_create_snapshot(const char *source_path, const char *root_object_id,
                          char *snapshot_id, size_t snapshot_id_len) {
    (void)source_path; (void)root_object_id; (void)snapshot_id; (void)snapshot_id_len;
    return -1;
}

int kopia_flush(void) { return -1; }
