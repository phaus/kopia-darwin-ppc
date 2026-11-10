#ifndef KOPIA_H
#define KOPIA_H

/*
 * Kopia API-server client (thin client).
 *
 * Design: the kopia server performs content encryption, index packing and
 * compaction. This client only does: HTTP transport, buzhash chunking,
 * object/manifest JSON assembly. Spec: docs/kopia-protocol.md
 */

#include <stddef.h>
#include <stdint.h>

/* Connection settings */
typedef struct {
    char server_url[512];      /* e.g. https://kopia.example.com:51515 */
    char server_user[256];     /* control-level user (server-username) */
    char server_password[256];
    char repo_user[256];       /* repository user: bare name ("test") */
    char repo_hostname[256];   /* repository user: hostname part ("test") */
    char repo_password[256];
    char fingerprint[128];     /* server cert sha256 hex, colon-separated; "" = no pin */
    int  insecure;             /* 1 = skip cert pinning (still TLS) */
} kopia_config_t;

/* Initialize connection; returns 0 on success. */
int kopia_connect(kopia_config_t *cfg);

/* Disconnect / cleanup session. */
void kopia_disconnect(void);

/* Write a file at 'path' into the repository; fills object_id (kopia ID string). */
int kopia_upload_file(const char *path, char *object_id, size_t object_id_len);

/* Create a snapshot manifest for 'source_path' with root object 'root_object_id'. */
int kopia_create_snapshot(const char *source_path, const char *root_object_id,
                          char *snapshot_id, size_t snapshot_id_len);

/* Flush pending server-side writes. */
int kopia_flush(void);

#endif /* KOPIA_H */
