#ifndef BACKUP_H
#define BACKUP_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Repository configuration
typedef struct {
    char repo_path[1024];
    char manifest_path[1024];
    int compress_level;
    int use_encryption;
    char password[256];
} backup_config_t;

// File entry in manifest
typedef struct {
    char path[1024];
    char sha256[65];           // hex encoded
    uint64_t size;
    uint64_t mtime;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    int is_compressed;
    int is_encrypted;
} file_entry_t;

// Manifest header
typedef struct {
    uint32_t magic;            // "PBKP"
    uint32_t version;
    uint64_t timestamp;
    uint64_t entry_count;
    char prev_manifest_sha256[65];
} manifest_header_t;

// Initialize backup configuration
int backup_config_init(backup_config_t *cfg, const char *repo_path);

// Open/create repository
int backup_repo_open(const backup_config_t *cfg);

// Add file to backup (returns 0 on success, -1 on error)
int backup_add_file(const backup_config_t *cfg, const char *src_path, const char *rel_path);

// Create snapshot/manifest
int backup_create_snapshot(const backup_config_t *cfg, const char *snapshot_name);

// List snapshots
int backup_list_snapshots(const backup_config_t *cfg);

// Restore file from snapshot
int backup_restore_file(const backup_config_t *cfg, const char *snapshot_name, const char *rel_path, const char *dest_path);

// Verify repository integrity
int backup_verify(const backup_config_t *cfg);

// Cleanup
void backup_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // BACKUP_H