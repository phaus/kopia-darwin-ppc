#include "backup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <zlib.h>

// Simple SHA-256 implementation (public domain / minimal)
typedef struct {
    uint32_t h[8];
    uint32_t len[2];
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx_t;

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
    0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
    0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x27b70a85, 0x2e1b2138,
    0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

static void sha256_transform(uint32_t *state, const uint8_t *block) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = (block[i*4] << 24) | (block[i*4+1] << 16) | (block[i*4+2] << 8) | block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16];
    }
    uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a,
             e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = Sigma0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_init(uint32_t *state) {
    state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
    state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
}

static void sha256_update(uint32_t *state, uint8_t *buf, size_t *buflen, uint32_t *len, const uint8_t *data, size_t dlen) {
    while (dlen > 0) {
        size_t n = 64 - *buflen;
        if (dlen < n) n = dlen;
        memcpy(buf + *buflen, data, n);
        *buflen += n;
        data += n;
        dlen -= n;
        len[0] += n * 8;
        if (len[0] < n * 8) len[1]++;
        if (*buflen == 64) {
            sha256_transform(state, buf);
            *buflen = 0;
        }
    }
}

static void sha256_final(uint32_t *state, uint8_t *buf, size_t buflen, uint32_t *len, uint8_t *out) {
    uint8_t padding[64] = {0x80};
    size_t padlen = (buflen < 56) ? 56 - buflen : 120 - buflen;
    sha256_update(state, buf, &buflen, len, padding, padlen);
    for (int i = 7; i >= 0; i--) buf[buflen++] = (len[i/4] >> (8*(i%4))) & 0xFF;
    sha256_transform(state, buf);
    for (int i = 0; i < 8; i++) {
        out[i*4] = (state[i] >> 24) & 0xFF;
        out[i*4+1] = (state[i] >> 16) & 0xFF;
        out[i*4+2] = (state[i] >> 8) & 0xFF;
        out[i*4+3] = state[i] & 0xFF;
    }
}

void sha256_file(const char *path, char *out_hex) {
    uint32_t state[8]; sha256_init(state);
    uint8_t buf[64]; size_t buflen = 0;
    uint32_t len[2] = {0, 0};
    FILE *f = fopen(path, "rb");
    if (!f) { memset(out_hex, 0, 65); return; }
    uint8_t data[4096]; size_t n;
    while ((n = fread(data, 1, sizeof(data), f)) > 0) {
        sha256_update(state, buf, &buflen, len, data, n);
    }
    fclose(f);
    uint8_t hash[32];
    sha256_final(state, buf, buflen, len, hash);
    for (int i = 0; i < 32; i++) sprintf(out_hex + i * 2, "%02x", hash[i]);
    out_hex[64] = 0;
}

void sha256_data(const void *data, size_t dlen, char *out_hex) {
    uint32_t state[8]; sha256_init(state);
    uint8_t buf[64]; size_t buflen = 0;
    uint32_t len[2] = {0, 0};
    sha256_update(state, buf, &buflen, len, data, dlen);
    uint8_t hash[32];
    sha256_final(state, buf, buflen, len, hash);
    for (int i = 0; i < 32; i++) sprintf(out_hex + i * 2, "%02x", hash[i]);
    out_hex[64] = 0;
}

#define MAGIC_PBKP 0x50424B50
#define MANIFEST_VERSION 1
#define CHUNK_SIZE 65536

static backup_config_t g_config;
static int g_repo_open = 0;

static int compress_data(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len) {
    z_stream strm = {0};
    if (deflateInit(&strm, g_config.compress_level) != Z_OK) return -1;
    *out_len = compressBound(in_len);
    *out = malloc(*out_len);
    if (!*out) { deflateEnd(&strm); return -1; }
    strm.next_in = (Bytef*)in; strm.avail_in = in_len;
    strm.next_out = *out; strm.avail_out = *out_len;
    int ret = deflate(&strm, Z_FINISH);
    deflateEnd(&strm);
    if (ret != Z_STREAM_END) { free(*out); return -1; }
    *out_len = strm.total_out; return 0;
}

static int decompress_data(const unsigned char *in, size_t in_len, unsigned char **out, size_t *out_len) {
    z_stream strm = {0};
    if (inflateInit(&strm) != Z_OK) return -1;
    *out = malloc(in_len * 4);
    if (!*out) { inflateEnd(&strm); return -1; }
    strm.next_in = (Bytef*)in; strm.avail_in = in_len;
    strm.next_out = *out; strm.avail_out = in_len * 4;
    int ret = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    if (ret != Z_STREAM_END) { free(*out); return -1; }
    *out_len = strm.total_out; return 0;
}

static int ensure_dir(const char *path) {
    char tmp[1024]; snprintf(tmp, sizeof(tmp), "%s", path);
    for (size_t i = 1; i < strlen(tmp); i++) {
        if (tmp[i] == '/') { tmp[i] = 0; mkdir(tmp, 0755); tmp[i] = '/'; }
    }
    return mkdir(tmp, 0755);
}

static int store_object(const backup_config_t *cfg, const unsigned char *data, size_t len, char *out_sha256) {
    sha256_data(data, len, out_sha256);
    fprintf(stderr, "DEBUG: sha256 = %s\n", out_sha256);
    char obj_path[2048];
    snprintf(obj_path, sizeof(obj_path), "%s/objects/%c%c/%s", cfg->repo_path, out_sha256[0], out_sha256[1], out_sha256 + 2);
    char *slash = strrchr(obj_path, '/');
    if (slash) { *slash = 0; ensure_dir(obj_path); *slash = '/'; }
    FILE *f = fopen(obj_path, "wb");
    if (!f) { fprintf(stderr, "DEBUG: fopen failed: %s\n", strerror(errno)); return -1; }
    fwrite(data, 1, len, f); fclose(f); return 0;
}

static int load_object(const backup_config_t *cfg, const char *sha256, unsigned char **data, size_t *len) {
    char obj_path[2048];
    snprintf(obj_path, sizeof(obj_path), "%s/objects/%c%c/%s", cfg->repo_path, sha256[0], sha256[1], sha256 + 2);
    fprintf(stderr, "DEBUG load_object: obj_path=%s\n", obj_path);
    FILE *f = fopen(obj_path, "rb");
    if (!f) { fprintf(stderr, "DEBUG load_object: fopen failed for %s: %s\n", obj_path, strerror(errno)); return -1; }
    fseek(f, 0, SEEK_END); *len = ftell(f); fseek(f, 0, SEEK_SET);
    *data = malloc(*len); fread(*data, 1, *len, f); fclose(f);
    fprintf(stderr, "DEBUG load_object: fopen succeeded, len=%zu\n", *len);
    return 0;
}

int backup_config_init(backup_config_t *cfg, const char *repo_path) {
    memset(cfg, 0, sizeof(backup_config_t));
    snprintf(cfg->repo_path, sizeof(cfg->repo_path), "%s", repo_path);
    snprintf(cfg->manifest_path, sizeof(cfg->manifest_path), "%s/manifest.idx", repo_path);
    cfg->compress_level = 6; cfg->use_encryption = 0; return 0;
}

int backup_repo_open(const backup_config_t *cfg) {
    if (g_repo_open) return 0;
    ensure_dir(cfg->repo_path);
    char obj_dir[2048]; snprintf(obj_dir, sizeof(obj_dir), "%s/objects", cfg->repo_path);
    ensure_dir(obj_dir);
    for (int i = 0; i < 256; i++) {
        char subdir[2048]; snprintf(subdir, sizeof(subdir), "%s/objects/%02x", cfg->repo_path, i);
        ensure_dir(subdir);
    }
    g_repo_open = 1; memcpy(&g_config, cfg, sizeof(backup_config_t)); return 0;
}

int backup_add_file(const backup_config_t *cfg, const char *src_path, const char *rel_path) {
    struct stat st; if (stat(src_path, &st) != 0) { fprintf(stderr, "DEBUG: stat failed: %s\n", strerror(errno)); return -1; }
    if (!S_ISREG(st.st_mode)) return -1;
    FILE *f = fopen(src_path, "rb"); if (!f) { fprintf(stderr, "DEBUG: fopen src failed: %s\n", strerror(errno)); return -1; }
    fseek(f, 0, SEEK_END); size_t fsize = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *file_data = malloc(fsize); fread(file_data, 1, fsize, f); fclose(f);
    unsigned char *stored_data = file_data; size_t stored_len = fsize; int is_compressed = 0;
    if (g_config.compress_level > 0 && fsize > 1024) {
        unsigned char *comp_data; size_t comp_len;
        if (compress_data(file_data, fsize, &comp_data, &comp_len) == 0 && comp_len < fsize) {
            stored_data = comp_data; stored_len = comp_len; is_compressed = 1;
        } else if (comp_data) free(comp_data);
    }
    char sha256[65];
    int store_ret = store_object(cfg, stored_data, stored_len, sha256);
    fprintf(stderr, "DEBUG backup_add_file: store_object returned %d\n", store_ret);
    if (store_ret != 0) {
        if (stored_data != file_data) free(stored_data); free(file_data); return -1;
    }
    file_entry_t entry = {0};
    snprintf(entry.path, sizeof(entry.path), "%s", rel_path);
    snprintf(entry.sha256, sizeof(entry.sha256), "%s", sha256);
    entry.size = fsize; entry.mtime = st.st_mtime; entry.mode = st.st_mode;
    entry.uid = st.st_uid; entry.gid = st.st_gid;
    entry.is_compressed = is_compressed; entry.is_encrypted = 0;
    FILE *mf = fopen(cfg->manifest_path, "ab");
    if (!mf) { fprintf(stderr, "DEBUG: fopen manifest failed: %s\n", strerror(errno));
        if (stored_data != file_data) free(stored_data); free(file_data); return -1; }
    fwrite(&entry, sizeof(file_entry_t), 1, mf); fclose(mf);
    if (stored_data != file_data) free(stored_data); free(file_data); return 0;
}

int backup_create_snapshot(const backup_config_t *cfg, const char *snapshot_name) {
    FILE *mf = fopen(cfg->manifest_path, "rb"); if (!mf) { fprintf(stderr, "DEBUG: fopen manifest failed for read\n"); return -1; }
    fseek(mf, 0, SEEK_END); long mf_size = ftell(mf); fseek(mf, 0, SEEK_SET);
    unsigned char *mf_data = malloc(mf_size); fread(mf_data, 1, mf_size, mf); fclose(mf);
    char mf_sha256[65]; sha256_data(mf_data, mf_size, mf_sha256); free(mf_data);
    manifest_header_t hdr = {0}; hdr.magic = MAGIC_PBKP; hdr.version = MANIFEST_VERSION;
    hdr.timestamp = time(NULL); hdr.entry_count = mf_size / sizeof(file_entry_t);
    snprintf(hdr.prev_manifest_sha256, sizeof(hdr.prev_manifest_sha256), "%s", mf_sha256);
    char snap_path[2048]; snprintf(snap_path, sizeof(snap_path), "%s/snapshots/%s.manifest", cfg->repo_path, snapshot_name);
    fprintf(stderr, "DEBUG: snap_path=%s\n", snap_path);
    char *slash2 = strrchr(snap_path, '/');
    if (slash2) { *slash2 = 0; ensure_dir(snap_path); *slash2 = '/'; }
    FILE *sf = fopen(snap_path, "wb"); if (!sf) { fprintf(stderr, "DEBUG: fopen snapshot failed: %s\n", strerror(errno)); return -1; }
    fwrite(&hdr, sizeof(manifest_header_t), 1, sf);
    FILE *mf2 = fopen(cfg->manifest_path, "rb");
    if (mf2) { char buf[CHUNK_SIZE]; size_t n; while ((n = fread(buf, 1, CHUNK_SIZE, mf2)) > 0) fwrite(buf, 1, n, sf); fclose(mf2); }
    fclose(sf);
    FILE *mf3 = fopen(cfg->manifest_path, "wb"); if (mf3) fclose(mf3); return 0;
}

int backup_list_snapshots(const backup_config_t *cfg) {
    char snap_dir[2048]; snprintf(snap_dir, sizeof(snap_dir), "%s/snapshots", cfg->repo_path);
    DIR *d = opendir(snap_dir); if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strstr(de->d_name, ".manifest")) {
            char path[2048]; snprintf(path, sizeof(path), "%s/%s", snap_dir, de->d_name);
            FILE *f = fopen(path, "rb"); if (f) {
                manifest_header_t hdr; fread(&hdr, sizeof(hdr), 1, f); fclose(f);
                fprintf(stderr, "%s  entries=%llu  time=%s", de->d_name, (unsigned long long)hdr.entry_count, ctime(&hdr.timestamp));
            }
        }
    } closedir(d); return 0;
}

int backup_restore_file(const backup_config_t *cfg, const char *snapshot_name, const char *rel_path, const char *dest_path) {
    char snap_path[2048]; snprintf(snap_path, sizeof(snap_path), "%s/snapshots/%s.manifest", cfg->repo_path, snapshot_name);
    FILE *f = fopen(snap_path, "rb"); if (!f) return -1;
    manifest_header_t hdr; fread(&hdr, sizeof(hdr), 1, f);
    file_entry_t entry; int found = 0;
    for (uint64_t i = 0; i < hdr.entry_count; i++) {
        if (fread(&entry, sizeof(entry), 1, f) != 1) break;
        if (strcmp(entry.path, rel_path) == 0) { found = 1; break; }
    } fclose(f); if (!found) return -1;
    fprintf(stderr, "DEBUG: loading object %s\n", entry.sha256);
    unsigned char *data; size_t len;
    if (load_object(cfg, entry.sha256, &data, &len) != 0) { fprintf(stderr, "DEBUG: load_object failed\n"); return -1; }
    fprintf(stderr, "DEBUG: ensure_dir\n");
    char *slash3 = strrchr(dest_path, '/');
    if (slash3) { *slash3 = 0; ensure_dir(dest_path); *slash3 = '/'; }
    fprintf(stderr, "DEBUG: fopen dest %s\n", dest_path);
    FILE *out = fopen(dest_path, "wb"); if (!out) { fprintf(stderr, "DEBUG: fopen dest failed: %s\n", strerror(errno)); free(data); return -1; }
    fwrite(data, 1, len, out); fclose(out); free(data);
    chmod(dest_path, entry.mode); chown(dest_path, entry.uid, entry.gid); return 0;
}

int backup_verify(const backup_config_t *cfg) {
    char snap_dir[2048]; snprintf(snap_dir, sizeof(snap_dir), "%s/snapshots", cfg->repo_path);
    DIR *d = opendir(snap_dir); if (!d) return -1;
    struct dirent *de; int errors = 0;
    while ((de = readdir(d)) != NULL) {
        if (strstr(de->d_name, ".manifest")) {
            char path[2048]; snprintf(path, sizeof(path), "%s/%s", snap_dir, de->d_name);
            FILE *f = fopen(path, "rb"); if (f) {
                manifest_header_t hdr; fread(&hdr, sizeof(hdr), 1, f);
                file_entry_t entry;
                for (uint64_t i = 0; i < hdr.entry_count; i++) {
                    if (fread(&entry, sizeof(entry), 1, f) != 1) { errors++; break; }
                    unsigned char *data; size_t len;
                    if (load_object(cfg, entry.sha256, &data, &len) != 0) { fprintf(stderr, "MISSING: %s\n", entry.path); errors++; continue; }
                    char verify_sha[65]; sha256_data(data, len, verify_sha);
                    if (strcmp(verify_sha, entry.sha256) != 0) { fprintf(stderr, "HASH MISMATCH: %s\n", entry.path); errors++; }
                    free(data);
                } fclose(f);
            }
        }
    } closedir(d); return errors;
}

void backup_cleanup(void) { g_repo_open = 0; }