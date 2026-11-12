#include "backup.h"
#include "kopia.h"
#include "kopia_internal.h"
#include "kopia_cache.h"
#include "kopia_ignore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* read first line of a file into buf (password files: no trailing newline) */
static int read_password_file(const char *path, char *buf, size_t buflen) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, (int)buflen, f)) { fclose(f); return -1; }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[--len] = '\0';
    if (len > 0 && buf[len - 1] == '\r') buf[--len] = '\0';
    fclose(f);
    return 0;
}

static int cmd_kopia_push(int argc, char **argv) {
    kopia_config_t cfg = {0};
    const char *path = NULL;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--url") == 0 && i + 1 < argc) {
            snprintf(cfg.server_url, sizeof(cfg.server_url), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            snprintf(cfg.repo_user, sizeof(cfg.repo_user), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--hostname") == 0 && i + 1 < argc) {
            snprintf(cfg.repo_hostname, sizeof(cfg.repo_hostname), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            snprintf(cfg.repo_password, sizeof(cfg.repo_password), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--password-file") == 0 && i + 1 < argc) {
            if (read_password_file(argv[++i], cfg.repo_password, sizeof(cfg.repo_password)) != 0) {
                fprintf(stderr, "cannot read --password-file %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--fingerprint") == 0 && i + 1 < argc) {
            snprintf(cfg.fingerprint, sizeof(cfg.fingerprint), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--ignore") == 0 && i + 1 < argc) {
            if (kignore_add_pattern(argv[++i]) != 0) {
                fprintf(stderr, "invalid --ignore pattern: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--ignore-file") == 0 && i + 1 < argc) {
            int n = kignore_add_file(argv[++i]);
            if (n < 0) {
                fprintf(stderr, "cannot read --ignore-file %s\n", argv[i]);
                return 1;
            }
        } else {
            path = argv[i];
        }
    }

    if (!cfg.server_url[0] || !cfg.repo_user[0] || !path) {
        fprintf(stderr, "Usage: %s kopia-push --url https://host:port --user NAME "
                        "--hostname HOST [--password PASS | --password-file FILE] "
                        "[--fingerprint FP] [--ignore PAT]... [--ignore-file FILE]... <path>\n", argv[0]);
        return 1;
    }

    if (!cfg.repo_password[0]) {
        const char *env = getenv("KOPIA_PASSWORD");
        if (env) snprintf(cfg.repo_password, sizeof(cfg.repo_password), "%s", env);
    }
    if (!cfg.repo_password[0]) {
        fprintf(stderr, "no password: use --password, --password-file or KOPIA_PASSWORD\n");
        return 1;
    }

    /* default rule source, kopia-compatible: <path>/.kopiaignore */
    int rcdef = kignore_load_source_default(path);
    if (rcdef < 0) {
        fprintf(stderr, "cannot read .kopiaignore in %s\n", path);
        return 1;
    }

    kopia_session_t s;
    char err[512] = "";
    if (ksess_connect(&s, &cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "kopia connect failed: %s\n", err);
        return 1;
    }
    printf("connected: hash=%s splitter=%s\n", s.hash_function, s.splitter_name);

    char oid[256];
    if (kup_upload_path(&s, path, oid, sizeof(oid)) != 0) {
        fprintf(stderr, "upload failed: %s\n", path);
        return 1;
    }
    printf("object: %s\n", oid);

    if (ksess_flush(&s) != 0) {
        fprintf(stderr, "flush failed\n");
        return 1;
    }

    char mid[128];
    if (kup_snapshot(&s, path, oid, mid, sizeof(mid)) != 0) {
        fprintf(stderr, "snapshot failed\n");
        return 1;
    }
    printf("snapshot: %s\n", mid);

    /* manifest contents must be flushed before disconnect */
    if (ksess_flush(&s) != 0) {
        fprintf(stderr, "final flush failed\n");
        return 1;
    }

    /* everything uploaded + snapshotted: promote the incremental cache */
    kcache_commit();

    ksess_close(&s);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  init <repo_path>           - Initialize backup repository\n");
        fprintf(stderr, "  add <repo> <src> <rel>     - Add file to backup\n");
        fprintf(stderr, "  snapshot <repo> <name>     - Create snapshot\n");
        fprintf(stderr, "  list <repo>                - List snapshots\n");
        fprintf(stderr, "  restore <repo> <snap> <rel> <dest> - Restore file\n");
        fprintf(stderr, "  verify <repo>              - Verify repository\n");
        fprintf(stderr, "  kopia-push [opts] <path>   - Upload path to kopia API server\n");
        return 1;
    }

    if (strcmp(argv[1], "kopia-push") == 0) {
        return cmd_kopia_push(argc - 2, argv + 2);
    }

    backup_config_t cfg = {0};
    int ret = 1;

    if (strcmp(argv[1], "init") == 0) {
        if (argc != 3) { fprintf(stderr, "Usage: %s init <repo_path>\n", argv[0]); return 1; }
        if (backup_config_init(&cfg, argv[2]) != 0) return 1;
        if (backup_repo_open(&cfg) != 0) return 1;
        printf("Repository initialized at %s\n", argv[2]);
        ret = 0;
    } else if (strcmp(argv[1], "add") == 0) {
        if (argc != 5) { fprintf(stderr, "Usage: %s add <repo> <src> <rel>\n", argv[0]); return 1; }
        if (backup_config_init(&cfg, argv[2]) != 0) return 1;
        if (backup_repo_open(&cfg) != 0) return 1;
        if (backup_add_file(&cfg, argv[3], argv[4]) != 0) { fprintf(stderr, "Failed to add %s\n", argv[3]); return 1; }
        printf("Added %s as %s\n", argv[3], argv[4]);
        ret = 0;
    } else if (strcmp(argv[1], "snapshot") == 0) {
        if (argc != 4) { fprintf(stderr, "Usage: %s snapshot <repo> <name>\n", argv[0]); return 1; }
        if (backup_config_init(&cfg, argv[2]) != 0) return 1;
        if (backup_repo_open(&cfg) != 0) return 1;
        if (backup_create_snapshot(&cfg, argv[3]) != 0) { fprintf(stderr, "Failed to create snapshot\n"); return 1; }
        printf("Snapshot %s created\n", argv[3]);
        ret = 0;
    } else if (strcmp(argv[1], "list") == 0) {
        if (argc != 3) { fprintf(stderr, "Usage: %s list <repo>\n", argv[0]); return 1; }
        if (backup_config_init(&cfg, argv[2]) != 0) return 1;
        if (backup_repo_open(&cfg) != 0) return 1;
        backup_list_snapshots(&cfg);
        ret = 0;
    } else if (strcmp(argv[1], "restore") == 0) {
        if (argc != 6) { fprintf(stderr, "Usage: %s restore <repo> <snap> <rel> <dest>\n", argv[0]); return 1; }
        if (backup_config_init(&cfg, argv[2]) != 0) return 1;
        if (backup_repo_open(&cfg) != 0) return 1;
        if (backup_restore_file(&cfg, argv[3], argv[4], argv[5]) != 0) { fprintf(stderr, "Failed to restore\n"); return 1; }
        printf("Restored %s to %s\n", argv[4], argv[5]);
        ret = 0;
    } else if (strcmp(argv[1], "verify") == 0) {
        if (argc != 3) { fprintf(stderr, "Usage: %s verify <repo>\n", argv[0]); return 1; }
        if (backup_config_init(&cfg, argv[2]) != 0) return 1;
        if (backup_repo_open(&cfg) != 0) return 1;
        int errors = backup_verify(&cfg);
        if (errors == 0) printf("Repository OK\n");
        else printf("Repository has %d errors\n", errors);
        ret = (errors == 0) ? 0 : 1;
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
    }

    backup_cleanup();
    return ret;
}