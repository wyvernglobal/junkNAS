/*
 * junkNAS - FUSE mount tool (early development)
 *
 * This binary loads config.json then mounts the junkNAS FUSE filesystem.
 * It does not start WireGuard, web UI, or mesh.
 *
 * Usage:
 *   ./junknas_fuse <config.json>
 *   ./junknas_fuse <config.json> bootstrap-peers list
 *   ./junknas_fuse <config.json> bootstrap-peers add <ip:port>
 *   ./junknas_fuse <config.json> bootstrap-peers delete <index>
 *   ./junknas_fuse <config.json> bootstrap-peers edit <index> <ip:port>
 *
 * Example:
 *   ./junknas_fuse config.test.json
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "config.h"
#include "fuse_fs.h"
#include "mesh.h"
#include "web_server.h"

static void print_usage(const char *argv0) {
    fprintf(stderr,
            "Usage:\n"
            "  %s <config.json>\n"
            "  %s <config.json> bootstrap-peers list\n"
            "  %s <config.json> bootstrap-peers add <ip:port>\n"
            "  %s <config.json> bootstrap-peers delete <index>\n"
            "  %s <config.json> bootstrap-peers edit <index> <ip:port>\n",
            argv0, argv0, argv0, argv0, argv0);
}

static int parse_uint_index(const char *text, int *out_index) {
    if (!text || !out_index) return -1;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (end == text || *end != '\0') return -1;
    if (value < 1 || value > INT_MAX) return -1;
    *out_index = (int)value;
    return 0;
}

static int validate_ipv4(const char *host) {
    if (!host || host[0] == '\0') return -1;
    int parts = 0;
    const char *ptr = host;
    while (*ptr) {
        if (parts >= 4) return -1;
        if (*ptr < '0' || *ptr > '9') return -1;
        int value = 0;
        int digits = 0;
        while (*ptr >= '0' && *ptr <= '9') {
            value = value * 10 + (*ptr - '0');
            if (value > 255) return -1;
            ptr++;
            digits++;
            if (digits > 3) return -1;
        }
        if (digits == 0) return -1;
        parts++;
        if (*ptr == '\0') break;
        if (*ptr != '.') return -1;
        ptr++;
        if (*ptr == '\0') return -1;
    }
    return (parts == 4) ? 0 : -1;
}

static int validate_peer_endpoint(const char *endpoint) {
    if (!endpoint) return -1;
    const char *colon = strrchr(endpoint, ':');
    if (!colon || colon == endpoint || *(colon + 1) == '\0') return -1;

    char host[MAX_ENDPOINT_LEN];
    size_t host_len = (size_t)(colon - endpoint);
    if (host_len >= sizeof(host)) return -1;
    memcpy(host, endpoint, host_len);
    host[host_len] = '\0';

    if (validate_ipv4(host) != 0) return -1;

    char *end = NULL;
    long port = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end != '\0') return -1;
    if (port < 1 || port > 65535) return -1;
    return 0;
}

static void list_bootstrap_peers(const junknas_config_t *cfg) {
    printf("bootstrap_peers (%d)", cfg->bootstrap_peer_count);
    if (cfg->bootstrap_peers_updated_at != 0) {
        printf(" updated_at=%llu\n",
               (unsigned long long)cfg->bootstrap_peers_updated_at);
    } else {
        printf(" updated_at=unset\n");
    }
    for (int i = 0; i < cfg->bootstrap_peer_count; i++) {
        printf("  %d) %s\n", i + 1, cfg->bootstrap_peers[i]);
    }
}

static int delete_bootstrap_peer(junknas_config_t *cfg, int index) {
    if (index < 1 || index > cfg->bootstrap_peer_count) return -1;
    int zero_index = index - 1;
    for (int i = zero_index; i < cfg->bootstrap_peer_count - 1; i++) {
        (void)memmove(cfg->bootstrap_peers[i],
                      cfg->bootstrap_peers[i + 1],
                      sizeof(cfg->bootstrap_peers[i]));
    }
    cfg->bootstrap_peer_count--;
    if (cfg->bootstrap_peer_count < 0) cfg->bootstrap_peer_count = 0;
    return 0;
}

static int handle_bootstrap_peers_command(junknas_config_t *cfg,
                                          int argc,
                                          char **argv,
                                          const char *config_path) {
    if (argc < 2) {
        fprintf(stderr, "bootstrap-peers command required.\n");
        return 2;
    }

    const char *command = argv[1];
    if (strcmp(command, "list") == 0) {
        list_bootstrap_peers(cfg);
        return 0;
    }

    if (strcmp(command, "add") == 0) {
        if (argc < 3) {
            fprintf(stderr, "bootstrap-peers add requires <ip:port>.\n");
            return 2;
        }
        if (validate_peer_endpoint(argv[2]) != 0) {
            fprintf(stderr, "Invalid peer endpoint '%s'. Use <ip:port>.\n", argv[2]);
            return 2;
        }
        if (junknas_config_add_bootstrap_peer(cfg, argv[2]) != 0) {
            fprintf(stderr, "Too many bootstrap peers (max %d).\n", MAX_BOOTSTRAP_PEERS);
            return 1;
        }
    } else if (strcmp(command, "delete") == 0) {
        if (argc < 3) {
            fprintf(stderr, "bootstrap-peers delete requires <index>.\n");
            return 2;
        }
        int index = 0;
        if (parse_uint_index(argv[2], &index) != 0) {
            fprintf(stderr, "Invalid index '%s'. Use a 1-based number.\n", argv[2]);
            return 2;
        }
        if (delete_bootstrap_peer(cfg, index) != 0) {
            fprintf(stderr, "Index %d is out of range (1-%d).\n",
                    index, cfg->bootstrap_peer_count);
            return 1;
        }
    } else if (strcmp(command, "edit") == 0) {
        if (argc < 4) {
            fprintf(stderr, "bootstrap-peers edit requires <index> <ip:port>.\n");
            return 2;
        }
        int index = 0;
        if (parse_uint_index(argv[2], &index) != 0) {
            fprintf(stderr, "Invalid index '%s'. Use a 1-based number.\n", argv[2]);
            return 2;
        }
        if (index < 1 || index > cfg->bootstrap_peer_count) {
            fprintf(stderr, "Index %d is out of range (1-%d).\n",
                    index, cfg->bootstrap_peer_count);
            return 1;
        }
        if (validate_peer_endpoint(argv[3]) != 0) {
            fprintf(stderr, "Invalid peer endpoint '%s'. Use <ip:port>.\n", argv[3]);
            return 2;
        }
        (void)snprintf(cfg->bootstrap_peers[index - 1],
                       sizeof(cfg->bootstrap_peers[index - 1]),
                       "%s",
                       argv[3]);
    } else {
        fprintf(stderr, "Unknown bootstrap-peers command '%s'.\n", command);
        return 2;
    }

    cfg->bootstrap_peers_updated_at = (uint64_t)time(NULL);
    if (junknas_config_save(cfg, config_path) != 0) {
        fprintf(stderr, "Failed to save config to %s\n", config_path);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 2;
    }

    const char *config_path = argv[1];

    junknas_config_t cfg;
    if (junknas_config_init(&cfg, config_path) != 0) {
        fprintf(stderr, "Failed to load config: %s\n", config_path);
        return 1;
    }

    if (argc >= 3 && strcmp(argv[2], "bootstrap-peers") == 0) {
        return handle_bootstrap_peers_command(&cfg, argc - 2, argv + 2, config_path);
    }

    if (!cfg.enable_fuse) {
        fprintf(stderr, "Config enable_fuse=false; refusing to mount.\n");
        return 1;
    }

    junknas_mesh_t *mesh = junknas_mesh_start(&cfg);
    if (!mesh) {
        fprintf(stderr, "Warning: failed to start mesh; running standalone.\n");
    }

    junknas_web_server_t *web = junknas_web_server_start(&cfg);
    if (!web) {
        fprintf(stderr, "Warning: failed to start web server on port %u.\n", cfg.web_port);
    }

    /* We pass argc/argv to FUSE so you can add options later.
     * But note: FUSE will also see your config path argument.
     * That’s fine for now because we explicitly add cfg.mount_point.
     */
    int rc = (junknas_fuse_run(&cfg, mesh, argc, argv) == 0) ? 0 : 1;

    if (web) junknas_web_server_stop(web);
    if (mesh) junknas_mesh_stop(mesh);

    return rc;
}
