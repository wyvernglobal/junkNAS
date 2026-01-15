/*
 * junkNAS - config.c test harness
 *
 * This is a simple test program to verify:
 *  - config defaults work
 *  - JSON loading works
 *  - validation works
 *
 * It does NOT touch WireGuard, FUSE, or networking.
 */

#include <stdio.h>
#include "config.h"

static void dump_config(const junknas_config_t *cfg) {
    printf("junkNAS configuration:\n");
    printf("  data_dir:        %s\n", cfg->data_dir);
    printf("  data_dirs (%zu):\n", cfg->data_dir_count);
    for (size_t i = 0; i < cfg->data_dir_count; i++) {
        printf("    - %s\n", cfg->data_dirs[i]);
    }
    printf("  mount_point:     %s\n", cfg->mount_point);
    printf("  storage_size:    %s\n", cfg->storage_size);
    printf("  max_storage:     %zu bytes\n", cfg->max_storage_bytes);
    printf("  web_port:        %u\n", cfg->web_port);

    printf("  verbose:         %d\n", cfg->verbose);
    printf("  enable_fuse:     %d\n", cfg->enable_fuse);
    printf("  daemon_mode:     %d\n", cfg->daemon_mode);

    printf("  WireGuard:\n");
    printf("    interface:     %s\n", cfg->wg.interface_name);
    printf("    wg_ip:         %s\n", cfg->wg.wg_ip);
    printf("    listen_port:   %u\n", cfg->wg.listen_port);
    printf("    mtu:           %d\n", cfg->wg.mtu);
    printf("    public_key:    %s\n", cfg->wg.public_key[0] ? "(set)" : "(empty)");
    printf("    private_key:   %s\n", cfg->wg.private_key[0] ? "(set)" : "(empty)");

    printf("  bootstrap_peers (%d):\n", cfg->bootstrap_peer_count);
    for (int i = 0; i < cfg->bootstrap_peer_count; i++) {
        printf("    - %s\n", cfg->bootstrap_peers[i]);
    }
}

int main(int argc, char **argv) {
    const char *config_path = NULL;

    if (argc > 1) {
        config_path = argv[1];
    }

    junknas_config_t cfg;

    if (junknas_config_init(&cfg, config_path) != 0) {
        fprintf(stderr, "Failed to load config\n");
        return 1;
    }

    dump_config(&cfg);
    junknas_config_cleanup(&cfg);

    return 0;
}
