/*
 * junkNAS - FUSE mount tool (early development)
 *
 * This binary loads config.json then mounts the junkNAS FUSE filesystem.
 * It does not start WireGuard, web UI, or mesh.
 *
 * Usage:
 *   ./junknas_fuse <config.json>
 *
 * Example:
 *   ./junknas_fuse config.test.json
 */

#include <stdio.h>
#include "config.h"
#include "fuse_fs.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config.json>\n", argv[0]);
        return 2;
    }

    const char *config_path = argv[1];

    junknas_config_t cfg;
    if (junknas_config_init(&cfg, config_path) != 0) {
        fprintf(stderr, "Failed to load config: %s\n", config_path);
        return 1;
    }

    if (!cfg.enable_fuse) {
        fprintf(stderr, "Config enable_fuse=false; refusing to mount.\n");
        return 1;
    }

    /* We pass argc/argv to FUSE so you can add options later.
     * But note: FUSE will also see your config path argument.
     * That’s fine for now because we explicitly add cfg.mount_point.
     */
    return (junknas_fuse_run(&cfg, argc, argv) == 0) ? 0 : 1;
}
