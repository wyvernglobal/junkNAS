/*
 * junkNAS - FUSE Filesystem Interface
 *
 * This module mounts a FUSE filesystem at config->mount_point and stores
 * file contents + directories under config->data_dir.
 *
 * Current backend model:
 *   "backing store passthrough"
 *     FUSE path:   /mnt/junknas/hello.txt
 *     Backing dir: <data_dir>/hello.txt
 *
 * Later, we can replace the backing store with chunking without changing
 * the rest of the app.
 */

#ifndef JUNKNAS_FUSE_FS_H
#define JUNKNAS_FUSE_FS_H

#include "config.h"

/*
 * Start the FUSE filesystem.
 *
 * This call typically blocks until the filesystem is unmounted.
 *
 * @param cfg       Loaded/validated junkNAS config
 * @param argc      argc passed from main()
 * @param argv      argv passed from main() (used by FUSE for options)
 * @return          0 on normal exit, -1 on error
 */
int junknas_fuse_run(const junknas_config_t *cfg, int argc, char **argv);

#endif /* JUNKNAS_FUSE_FS_H */
