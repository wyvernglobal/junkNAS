/*
 * junkNAS - Mesh coordination + chunk replication helpers
 */

#ifndef JUNKNAS_MESH_H
#define JUNKNAS_MESH_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"

typedef struct junknas_mesh junknas_mesh_t;

/*
 * Start the mesh listener and attempt bootstrap connections.
 * Returns an initialized mesh handle (or NULL on failure).
 */
junknas_mesh_t *junknas_mesh_start(junknas_config_t *config);

/*
 * Stop the mesh threads and release resources.
 */
void junknas_mesh_stop(junknas_mesh_t *mesh);

/*
 * Try to fetch a chunk from the mesh into dest_path.
 * Returns 0 on success, -1 on failure/not found.
 */
int junknas_mesh_fetch_chunk(junknas_mesh_t *mesh, const char *hashhex, const char *dest_path);

/*
 * Replicate a chunk to known mesh peers (best-effort).
 * Returns 0 if dispatched, -1 on error.
 */
int junknas_mesh_replicate_chunk(junknas_mesh_t *mesh,
                                const char *hashhex,
                                const uint8_t *data,
                                size_t len);

/*
 * Whether the mesh has at least one active peer.
 */
int junknas_mesh_is_active(const junknas_mesh_t *mesh);

#endif /* JUNKNAS_MESH_H */
