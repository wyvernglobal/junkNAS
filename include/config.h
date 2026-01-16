/*
 * junkNAS - Configuration Management
 * Header file for configuration structures and functions
 */

#ifndef JUNKNAS_CONFIG_H
#define JUNKNAS_CONFIG_H

#include <pthread.h>
#include <stddef.h>   /* for size_t */
#include <stdint.h>   /* for uint16_t, etc. */

/* ============================================================================
 * SECTION 1: Default Configuration Constants
 * ============================================================================
 * These are the fallback values if no config file exists or values are missing
 */

#define DEFAULT_DATA_DIR        "/var/lib/junknas/data"
#define DEFAULT_CONFIG_FILE     "/etc/junknas/config.json"
#define DEFAULT_MOUNT_POINT     "/mnt/junknas"
#define DEFAULT_WEB_PORT        8080
#define DEFAULT_WG_PORT         51820
#define DEFAULT_WG_INTERFACE    "jnk0"
#define DEFAULT_STORAGE_SIZE    "10G"

/* Maximum lengths for various strings */
#define MAX_PATH_LEN            4096
#define MAX_WG_KEY_LEN          45      /* WireGuard keys are 44 chars + null */
#define MAX_NODE_ID_LEN         64
#define MAX_BOOTSTRAP_PEERS     10      /* Max initial peers to connect to */
#define MAX_ENDPOINT_LEN        256     /* For "hostname:port" strings */
#define MAX_DATA_DIRS           8       /* Max chunk storage directories */
#define MAX_DATA_MOUNT_POINTS   16      /* Max mesh mount points */
#define MAX_WG_PEERS            64      /* Max WireGuard peers */

#define NODE_STATE_NODE         "node"
#define NODE_STATE_END          "end"


/* ============================================================================
 * SECTION 2: WireGuard Configuration Structure
 * ============================================================================
 * Holds all WireGuard-specific settings for this node
 */

typedef struct {
    char interface_name[32];            /* e.g., "jnk0" */
    char private_key[MAX_WG_KEY_LEN];   /* Base64 WireGuard private key */
    char public_key[MAX_WG_KEY_LEN];    /* Base64 WireGuard public key */
    char wg_ip[16];                     /* IP within mesh, e.g., "10.99.0.5" */
    char endpoint[MAX_ENDPOINT_LEN];    /* Public endpoint host:port */
    uint16_t listen_port;               /* UDP port for WireGuard */
    int mtu;                            /* MTU for the interface (0 = default) */
} junknas_wg_config_t;

typedef struct {
    char public_key[MAX_WG_KEY_LEN];
    char preshared_key[MAX_WG_KEY_LEN];
    char endpoint[MAX_ENDPOINT_LEN];
    char wg_ip[16];
    uint16_t persistent_keepalive;
    uint16_t web_port;
} junknas_wg_peer_t;


/* ============================================================================
 * SECTION 3: Main Configuration Structure
 * ============================================================================
 * This holds ALL configuration for a junkNAS node
 */

typedef struct {
    /* Storage configuration */
    char storage_size[32];              /* Human-readable: "10G", "500M", etc. */
    size_t max_storage_bytes;           /* Parsed value in bytes */

    /* File paths */
    char data_dir[MAX_PATH_LEN];        /* Primary metadata + chunk dir */
    char data_dirs[MAX_DATA_DIRS][MAX_PATH_LEN]; /* Chunk store directories */
    size_t data_dir_count;              /* Number of chunk store dirs */
    char mount_point[MAX_PATH_LEN];     /* Where FUSE mounts the filesystem */
    char config_file_path[MAX_PATH_LEN];/* Path to this config file */

    /* Network configuration */
    uint16_t web_port;                  /* HTTP web interface port */

    /* Node role */
    char node_state[8];                 /* "node" or "end" */

    /* WireGuard mesh configuration */
    junknas_wg_config_t wg;             /* Nested WireGuard config */

    /* Bootstrap peers - initial peers to connect to when joining mesh */
    char bootstrap_peers[MAX_BOOTSTRAP_PEERS][MAX_ENDPOINT_LEN];
    int bootstrap_peer_count;           /* How many bootstrap peers are set */
    uint64_t bootstrap_peers_updated_at;/* Unix epoch seconds for mesh propagation */
    int bootstrap_peer_status[MAX_BOOTSTRAP_PEERS]; /* 1=reachable, 0=dead end, -1=unknown */

    /* WireGuard peers for full mesh sync */
    junknas_wg_peer_t wg_peers[MAX_WG_PEERS];
    int wg_peer_count;
    uint64_t wg_peers_updated_at;
    int wg_peer_status[MAX_WG_PEERS];  /* 1=reachable, 0=dead end, -1=unknown */

    /* Mesh data mount points (for cross-node discovery) */
    char data_mount_points[MAX_DATA_MOUNT_POINTS][MAX_PATH_LEN];
    int data_mount_point_count;
    uint64_t data_mount_points_updated_at;

    /* Runtime flags */
    int verbose;                        /* Enable verbose logging? */
    int enable_fuse;                    /* Mount FUSE filesystem? */
    int daemon_mode;                    /* Run as background daemon? */

    pthread_mutex_t lock;
} junknas_config_t;


/* ============================================================================
 * SECTION 4: Function Declarations
 * ============================================================================
 * Public API for working with configurations
 */

/*
 * Initialize configuration with defaults, then optionally load from file
 *
 * @param config        Pointer to config structure to initialize
 * @param config_file   Path to config file (NULL = use defaults only)
 * @return              0 on success, -1 on error
 */
int junknas_config_init(junknas_config_t *config, const char *config_file);

/*
 * Enable verbose startup logging before config initialization.
 * This does not persist to the config file and is intended for -v usage.
 */
void junknas_config_set_startup_verbose(int verbose);

/*
 * Load configuration from a JSON file
 * @param config        Pointer to config structure to populate
 * @param config_file   Path to JSON config file
 * @return              0 on success, -1 on error
 */
int junknas_config_load(junknas_config_t *config, const char *config_file);

/*
 * Save current configuration to a JSON file
 * @param config        Pointer to config structure to save
 * @param config_file   Path where JSON file should be written
 * @return              0 on success, -1 on error
 */
int junknas_config_save(const junknas_config_t *config, const char *config_file);

/*
 * Validate configuration values
 * Checks that paths exist, ports are valid, etc.
 * @param config        Pointer to config to validate
 * @return              0 if valid, -1 if invalid
 */
int junknas_config_validate(const junknas_config_t *config);

/*
 * Ensure WireGuard keys exist by loading from private.key or generating them.
 * Updates config->wg.public_key and writes private key to private.key when needed.
 * Returns 0 on success, -1 on failure.
 */
int junknas_config_ensure_wg_keys(junknas_config_t *config);

/*
 * Clean up any dynamically allocated resources in config
 * (Currently config uses static buffers, but good practice for future)
 * @param config        Pointer to config to clean up
 */
void junknas_config_cleanup(junknas_config_t *config);

/*
 * Add a bootstrap peer to the configuration
 * @param config        Pointer to config
 * @param endpoint      Peer endpoint as "hostname:port" or "ip:port"
 * @return              0 on success, -1 if too many peers
 */
int junknas_config_add_bootstrap_peer(junknas_config_t *config, const char *endpoint);

/*
 * Add a data mount point to the configuration
 * @param config        Pointer to config
 * @param mount_point   Mount point path (string)
 * @return              0 on success, -1 if too many entries
 */
int junknas_config_add_data_mount_point(junknas_config_t *config, const char *mount_point);

/*
 * Add or update a WireGuard peer by public key.
 * Returns 1 if changed, 0 if no change, -1 on error.
 */
int junknas_config_upsert_wg_peer(junknas_config_t *config, const junknas_wg_peer_t *peer);

/*
 * Replace the WireGuard peers list with provided peers.
 * Returns 0 on success, -1 on error.
 */
int junknas_config_set_wg_peers(junknas_config_t *config, const junknas_wg_peer_t *peers, int count);

/*
 * Lock/unlock helpers for shared config access.
 */
void junknas_config_lock(junknas_config_t *config);
void junknas_config_unlock(junknas_config_t *config);

/*
 * Parse human-readable size string to bytes
 * e.g., "10G" -> 10737418240, "500M" -> 524288000
 * @param size_str      String like "10G", "500M", "1T"
 * @return              Size in bytes, or 0 on parse error
 */
size_t junknas_parse_storage_size(const char *size_str);


#endif /* JUNKNAS_CONFIG_H */
