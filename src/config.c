/*
 * junkNAS - Configuration Management (implementation)
 *
 * This file implements the functions declared in include/config.h.
 *
 * Dependencies:
 *  - cJSON (https://github.com/DaveGamble/cJSON)
 *
 * Expected JSON shape (example):
 * {
 *   "storage_size": "10G",
 *   "data_dir": "/var/lib/junknas/data",
 *   "mount_point": "/mnt/junknas",
 *   "web_port": 8080,
 *   "verbose": 1,
 *   "enable_fuse": 1,
 *   "daemon_mode": 0,
 *   "wireguard": {
 *     "interface_name": "jnk0",
 *     "private_key": "BASE64...",
 *     "public_key": "BASE64...",
 *     "wg_ip": "10.99.0.5",
 *     "listen_port": 51820,
 *     "mtu": 0
 *   },
 *   "bootstrap_peers": [
 *     "example.com:51820",
 *     "10.0.0.2:51820"
 *   ]
 * }
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

/* ------------------------------ Helpers ---------------------------------- */

/* Safe string copy into fixed-size buffers:
 * - Always NUL-terminates
 * - Returns 0 on success, -1 if truncated
 */
static int safe_strcpy(char *dst, size_t dst_len, const char *src) {
    if (!dst || dst_len == 0) return -1;
    if (!src) {
        dst[0] = '\0';
        return 0;
    }

    size_t n = strnlen(src, dst_len);
    if (n >= dst_len) {
        /* src length is >= dst_len; truncation would occur */
        memcpy(dst, src, dst_len - 1);
        dst[dst_len - 1] = '\0';
        return -1;
    }

    memcpy(dst, src, n);
    dst[n] = '\0';
    return 0;
}

/* Read entire file into a heap buffer.
 * Caller must free(*out_buf).
 * Returns 0 on success, -1 on error.
 */
static int read_entire_file(const char *path, char **out_buf, size_t *out_len) {
    FILE *f = NULL;
    char *buf = NULL;
    long sz = 0;

    if (!path || !out_buf) return -1;
    *out_buf = NULL;
    if (out_len) *out_len = 0;

    f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return -1;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }

    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }

    if (sz > 0) {
        size_t got = fread(buf, 1, (size_t)sz, f);
        if (got != (size_t)sz) {
            free(buf);
            fclose(f);
            return -1;
        }
    }

    buf[(size_t)sz] = '\0';
    fclose(f);

    *out_buf = buf;
    if (out_len) *out_len = (size_t)sz;
    return 0;
}

/* Write a string to file atomically-ish:
 * - Writes to "<path>.tmp"
 * - Renames to "<path>"
 */
static int write_entire_file_atomic(const char *path, const char *data) {
    if (!path || !data) return -1;

    char tmp_path[MAX_PATH_LEN];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path) >= (int)sizeof(tmp_path)) {
        return -1;
    }

    FILE *f = fopen(tmp_path, "wb");
    if (!f) return -1;

    size_t len = strlen(data);
    if (len > 0) {
        if (fwrite(data, 1, len, f) != len) {
            fclose(f);
            (void)remove(tmp_path);
            return -1;
        }
    }

    if (fflush(f) != 0) {
        fclose(f);
        (void)remove(tmp_path);
        return -1;
    }

    fclose(f);

    /* rename() is atomic on POSIX when within same filesystem */
    if (rename(tmp_path, path) != 0) {
        (void)remove(tmp_path);
        return -1;
    }

    return 0;
}

/* -------------------------- Public API ----------------------------------- */

size_t junknas_parse_storage_size(const char *size_str) {
    /* Parses strings like:
     *  - "10G" => 10 * 1024^3
     *  - "500M" => 500 * 1024^2
     *  - "1T" => 1 * 1024^4
     *  - "123" => 123 bytes (no suffix)
     *
     * Returns 0 on error (including NULL or invalid format).
     */
    if (!size_str) return 0;

    /* Skip leading whitespace */
    while (*size_str == ' ' || *size_str == '\t' || *size_str == '\n' || *size_str == '\r') {
        size_str++;
    }
    if (*size_str == '\0') return 0;

    errno = 0;
    char *end = NULL;
    unsigned long long base = strtoull(size_str, &end, 10);
    if (errno != 0 || end == size_str) return 0;

    /* Skip whitespace between number and suffix */
    while (*end == ' ' || *end == '\t') end++;

    unsigned long long mul = 1;

    if (*end != '\0') {
        char s = *end;
        /* Allow K/M/G/T in either case */
        if (s >= 'a' && s <= 'z') s = (char)(s - ('a' - 'A'));

        switch (s) {
            case 'K': mul = 1024ULL; break;
            case 'M': mul = 1024ULL * 1024ULL; break;
            case 'G': mul = 1024ULL * 1024ULL * 1024ULL; break;
            case 'T': mul = 1024ULL * 1024ULL * 1024ULL * 1024ULL; break;
            default:
                /* Unknown suffix */
                return 0;
        }

        /* Extra trailing junk after suffix is not allowed */
        end++;
        while (*end == ' ' || *end == '\t') end++;
        if (*end != '\0') return 0;
    }

    unsigned long long bytes = base * mul;

    /* Clamp to size_t range */
    if (bytes > (unsigned long long)(SIZE_MAX)) {
        return 0;
    }
    return (size_t)bytes;
}

int junknas_config_add_bootstrap_peer(junknas_config_t *config, const char *endpoint) {
    if (!config || !endpoint) return -1;

    if (config->bootstrap_peer_count < 0) config->bootstrap_peer_count = 0;

    if (config->bootstrap_peer_count >= MAX_BOOTSTRAP_PEERS) {
        return -1;
    }

    int idx = config->bootstrap_peer_count;

    /* Copy endpoint into fixed buffer */
    (void)safe_strcpy(config->bootstrap_peers[idx], MAX_ENDPOINT_LEN, endpoint);

    config->bootstrap_peer_count++;
    return 0;
}

void junknas_config_cleanup(junknas_config_t *config) {
    /* Currently everything is fixed-size buffers, so nothing to free.
     */
    (void)config;
}

static void set_defaults(junknas_config_t *config) {
    /* This function sets the full config structure to known defaults. */
    memset(config, 0, sizeof(*config));

    /* Storage */
    (void)safe_strcpy(config->storage_size, sizeof(config->storage_size), DEFAULT_STORAGE_SIZE);
    config->max_storage_bytes = junknas_parse_storage_size(DEFAULT_STORAGE_SIZE);

    /* Paths */
    (void)safe_strcpy(config->data_dir, sizeof(config->data_dir), DEFAULT_DATA_DIR);
    (void)safe_strcpy(config->mount_point, sizeof(config->mount_point), DEFAULT_MOUNT_POINT);
    (void)safe_strcpy(config->config_file_path, sizeof(config->config_file_path), DEFAULT_CONFIG_FILE);

    /* Web */
    config->web_port = (uint16_t)DEFAULT_WEB_PORT;

    /* Runtime flags (sane defaults) */
    config->verbose = 0;
    config->enable_fuse = 1;
    config->daemon_mode = 0;

    /* WireGuard defaults */
    (void)safe_strcpy(config->wg.interface_name, sizeof(config->wg.interface_name), DEFAULT_WG_INTERFACE);
    config->wg.private_key[0] = '\0';
    config->wg.public_key[0] = '\0';
    (void)safe_strcpy(config->wg.wg_ip, sizeof(config->wg.wg_ip), "10.99.0.1");
    config->wg.listen_port = (uint16_t)DEFAULT_WG_PORT;
    config->wg.mtu = 0;

    /* Bootstrap list */
    config->bootstrap_peer_count = 0;
}

int junknas_config_validate(const junknas_config_t *config) {
    /* This validates values for correctness.
     * Note: we intentionally do NOT check filesystem existence here yet,
     * because:
     *  - running in container/dev mode might create dirs on demand
     *  - you may want "validate" to be pure and not touch disk
     *
     */
    if (!config) return -1;

    /* Ports: must be non-zero and within uint16 range already */
    if (config->web_port == 0) return -1;
    if (config->wg.listen_port == 0) return -1;

    /* Basic string sanity */
    if (config->data_dir[0] == '\0') return -1;
    if (config->mount_point[0] == '\0') return -1;
    if (config->wg.interface_name[0] == '\0') return -1;
    if (config->wg.wg_ip[0] == '\0') return -1;

    /* Storage: require parse success */
    if (config->max_storage_bytes == 0) return -1;

    /* Bootstrap peers count range */
    if (config->bootstrap_peer_count < 0 || config->bootstrap_peer_count > MAX_BOOTSTRAP_PEERS) {
        return -1;
    }

    /* Optional: if bootstrap_peer_count > 0, ensure each peer is non-empty */
    for (int i = 0; i < config->bootstrap_peer_count; i++) {
        if (config->bootstrap_peers[i][0] == '\0') return -1;
    }

    return 0;
}

int junknas_config_load(junknas_config_t *config, const char *config_file) {
    if (!config || !config_file) return -1;

    char *json_text = NULL;
    if (read_entire_file(config_file, &json_text, NULL) != 0) {
        return -1;
    }

    cJSON *root = cJSON_Parse(json_text);
    free(json_text);
    json_text = NULL;

    if (!root) {
        return -1;
    }

    /* storage_size */
    cJSON *storage_size = cJSON_GetObjectItemCaseSensitive(root, "storage_size");
    if (cJSON_IsString(storage_size) && storage_size->valuestring) {
        (void)safe_strcpy(config->storage_size, sizeof(config->storage_size), storage_size->valuestring);
        size_t b = junknas_parse_storage_size(config->storage_size);
        if (b != 0) config->max_storage_bytes = b;
    }

    /* data_dir */
    cJSON *data_dir = cJSON_GetObjectItemCaseSensitive(root, "data_dir");
    if (cJSON_IsString(data_dir) && data_dir->valuestring) {
        (void)safe_strcpy(config->data_dir, sizeof(config->data_dir), data_dir->valuestring);
    }

    /* mount_point */
    cJSON *mount_point = cJSON_GetObjectItemCaseSensitive(root, "mount_point");
    if (cJSON_IsString(mount_point) && mount_point->valuestring) {
        (void)safe_strcpy(config->mount_point, sizeof(config->mount_point), mount_point->valuestring);
    }

    /* web_port */
    cJSON *web_port = cJSON_GetObjectItemCaseSensitive(root, "web_port");
    if (cJSON_IsNumber(web_port) && web_port->valuedouble > 0 && web_port->valuedouble < 65536) {
        config->web_port = (uint16_t)web_port->valuedouble;
    }

    /* runtime flags */
    cJSON *verbose = cJSON_GetObjectItemCaseSensitive(root, "verbose");
    if (cJSON_IsBool(verbose)) config->verbose = cJSON_IsTrue(verbose) ? 1 : 0;
    if (cJSON_IsNumber(verbose)) config->verbose = (verbose->valueint != 0);

    cJSON *enable_fuse = cJSON_GetObjectItemCaseSensitive(root, "enable_fuse");
    if (cJSON_IsBool(enable_fuse)) config->enable_fuse = cJSON_IsTrue(enable_fuse) ? 1 : 0;
    if (cJSON_IsNumber(enable_fuse)) config->enable_fuse = (enable_fuse->valueint != 0);

    cJSON *daemon_mode = cJSON_GetObjectItemCaseSensitive(root, "daemon_mode");
    if (cJSON_IsBool(daemon_mode)) config->daemon_mode = cJSON_IsTrue(daemon_mode) ? 1 : 0;
    if (cJSON_IsNumber(daemon_mode)) config->daemon_mode = (daemon_mode->valueint != 0);

    /* wireguard object */
    cJSON *wg = cJSON_GetObjectItemCaseSensitive(root, "wireguard");
    if (cJSON_IsObject(wg)) {
        cJSON *ifn = cJSON_GetObjectItemCaseSensitive(wg, "interface_name");
        if (cJSON_IsString(ifn) && ifn->valuestring) {
            (void)safe_strcpy(config->wg.interface_name, sizeof(config->wg.interface_name), ifn->valuestring);
        }

        cJSON *priv = cJSON_GetObjectItemCaseSensitive(wg, "private_key");
        if (cJSON_IsString(priv) && priv->valuestring) {
            (void)safe_strcpy(config->wg.private_key, sizeof(config->wg.private_key), priv->valuestring);
        }

        cJSON *pub = cJSON_GetObjectItemCaseSensitive(wg, "public_key");
        if (cJSON_IsString(pub) && pub->valuestring) {
            (void)safe_strcpy(config->wg.public_key, sizeof(config->wg.public_key), pub->valuestring);
        }

        cJSON *ip = cJSON_GetObjectItemCaseSensitive(wg, "wg_ip");
        if (cJSON_IsString(ip) && ip->valuestring) {
            (void)safe_strcpy(config->wg.wg_ip, sizeof(config->wg.wg_ip), ip->valuestring);
        }

        cJSON *lp = cJSON_GetObjectItemCaseSensitive(wg, "listen_port");
        if (cJSON_IsNumber(lp) && lp->valuedouble > 0 && lp->valuedouble < 65536) {
            config->wg.listen_port = (uint16_t)lp->valuedouble;
        }

        cJSON *mtu = cJSON_GetObjectItemCaseSensitive(wg, "mtu");
        if (cJSON_IsNumber(mtu)) {
            config->wg.mtu = mtu->valueint;
        }
    }

    /* bootstrap_peers array */
    cJSON *peers = cJSON_GetObjectItemCaseSensitive(root, "bootstrap_peers");
    if (cJSON_IsArray(peers)) {
        config->bootstrap_peer_count = 0;
        int n = cJSON_GetArraySize(peers);
        if (n > MAX_BOOTSTRAP_PEERS) n = MAX_BOOTSTRAP_PEERS;

        for (int i = 0; i < n; i++) {
            cJSON *p = cJSON_GetArrayItem(peers, i);
            if (cJSON_IsString(p) && p->valuestring) {
                (void)junknas_config_add_bootstrap_peer(config, p->valuestring);
            }
        }
    }

    cJSON_Delete(root);
    return 0;
}

int junknas_config_save(const junknas_config_t *config, const char *config_file) {
    if (!config || !config_file) return -1;

    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    /* top-level fields */
    cJSON_AddStringToObject(root, "storage_size", config->storage_size);
    cJSON_AddStringToObject(root, "data_dir", config->data_dir);
    cJSON_AddStringToObject(root, "mount_point", config->mount_point);
    cJSON_AddNumberToObject(root, "web_port", (double)config->web_port);

    cJSON_AddBoolToObject(root, "verbose", config->verbose ? 1 : 0);
    cJSON_AddBoolToObject(root, "enable_fuse", config->enable_fuse ? 1 : 0);
    cJSON_AddBoolToObject(root, "daemon_mode", config->daemon_mode ? 1 : 0);

    /* wireguard */
    cJSON *wg = cJSON_CreateObject();
    if (!wg) {
        cJSON_Delete(root);
        return -1;
    }
    cJSON_AddItemToObject(root, "wireguard", wg);

    cJSON_AddStringToObject(wg, "interface_name", config->wg.interface_name);
    cJSON_AddStringToObject(wg, "private_key", config->wg.private_key);
    cJSON_AddStringToObject(wg, "public_key", config->wg.public_key);
    cJSON_AddStringToObject(wg, "wg_ip", config->wg.wg_ip);
    cJSON_AddNumberToObject(wg, "listen_port", (double)config->wg.listen_port);
    cJSON_AddNumberToObject(wg, "mtu", (double)config->wg.mtu);

    /* bootstrap peers */
    cJSON *arr = cJSON_CreateArray();
    if (!arr) {
        cJSON_Delete(root);
        return -1;
    }
    cJSON_AddItemToObject(root, "bootstrap_peers", arr);

    for (int i = 0; i < config->bootstrap_peer_count && i < MAX_BOOTSTRAP_PEERS; i++) {
        cJSON_AddItemToArray(arr, cJSON_CreateString(config->bootstrap_peers[i]));
    }

    /* Render JSON */
    char *printed = cJSON_Print(root);
    cJSON_Delete(root);

    if (!printed) return -1;

    int rc = write_entire_file_atomic(config_file, printed);
    free(printed);
    return (rc == 0) ? 0 : -1;
}

int junknas_config_init(junknas_config_t *config, const char *config_file) {
    if (!config) return -1;

    /* Start with defaults */
    set_defaults(config);

    /* If config_file provided, use it and also store the path */
    if (config_file && config_file[0] != '\0') {
        (void)safe_strcpy(config->config_file_path, sizeof(config->config_file_path), config_file);

        /* Loading is optional: missing file should not necessarily be fatal
         * BUT: right now we treat load failure as an error to make debugging easy.
         * We can change later to "ignore ENOENT".
         */
        if (junknas_config_load(config, config_file) != 0) {
            return -1;
        }
    }

    /* Validate final config */
    return junknas_config_validate(config);
}
