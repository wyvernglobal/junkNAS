/*
 * junkNAS - WireGuard mesh coordination + chunk replication helpers
 */

#include "mesh.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "wireguard.h"

#define MESH_MAX_PEERS   MAX_WG_PEERS
#define MESH_CONNECT_TIMEOUT_SEC 1
#define MESH_SYNC_INTERVAL_SEC 5

static void mesh_log_verbose(const junknas_config_t *config, const char *fmt, ...) {
    if (!config || !config->verbose) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

typedef struct {
    char wg_ip[16];
    uint16_t web_port;
} mesh_peer_t;

struct junknas_mesh {
    junknas_config_t *config;
    pthread_t listener;
    pthread_mutex_t lock;
    int stop;
    int active;
    int standalone;
    uint64_t last_applied_peers_updated_at;
    time_t last_public_ip_check;
    char last_public_ip[64];
};

static int mesh_apply_wireguard(struct junknas_mesh *mesh);
static char *http_request_body(const char *host, uint16_t port, const char *request,
                               const char *body, size_t body_len, int *out_status);

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

    buf = malloc((size_t)sz + 1);
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

    if (rename(tmp_path, path) != 0) {
        (void)remove(tmp_path);
        return -1;
    }

    return 0;
}

static int normalize_key_string(const char *input, char *out, size_t out_len) {
    if (!input || !out || out_len == 0) return -1;

    while (*input && isspace((unsigned char)*input)) {
        input++;
    }

    size_t len = strlen(input);
    while (len > 0 && isspace((unsigned char)input[len - 1])) {
        len--;
    }

    if (len == 0 || len >= out_len) return -1;
    memcpy(out, input, len);
    out[len] = '\0';
    return 0;
}

static int build_private_key_path(const junknas_config_t *config, char *out, size_t out_len) {
    if (!config || !out || out_len == 0) return -1;

    if (config->config_file_path[0] == '\0') {
        return snprintf(out, out_len, "private.key") >= (int)out_len ? -1 : 0;
    }

    const char *slash = strrchr(config->config_file_path, '/');
    if (!slash) {
        return snprintf(out, out_len, "private.key") >= (int)out_len ? -1 : 0;
    }

    size_t dir_len = (size_t)(slash - config->config_file_path);
    if (dir_len == 0) {
        return snprintf(out, out_len, "/private.key") >= (int)out_len ? -1 : 0;
    }

    return snprintf(out, out_len, "%.*s/private.key", (int)dir_len, config->config_file_path) >= (int)out_len
               ? -1
               : 0;
}

static int build_private_key_fallback_path(const junknas_config_t *config, char *out, size_t out_len) {
    if (!config || !out || out_len == 0) return -1;
    if (config->data_dir[0] == '\0') return -1;
    return snprintf(out, out_len, "%s/private.key", config->data_dir) >= (int)out_len ? -1 : 0;
}

static int parse_endpoint(const char *endpoint, char *host, size_t host_len, uint16_t *port) {
    if (!endpoint || !host || !port) return -1;
    const char *colon = strrchr(endpoint, ':');
    if (!colon || colon == endpoint || *(colon + 1) == '\0') return -1;

    size_t hlen = (size_t)(colon - endpoint);
    if (hlen >= host_len) return -1;
    memcpy(host, endpoint, hlen);
    host[hlen] = '\0';

    char *end = NULL;
    long p = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || *end != '\0' || p < 1 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

static int is_ipv4_address(const char *text) {
    if (!text || text[0] == '\0') return 0;
    struct in_addr addr;
    return inet_pton(AF_INET, text, &addr) == 1;
}

static int resolve_addr(const char *host, uint16_t port, int socktype,
                        struct sockaddr_storage *out, socklen_t *out_len) {
    if (!host || !out || !out_len) return -1;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = socktype;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    if (!res) return -1;
    memcpy(out, res->ai_addr, res->ai_addrlen);
    *out_len = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static int fetch_public_ip(char *out, size_t out_len) {
    if (!out || out_len == 0) return -1;
    out[0] = '\0';

    const char *host = "ifconfig.io";
    const char *path = "/ip";
    char request[256];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: junkNAS\r\nConnection: close\r\n\r\n",
             path, host);

    int status = 0;
    char *body = http_request_body(host, 80, request, NULL, 0, &status);
    if (!body) return -1;

    int rc = -1;
    if (status >= 200 && status < 300) {
        char *start = body;
        while (*start && isspace((unsigned char)*start)) start++;
        char *end = start;
        while (*end && !isspace((unsigned char)*end)) end++;
        if (end > start) {
            size_t len = (size_t)(end - start);
            if (len < out_len) {
                memcpy(out, start, len);
                out[len] = '\0';
                if (is_ipv4_address(out)) {
                    rc = 0;
                }
            }
        }
    }
    free(body);
    return rc;
}

static int mesh_refresh_public_endpoint(struct junknas_mesh *mesh, int force) {
    if (!mesh || !mesh->config) return -1;
    if (strcmp(mesh->config->node_state, NODE_STATE_END) == 0) return 0;

    char public_ip[64];
    if (fetch_public_ip(public_ip, sizeof(public_ip)) != 0) {
        return -1;
    }

    int changed = 0;
    junknas_config_lock(mesh->config);

    char host[MAX_ENDPOINT_LEN];
    uint16_t port = 0;
    int has_endpoint = (mesh->config->wg.endpoint[0] != '\0');
    int parsed = has_endpoint ? parse_endpoint(mesh->config->wg.endpoint, host, sizeof(host), &port) : -1;
    int host_is_ip = (parsed == 0) ? is_ipv4_address(host) : 0;

    if (force || !has_endpoint) {
        snprintf(mesh->config->wg.endpoint, sizeof(mesh->config->wg.endpoint), "%s:%u",
                 public_ip, mesh->config->wg.listen_port);
        changed = 1;
    } else if (host_is_ip && strcmp(host, public_ip) != 0) {
        snprintf(mesh->config->wg.endpoint, sizeof(mesh->config->wg.endpoint), "%s:%u",
                 public_ip, mesh->config->wg.listen_port);
        changed = 1;
    }

    if (strncmp(mesh->last_public_ip, public_ip, sizeof(mesh->last_public_ip)) != 0) {
        snprintf(mesh->last_public_ip, sizeof(mesh->last_public_ip), "%s", public_ip);
    }
    junknas_config_unlock(mesh->config);

    if (changed) {
        junknas_config_lock(mesh->config);
        (void)junknas_config_save(mesh->config, mesh->config->config_file_path);
        junknas_config_unlock(mesh->config);
    }

    return changed;
}

static char *http_request_body(const char *host, uint16_t port, const char *request,
                               const char *body, size_t body_len, int *out_status) {
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    if (resolve_addr(host, port, SOCK_STREAM, &addr, &addr_len) != 0) return NULL;

    int fd = socket(addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    if (connect(fd, (struct sockaddr *)&addr, addr_len) != 0) {
        close(fd);
        return NULL;
    }

    if (send(fd, request, strlen(request), 0) < 0) {
        close(fd);
        return NULL;
    }
    if (body && body_len > 0) {
        if (send(fd, body, body_len, 0) < 0) {
            close(fd);
            return NULL;
        }
    }

    char buf[4096];
    char header_buf[8192 + 1];
    size_t header_used = 0;
    int status = 0;
    int header_done = 0;
    char *out = NULL;
    size_t out_len = 0;

    while (1) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;

        if (!header_done) {
            size_t to_copy = (size_t)n;
            if (header_used + to_copy > sizeof(header_buf)) {
                to_copy = sizeof(header_buf) - header_used;
            }
            memcpy(header_buf + header_used, buf, to_copy);
            header_used += to_copy;

            char *header_end = NULL;
            for (size_t i = 0; i + 3 < header_used; i++) {
                if (header_buf[i] == '\r' && header_buf[i + 1] == '\n' &&
                    header_buf[i + 2] == '\r' && header_buf[i + 3] == '\n') {
                    header_end = header_buf + i + 4;
                    size_t header_len = i + 4;
                    if (header_len < sizeof(header_buf)) {
                        header_buf[header_len] = '\0';
                    } else {
                        header_buf[sizeof(header_buf) - 1] = '\0';
                    }
                    char *line_end = strstr(header_buf, "\r\n");
                    if (line_end) {
                        *line_end = '\0';
                        (void)sscanf(header_buf, "HTTP/%*s %d", &status);
                    }
                    header_done = 1;
                    size_t body_part = header_used - header_len;
                    if (body_part > 0) {
                        char *new_out = realloc(out, out_len + body_part + 1);
                        if (!new_out) break;
                        out = new_out;
                        memcpy(out + out_len, header_end, body_part);
                        out_len += body_part;
                        out[out_len] = '\0';
                    }
                    break;
                }
            }
        } else {
            char *new_out = realloc(out, out_len + (size_t)n + 1);
            if (!new_out) break;
            out = new_out;
            memcpy(out + out_len, buf, (size_t)n);
            out_len += (size_t)n;
            out[out_len] = '\0';
        }
    }

    close(fd);
    if (out_status) *out_status = status;
    if (!out) {
        out = calloc(1, 1);
    }
    return out;
}

static int mesh_mount_points_contains(const junknas_config_t *config, const char *mount_point) {
    if (!config || !mount_point) return 0;
    for (int i = 0; i < config->data_mount_point_count; i++) {
        if (strcmp(config->data_mount_points[i], mount_point) == 0) return 1;
    }
    return 0;
}

static void mesh_ensure_local_mount(struct junknas_mesh *mesh) {
    if (!mesh || !mesh->config) return;
    junknas_config_lock(mesh->config);
    if (!mesh_mount_points_contains(mesh->config, mesh->config->mount_point)) {
        (void)junknas_config_add_data_mount_point(mesh->config, mesh->config->mount_point);
        mesh->config->data_mount_points_updated_at = (uint64_t)time(NULL);
        mesh_log_verbose(mesh->config, "mesh: added local mount point %s", mesh->config->mount_point);
    }
    junknas_config_unlock(mesh->config);
}

static void mesh_mark_active(struct junknas_mesh *mesh) {
    if (!mesh) return;
    pthread_mutex_lock(&mesh->lock);
    mesh->active = 1;
    mesh->standalone = 0;
    pthread_mutex_unlock(&mesh->lock);
}

static int mesh_peer_from_json(cJSON *obj, junknas_wg_peer_t *peer) {
    if (!cJSON_IsObject(obj) || !peer) return -1;
    junknas_wg_peer_t out = {0};

    cJSON *pub = cJSON_GetObjectItemCaseSensitive(obj, "public_key");
    if (cJSON_IsString(pub) && pub->valuestring) {
        snprintf(out.public_key, sizeof(out.public_key), "%s", pub->valuestring);
    }
    cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(obj, "endpoint");
    if (cJSON_IsString(endpoint) && endpoint->valuestring) {
        snprintf(out.endpoint, sizeof(out.endpoint), "%s", endpoint->valuestring);
    }
    cJSON *wg_ip = cJSON_GetObjectItemCaseSensitive(obj, "wg_ip");
    if (cJSON_IsString(wg_ip) && wg_ip->valuestring) {
        snprintf(out.wg_ip, sizeof(out.wg_ip), "%s", wg_ip->valuestring);
    }
    cJSON *keepalive = cJSON_GetObjectItemCaseSensitive(obj, "persistent_keepalive");
    if (cJSON_IsNumber(keepalive) && keepalive->valuedouble >= 0) {
        out.persistent_keepalive = (uint16_t)keepalive->valuedouble;
    }
    cJSON *web_port = cJSON_GetObjectItemCaseSensitive(obj, "web_port");
    if (cJSON_IsNumber(web_port) && web_port->valuedouble > 0 && web_port->valuedouble < 65536) {
        out.web_port = (uint16_t)web_port->valuedouble;
    }

    if (out.public_key[0] == '\0' || out.wg_ip[0] == '\0') return -1;
    *peer = out;
    return 0;
}

static int mesh_peer_equal(const junknas_wg_peer_t *a, const junknas_wg_peer_t *b) {
    if (!a || !b) return 0;
    if (strcmp(a->public_key, b->public_key) != 0) return 0;
    if (strcmp(a->endpoint, b->endpoint) != 0) return 0;
    if (strcmp(a->wg_ip, b->wg_ip) != 0) return 0;
    if (a->persistent_keepalive != b->persistent_keepalive) return 0;
    if (a->web_port != b->web_port) return 0;
    return 1;
}

static cJSON *mesh_peer_to_json(const junknas_wg_peer_t *peer) {
    if (!peer) return NULL;
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    cJSON_AddStringToObject(obj, "public_key", peer->public_key);
    cJSON_AddStringToObject(obj, "endpoint", peer->endpoint);
    cJSON_AddStringToObject(obj, "wg_ip", peer->wg_ip);
    cJSON_AddNumberToObject(obj, "persistent_keepalive", (double)peer->persistent_keepalive);
    cJSON_AddNumberToObject(obj, "web_port", (double)peer->web_port);
    return obj;
}

static int mesh_update_from_json(struct junknas_mesh *mesh, const char *payload) {
    if (!mesh || !payload) return -1;

    cJSON *root = cJSON_Parse(payload);
    if (!root) return -1;

    int changed = 0;
    junknas_config_t *config = mesh->config;

    junknas_wg_peer_t incoming[MESH_MAX_PEERS];
    int incoming_count = 0;

    cJSON *peers = cJSON_GetObjectItemCaseSensitive(root, "peers");
    if (cJSON_IsArray(peers)) {
        int n = cJSON_GetArraySize(peers);
        for (int i = 0; i < n && incoming_count < MESH_MAX_PEERS; i++) {
            cJSON *entry = cJSON_GetArrayItem(peers, i);
            junknas_wg_peer_t peer = {0};
            if (mesh_peer_from_json(entry, &peer) == 0) {
                incoming[incoming_count++] = peer;
            }
        }
    }

    cJSON *self = cJSON_GetObjectItemCaseSensitive(root, "self");
    if (cJSON_IsObject(self) && incoming_count < MESH_MAX_PEERS) {
        junknas_wg_peer_t peer = {0};
        if (mesh_peer_from_json(self, &peer) == 0) {
            incoming[incoming_count++] = peer;
        }
    }

    uint64_t remote_updated = 0;
    cJSON *updated = cJSON_GetObjectItemCaseSensitive(root, "updated_at");
    if (cJSON_IsNumber(updated) && updated->valuedouble >= 0) {
        remote_updated = (uint64_t)updated->valuedouble;
    }

    junknas_config_lock(config);
    const char *local_pub = config->wg.public_key;
    uint64_t local_updated = config->wg_peers_updated_at;

    junknas_wg_peer_t filtered[MESH_MAX_PEERS];
    int filtered_count = 0;
    for (int i = 0; i < incoming_count; i++) {
        if (local_pub[0] != '\0' && strcmp(local_pub, incoming[i].public_key) == 0) {
            continue;
        }
        filtered[filtered_count++] = incoming[i];
    }

    if (remote_updated >= local_updated && remote_updated != 0) {
        int diff = (config->wg_peer_count != filtered_count);
        if (!diff) {
            for (int i = 0; i < filtered_count; i++) {
                if (!mesh_peer_equal(&config->wg_peers[i], &filtered[i])) {
                    diff = 1;
                    break;
                }
            }
        }
        if (diff) {
            if (junknas_config_set_wg_peers(config, filtered, filtered_count) == 0) {
                changed = 1;
            }
        }
        if (remote_updated > local_updated) {
            config->wg_peers_updated_at = remote_updated;
            changed = 1;
        }
    } else {
        for (int i = 0; i < filtered_count; i++) {
            int rc = junknas_config_upsert_wg_peer(config, &filtered[i]);
            if (rc == 1) changed = 1;
        }
    }

    cJSON *mounts_updated = cJSON_GetObjectItemCaseSensitive(root, "mounts_updated_at");
    uint64_t remote_mounts_updated = 0;
    if (cJSON_IsNumber(mounts_updated) && mounts_updated->valuedouble >= 0) {
        remote_mounts_updated = (uint64_t)mounts_updated->valuedouble;
    }
    if (remote_mounts_updated > config->data_mount_points_updated_at) {
        cJSON *mounts = cJSON_GetObjectItemCaseSensitive(root, "mount_points");
        if (cJSON_IsArray(mounts)) {
            config->data_mount_point_count = 0;
            int n = cJSON_GetArraySize(mounts);
            for (int i = 0; i < n && config->data_mount_point_count < MAX_DATA_MOUNT_POINTS; i++) {
                cJSON *entry = cJSON_GetArrayItem(mounts, i);
                if (cJSON_IsString(entry) && entry->valuestring) {
                    (void)junknas_config_add_data_mount_point(config, entry->valuestring);
                }
            }
            config->data_mount_points_updated_at = remote_mounts_updated;
            changed = 1;
        }
    }

    junknas_config_unlock(config);
    cJSON_Delete(root);
    return changed;
}

static char *mesh_build_sync_payload(junknas_config_t *config) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    if (strcmp(config->node_state, NODE_STATE_NODE) == 0) {
        cJSON_AddNumberToObject(root, "updated_at", (double)config->wg_peers_updated_at);
        cJSON_AddNumberToObject(root, "mounts_updated_at", (double)config->data_mount_points_updated_at);

        cJSON *self = cJSON_CreateObject();
        if (!self) {
            cJSON_Delete(root);
            return NULL;
        }
        cJSON_AddStringToObject(self, "public_key", config->wg.public_key);
        cJSON_AddStringToObject(self, "endpoint", config->wg.endpoint);
        cJSON_AddStringToObject(self, "wg_ip", config->wg.wg_ip);
        cJSON_AddNumberToObject(self, "web_port", (double)config->web_port);
        cJSON_AddNumberToObject(self, "persistent_keepalive", 0);
        cJSON_AddNumberToObject(self, "listen_port", (double)config->wg.listen_port);
        cJSON_AddItemToObject(root, "self", self);

        cJSON *peers = cJSON_CreateArray();
        if (!peers) {
            cJSON_Delete(root);
            return NULL;
        }
        cJSON_AddItemToObject(root, "peers", peers);
        for (int i = 0; i < config->wg_peer_count; i++) {
            cJSON *entry = mesh_peer_to_json(&config->wg_peers[i]);
            if (entry) cJSON_AddItemToArray(peers, entry);
        }

        cJSON *mounts = cJSON_CreateArray();
        if (!mounts) {
            cJSON_Delete(root);
            return NULL;
        }
        cJSON_AddItemToObject(root, "mount_points", mounts);
        for (int i = 0; i < config->data_mount_point_count; i++) {
            cJSON_AddItemToArray(mounts, cJSON_CreateString(config->data_mount_points[i]));
        }
    } else {
        cJSON_AddNumberToObject(root, "updated_at", 0.0);
        cJSON_AddNumberToObject(root, "mounts_updated_at", 0.0);
    }

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return printed;
}

static int mesh_sync_with_peer(struct junknas_mesh *mesh, const char *endpoint) {
    char host[MAX_ENDPOINT_LEN];
    uint16_t port = 0;
    if (parse_endpoint(endpoint, host, sizeof(host), &port) != 0) return -1;

    junknas_config_lock(mesh->config);
    char *payload = mesh_build_sync_payload(mesh->config);
    junknas_config_unlock(mesh->config);
    if (!payload) return -1;

    char request[512];
    size_t payload_len = strlen(payload);
    snprintf(request, sizeof(request),
             "POST /mesh/peers HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n",
             host, payload_len);

    int status = 0;
    char *body = http_request_body(host, port, request, payload, payload_len, &status);
    free(payload);
    if (!body) return -1;

    int changed = 0;
    int ok = (status >= 200 && status < 300);
    if (ok) {
        if (body[0] != '\0') {
            changed = mesh_update_from_json(mesh, body);
        }
        mesh_mark_active(mesh);
    }
    free(body);

    if (changed > 0) {
        junknas_config_lock(mesh->config);
        (void)junknas_config_save(mesh->config, mesh->config->config_file_path);
        junknas_config_unlock(mesh->config);
        (void)mesh_apply_wireguard(mesh);
        junknas_config_lock(mesh->config);
        mesh->last_applied_peers_updated_at = mesh->config->wg_peers_updated_at;
        junknas_config_unlock(mesh->config);
        mesh_mark_active(mesh);
    }

    return ok ? 0 : -1;
}

static void mesh_free_wg_peers(wg_peer *peer) {
    while (peer) {
        wg_peer *next = peer->next_peer;
        wg_allowedip *allowed = peer->first_allowedip;
        while (allowed) {
            wg_allowedip *next_allowed = allowed->next_allowedip;
            free(allowed);
            allowed = next_allowed;
        }
        free(peer);
        peer = next;
    }
}

static int mesh_apply_wireguard(struct junknas_mesh *mesh) {
    if (!mesh || !mesh->config) return -1;

    junknas_config_lock(mesh->config);
    junknas_wg_peer_t peers[MESH_MAX_PEERS];
    int peer_count = mesh->config->wg_peer_count;
    if (peer_count > MESH_MAX_PEERS) peer_count = MESH_MAX_PEERS;
    memcpy(peers, mesh->config->wg_peers, sizeof(junknas_wg_peer_t) * (size_t)peer_count);
    char iface[32];
    snprintf(iface, sizeof(iface), "%s", mesh->config->wg.interface_name);
    char private_key_b64[MAX_WG_KEY_LEN];
    snprintf(private_key_b64, sizeof(private_key_b64), "%s", mesh->config->wg.private_key);
    uint16_t listen_port = mesh->config->wg.listen_port;
    junknas_config_unlock(mesh->config);

    wg_device *existing = NULL;
    if (wg_get_device(&existing, iface) != 0) {
        (void)wg_add_device(iface);
    }
    if (existing) wg_free_device(existing);

    wg_device dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.name, sizeof(dev.name), "%s", iface);
    dev.flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT | WGDEVICE_REPLACE_PEERS;
    dev.listen_port = listen_port;

    if (wg_key_from_base64(dev.private_key, private_key_b64) != 0) {
        return -1;
    }

    wg_peer *first_peer = NULL;
    wg_peer *last_peer = NULL;

    for (int i = 0; i < peer_count; i++) {
        wg_peer *peer = calloc(1, sizeof(*peer));
        if (!peer) continue;

        peer->flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;
        if (wg_key_from_base64(peer->public_key, peers[i].public_key) != 0) {
            free(peer);
            continue;
        }

        if (peers[i].persistent_keepalive > 0) {
            peer->persistent_keepalive_interval = peers[i].persistent_keepalive;
            peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
        }

        if (peers[i].endpoint[0] != '\0') {
            char host[MAX_ENDPOINT_LEN];
            uint16_t port = 0;
            if (parse_endpoint(peers[i].endpoint, host, sizeof(host), &port) == 0) {
                struct sockaddr_storage addr;
                socklen_t addr_len = 0;
                if (resolve_addr(host, port, SOCK_DGRAM, &addr, &addr_len) == 0) {
                    memcpy(&peer->endpoint.addr, &addr, addr_len);
                }
            }
        }

        struct in_addr ip4;
        if (inet_pton(AF_INET, peers[i].wg_ip, &ip4) == 1) {
            wg_allowedip *allowed = calloc(1, sizeof(*allowed));
            if (allowed) {
                allowed->family = AF_INET;
                allowed->ip4 = ip4;
                allowed->cidr = 32;
                peer->first_allowedip = allowed;
                peer->last_allowedip = allowed;
            }
        }

        if (!first_peer) {
            first_peer = peer;
        } else {
            last_peer->next_peer = peer;
        }
        last_peer = peer;
    }

    dev.first_peer = first_peer;
    dev.last_peer = last_peer;

    int rc = wg_set_device(&dev);
    mesh_free_wg_peers(first_peer);
    return rc == 0 ? 0 : -1;
}

static int mesh_ensure_wg_keys(struct junknas_mesh *mesh) {
    if (!mesh || !mesh->config) return -1;

    char private_key_path[MAX_PATH_LEN];
    char fallback_key_path[MAX_PATH_LEN];
    bool have_fallback_path = false;
    if (build_private_key_path(mesh->config, private_key_path, sizeof(private_key_path)) != 0) {
        mesh_log_verbose(mesh->config, "mesh: failed to build WireGuard key path");
        return -1;
    }
    if (build_private_key_fallback_path(mesh->config, fallback_key_path, sizeof(fallback_key_path)) == 0 &&
        strcmp(fallback_key_path, private_key_path) != 0) {
        have_fallback_path = true;
    }

    mesh_log_verbose(mesh->config, "mesh: ensuring WireGuard keys in %s", private_key_path);
    junknas_config_lock(mesh->config);

    wg_key private_key;
    wg_key public_key;
    wg_key_b64_string pub_b64;
    bool have_private = false;
    bool changed = false;
    bool should_write_private = false;
    bool file_loaded = false;

    char *file_contents = NULL;
    if (read_entire_file(private_key_path, &file_contents, NULL) == 0) {
        char normalized[MAX_WG_KEY_LEN];
        if (normalize_key_string(file_contents, normalized, sizeof(normalized)) == 0 &&
            wg_key_from_base64(private_key, normalized) == 0) {
            if (strcmp(mesh->config->wg.private_key, normalized) != 0) {
                snprintf(mesh->config->wg.private_key, sizeof(mesh->config->wg.private_key), "%s", normalized);
                changed = true;
            }
            have_private = true;
            file_loaded = true;
            mesh_log_verbose(mesh->config, "mesh: loaded existing WireGuard private key");
        }
    } else {
        mesh_log_verbose(mesh->config, "mesh: no private key file found at %s", private_key_path);
    }
    free(file_contents);
    file_contents = NULL;

    if (!have_private && have_fallback_path) {
        if (read_entire_file(fallback_key_path, &file_contents, NULL) == 0) {
            char normalized[MAX_WG_KEY_LEN];
            if (normalize_key_string(file_contents, normalized, sizeof(normalized)) == 0 &&
                wg_key_from_base64(private_key, normalized) == 0) {
                if (strcmp(mesh->config->wg.private_key, normalized) != 0) {
                    snprintf(mesh->config->wg.private_key, sizeof(mesh->config->wg.private_key), "%s",
                             normalized);
                    changed = true;
                }
                have_private = true;
                file_loaded = true;
                mesh_log_verbose(mesh->config, "mesh: loaded existing WireGuard private key from %s",
                                 fallback_key_path);
            }
        } else {
            mesh_log_verbose(mesh->config, "mesh: no private key file found at %s", fallback_key_path);
        }
        free(file_contents);
        file_contents = NULL;
    }

    if (!have_private) {
        if (mesh->config->wg.private_key[0] != '\0' &&
            wg_key_from_base64(private_key, mesh->config->wg.private_key) == 0) {
            have_private = true;
        } else {
            wg_key_b64_string priv_b64;
            wg_generate_private_key(private_key);
            wg_key_to_base64(priv_b64, private_key);
            snprintf(mesh->config->wg.private_key, sizeof(mesh->config->wg.private_key), "%s", priv_b64);
            changed = true;
            have_private = true;
            mesh_log_verbose(mesh->config, "mesh: generated new WireGuard private key");
        }
    }

    if (!have_private) {
        junknas_config_unlock(mesh->config);
        mesh_log_verbose(mesh->config, "mesh: failed to obtain WireGuard private key");
        return -1;
    }

    if (wg_key_from_base64(private_key, mesh->config->wg.private_key) != 0) {
        junknas_config_unlock(mesh->config);
        mesh_log_verbose(mesh->config, "mesh: WireGuard private key is invalid");
        return -1;
    }

    wg_generate_public_key(public_key, private_key);
    wg_key_to_base64(pub_b64, public_key);
    if (strcmp(mesh->config->wg.public_key, pub_b64) != 0) {
        snprintf(mesh->config->wg.public_key, sizeof(mesh->config->wg.public_key), "%s", pub_b64);
        changed = true;
        mesh_log_verbose(mesh->config, "mesh: updated WireGuard public key");
    }

    should_write_private = !file_loaded;
    junknas_config_unlock(mesh->config);

    if (should_write_private) {
        if (write_entire_file_atomic(private_key_path, mesh->config->wg.private_key) != 0) {
            mesh_log_verbose(mesh->config,
                             "mesh: failed to write private key to %s (continuing without key file)",
                             private_key_path);
            if (have_fallback_path &&
                write_entire_file_atomic(fallback_key_path, mesh->config->wg.private_key) == 0) {
                mesh_log_verbose(mesh->config, "mesh: wrote WireGuard private key to %s",
                                 fallback_key_path);
            }
        } else {
            mesh_log_verbose(mesh->config, "mesh: wrote WireGuard private key to %s", private_key_path);
        }
    }

    if (changed) {
        mesh_log_verbose(mesh->config, "mesh: saving updated WireGuard keys to %s",
                         mesh->config->config_file_path);
        return junknas_config_save(mesh->config, mesh->config->config_file_path);
    }

    return 0;
}

static void mesh_refresh_active(struct junknas_mesh *mesh) {
    if (!mesh || !mesh->config) return;
    junknas_config_lock(mesh->config);
    int active = (mesh->config->wg_peer_count > 0);
    junknas_config_unlock(mesh->config);
    pthread_mutex_lock(&mesh->lock);
    mesh->active = active;
    pthread_mutex_unlock(&mesh->lock);
}

static void *mesh_listener_thread(void *arg) {
    struct junknas_mesh *mesh = (struct junknas_mesh *)arg;

    while (!mesh->stop) {
        int did_sync = 0;
        time_t now = time(NULL);
        if (mesh->last_public_ip_check == 0 || now - mesh->last_public_ip_check >= 60) {
            mesh->last_public_ip_check = now;
            if (mesh_refresh_public_endpoint(mesh, 0) > 0) {
                did_sync = 1;
            }
        }

        junknas_config_lock(mesh->config);
        int peer_count = mesh->config->bootstrap_peer_count;
        char peers[MAX_BOOTSTRAP_PEERS][MAX_ENDPOINT_LEN];
        for (int i = 0; i < peer_count; i++) {
            snprintf(peers[i], sizeof(peers[i]), "%s", mesh->config->bootstrap_peers[i]);
        }
        int wg_peer_count = mesh->config->wg_peer_count;
        uint16_t default_web_port = mesh->config->web_port;
        junknas_wg_peer_t wg_peers[MESH_MAX_PEERS];
        if (wg_peer_count > MESH_MAX_PEERS) wg_peer_count = MESH_MAX_PEERS;
        for (int i = 0; i < wg_peer_count; i++) {
            wg_peers[i] = mesh->config->wg_peers[i];
        }
        junknas_config_unlock(mesh->config);

        for (int i = 0; i < peer_count; i++) {
            int rc = mesh_sync_with_peer(mesh, peers[i]);
            junknas_config_lock(mesh->config);
            mesh->config->bootstrap_peer_status[i] = (rc == 0) ? 1 : 0;
            junknas_config_unlock(mesh->config);
            if (rc == 0) did_sync = 1;
        }

        for (int i = 0; i < wg_peer_count; i++) {
            uint16_t web_port = wg_peers[i].web_port ? wg_peers[i].web_port : default_web_port;
            char endpoint[MAX_ENDPOINT_LEN];
            snprintf(endpoint, sizeof(endpoint), "%s:%u", wg_peers[i].wg_ip, web_port);
            int rc = mesh_sync_with_peer(mesh, endpoint);
            junknas_config_lock(mesh->config);
            mesh->config->wg_peer_status[i] = (rc == 0) ? 1 : 0;
            junknas_config_unlock(mesh->config);
            if (rc == 0) did_sync = 1;
        }

        uint64_t peers_updated_at = 0;
        junknas_config_lock(mesh->config);
        peers_updated_at = mesh->config->wg_peers_updated_at;
        junknas_config_unlock(mesh->config);

        if (peers_updated_at != mesh->last_applied_peers_updated_at) {
            if (mesh_apply_wireguard(mesh) == 0) {
                mesh->last_applied_peers_updated_at = peers_updated_at;
            }
        }

        if (!did_sync) {
            mesh_refresh_active(mesh);
        }

        for (int i = 0; i < MESH_SYNC_INTERVAL_SEC && !mesh->stop; i++) {
            sleep(1);
        }
    }

    return NULL;
}

static int http_request(const char *host, uint16_t port, const char *request,
                        const uint8_t *body, size_t body_len,
                        FILE *out, int *out_status) {
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    if (resolve_addr(host, port, SOCK_STREAM, &addr, &addr_len) != 0) return -1;

    int fd = socket(addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    if (connect(fd, (struct sockaddr *)&addr, addr_len) != 0) {
        close(fd);
        return -1;
    }

    if (send(fd, request, strlen(request), 0) < 0) {
        close(fd);
        return -1;
    }
    if (body && body_len > 0) {
        if (send(fd, body, body_len, 0) < 0) {
            close(fd);
            return -1;
        }
    }

    char buf[4096];
    char header_buf[8192 + 1];
    size_t header_used = 0;
    int status = 0;
    int header_done = 0;
    while (1) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;

        if (!header_done) {
            size_t to_copy = (size_t)n;
            if (header_used + to_copy > sizeof(header_buf)) {
                to_copy = sizeof(header_buf) - header_used;
            }
            memcpy(header_buf + header_used, buf, to_copy);
            header_used += to_copy;

            char *header_end = NULL;
            for (size_t i = 0; i + 3 < header_used; i++) {
                if (header_buf[i] == '\r' && header_buf[i + 1] == '\n' &&
                    header_buf[i + 2] == '\r' && header_buf[i + 3] == '\n') {
                    header_end = header_buf + i + 4;
                    size_t header_len = i + 4;
                    if (header_len < sizeof(header_buf)) {
                        header_buf[header_len] = '\0';
                    } else {
                        header_buf[sizeof(header_buf) - 1] = '\0';
                    }
                    char *line_end = strstr(header_buf, "\r\n");
                    if (line_end) {
                        *line_end = '\0';
                        (void)sscanf(header_buf, "HTTP/%*s %d", &status);
                    }
                    header_done = 1;
                    size_t body_part = header_used - header_len;
                    if (body_part > 0 && out) {
                        fwrite(header_end, 1, body_part, out);
                    }
                    break;
                }
            }
        } else if (out) {
            fwrite(buf, 1, (size_t)n, out);
        }
    }

    close(fd);
    if (out_status) *out_status = status;
    return (status >= 200 && status < 300) ? 0 : -1;
}

int junknas_mesh_fetch_chunk(junknas_mesh_t *mesh, const char *hashhex, const char *dest_path) {
    if (!mesh || !hashhex || !dest_path) return -1;
    if (!junknas_mesh_is_active(mesh)) return -1;

    junknas_config_lock(mesh->config);
    mesh_peer_t peers[MESH_MAX_PEERS];
    int peer_count = mesh->config->wg_peer_count;
    if (peer_count > MESH_MAX_PEERS) peer_count = MESH_MAX_PEERS;
    for (int i = 0; i < peer_count; i++) {
        snprintf(peers[i].wg_ip, sizeof(peers[i].wg_ip), "%s", mesh->config->wg_peers[i].wg_ip);
        peers[i].web_port = mesh->config->wg_peers[i].web_port ?
            mesh->config->wg_peers[i].web_port : mesh->config->web_port;
    }
    junknas_config_unlock(mesh->config);

    for (int i = 0; i < peer_count; i++) {
        char request[512];
        snprintf(request, sizeof(request),
                 "GET /chunks/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                 hashhex, peers[i].wg_ip);

        FILE *out = fopen(dest_path, "wb");
        if (!out) continue;
        int status = 0;
        int rc = http_request(peers[i].wg_ip, peers[i].web_port, request, NULL, 0, out, &status);
        fclose(out);

        if (rc == 0) {
            return 0;
        }
        (void)unlink(dest_path);
    }

    return -1;
}

int junknas_mesh_replicate_chunk(junknas_mesh_t *mesh,
                                const char *hashhex,
                                const uint8_t *data,
                                size_t len) {
    if (!mesh || !hashhex || !data || len == 0) return -1;
    if (!junknas_mesh_is_active(mesh)) return -1;

    junknas_config_lock(mesh->config);
    mesh_peer_t peers[MESH_MAX_PEERS];
    int peer_count = mesh->config->wg_peer_count;
    if (peer_count > MESH_MAX_PEERS) peer_count = MESH_MAX_PEERS;
    for (int i = 0; i < peer_count; i++) {
        snprintf(peers[i].wg_ip, sizeof(peers[i].wg_ip), "%s", mesh->config->wg_peers[i].wg_ip);
        peers[i].web_port = mesh->config->wg_peers[i].web_port ?
            mesh->config->wg_peers[i].web_port : mesh->config->web_port;
    }
    junknas_config_unlock(mesh->config);

    for (int i = 0; i < peer_count; i++) {
        char request[512];
        snprintf(request, sizeof(request),
                 "POST /chunks/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\n\r\n",
                 hashhex, peers[i].wg_ip, len);
        (void)http_request(peers[i].wg_ip, peers[i].web_port, request, data, len, NULL, NULL);
    }

    return 0;
}

int junknas_mesh_is_active(const junknas_mesh_t *mesh) {
    if (!mesh) return 0;
    pthread_mutex_lock((pthread_mutex_t *)&mesh->lock);
    int active = mesh->active;
    pthread_mutex_unlock((pthread_mutex_t *)&mesh->lock);
    return active;
}

junknas_mesh_t *junknas_mesh_start(junknas_config_t *config) {
    if (!config) return NULL;

    struct junknas_mesh *mesh = calloc(1, sizeof(*mesh));
    if (!mesh) return NULL;

    mesh->config = config;
    pthread_mutex_init(&mesh->lock, NULL);

    mesh_log_verbose(config, "mesh: starting mesh services");
    mesh_ensure_local_mount(mesh);

    if (mesh_ensure_wg_keys(mesh) != 0) {
        mesh_log_verbose(config, "mesh: WireGuard key setup failed");
        pthread_mutex_destroy(&mesh->lock);
        free(mesh);
        return NULL;
    }

    (void)mesh_refresh_public_endpoint(mesh, 1);

    mesh_log_verbose(config, "mesh: applying WireGuard configuration");
    (void)mesh_apply_wireguard(mesh);
    junknas_config_lock(mesh->config);
    mesh->last_applied_peers_updated_at = mesh->config->wg_peers_updated_at;
    junknas_config_unlock(mesh->config);

    if (pthread_create(&mesh->listener, NULL, mesh_listener_thread, mesh) != 0) {
        mesh_log_verbose(config, "mesh: failed to start mesh listener thread");
        pthread_mutex_destroy(&mesh->lock);
        free(mesh);
        return NULL;
    }

    if (config->bootstrap_peer_count == 0) {
        mesh->standalone = 1;
        mesh_refresh_active(mesh);
        mesh_log_verbose(config, "mesh: running in standalone mode (no bootstrap peers)");
        return mesh;
    }

    time_t start = time(NULL);
    while (time(NULL) - start < MESH_CONNECT_TIMEOUT_SEC) {
        pthread_mutex_lock(&mesh->lock);
        int active = mesh->active;
        pthread_mutex_unlock(&mesh->lock);
        if (active) break;
        usleep(100000);
    }

    pthread_mutex_lock(&mesh->lock);
    if (!mesh->active) mesh->standalone = 1;
    pthread_mutex_unlock(&mesh->lock);

    return mesh;
}

void junknas_mesh_stop(junknas_mesh_t *mesh) {
    if (!mesh) return;
    mesh->stop = 1;
    if (mesh->listener) {
        pthread_join(mesh->listener, NULL);
    }
    pthread_mutex_destroy(&mesh->lock);
    free(mesh);
}
