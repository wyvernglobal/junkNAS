/*
 * junkNAS - Mesh coordination + chunk replication helpers
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
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MESH_HELLO       "JNK_HELLO"
#define MESH_HELLO_ACK   "JNK_HELLO_ACK"
#define MESH_MOUNTS_REQ  "JNK_MOUNTS_REQ"
#define MESH_MOUNTS_RESP "JNK_MOUNTS_RESP"
#define MESH_MAX_PACKET  4096
#define MESH_MAX_PEERS   32
#define MESH_CONNECT_TIMEOUT_SEC 1

typedef struct {
    char host[MAX_ENDPOINT_LEN];
    uint16_t wg_port;
    uint16_t web_port;
    time_t last_seen;
} mesh_peer_t;

struct junknas_mesh {
    junknas_config_t *config;
    int udp_fd;
    pthread_t listener;
    pthread_mutex_t lock;
    int stop;
    int active;
    int standalone;
    mesh_peer_t peers[MESH_MAX_PEERS];
    size_t peer_count;
};

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

static int mesh_sendto(struct junknas_mesh *mesh, const char *host, uint16_t port, const char *payload) {
    if (!mesh || !host || !payload) return -1;
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    if (resolve_addr(host, port, SOCK_DGRAM, &addr, &addr_len) != 0) return -1;
    ssize_t sent = sendto(mesh->udp_fd, payload, strlen(payload), 0,
                          (struct sockaddr *)&addr, addr_len);
    return (sent >= 0) ? 0 : -1;
}

static void mesh_record_peer(struct junknas_mesh *mesh,
                             const char *host,
                             uint16_t wg_port,
                             uint16_t web_port) {
    if (!mesh || !host) return;
    pthread_mutex_lock(&mesh->lock);
    for (size_t i = 0; i < mesh->peer_count; i++) {
        if (strcmp(mesh->peers[i].host, host) == 0 && mesh->peers[i].wg_port == wg_port) {
            if (web_port != 0) mesh->peers[i].web_port = web_port;
            mesh->peers[i].last_seen = time(NULL);
            pthread_mutex_unlock(&mesh->lock);
            return;
        }
    }
    if (mesh->peer_count < MESH_MAX_PEERS) {
        mesh_peer_t *peer = &mesh->peers[mesh->peer_count++];
        snprintf(peer->host, sizeof(peer->host), "%s", host);
        peer->wg_port = wg_port;
        peer->web_port = web_port;
        peer->last_seen = time(NULL);
    }
    pthread_mutex_unlock(&mesh->lock);
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
    pthread_mutex_lock(&mesh->lock);
    if (!mesh_mount_points_contains(mesh->config, mesh->config->mount_point)) {
        (void)junknas_config_add_data_mount_point(mesh->config, mesh->config->mount_point);
        mesh->config->data_mount_points_updated_at = (uint64_t)time(NULL);
    }
    pthread_mutex_unlock(&mesh->lock);
}

static void mesh_send_mounts_resp(struct junknas_mesh *mesh,
                                  struct sockaddr_storage *addr,
                                  socklen_t addr_len) {
    if (!mesh || !addr) return;

    char payload[MESH_MAX_PACKET];
    pthread_mutex_lock(&mesh->lock);
    uint64_t updated = mesh->config->data_mount_points_updated_at;
    int count = mesh->config->data_mount_point_count;
    int written = snprintf(payload, sizeof(payload), "%s %llu %d\n",
                           MESH_MOUNTS_RESP,
                           (unsigned long long)updated,
                           count);
    for (int i = 0; i < count && written > 0 && (size_t)written < sizeof(payload); i++) {
        int n = snprintf(payload + written, sizeof(payload) - (size_t)written,
                         "%s\n", mesh->config->data_mount_points[i]);
        if (n < 0) break;
        written += n;
    }
    pthread_mutex_unlock(&mesh->lock);

    if (written > 0) {
        (void)sendto(mesh->udp_fd, payload, (size_t)written, 0,
                     (struct sockaddr *)addr, addr_len);
    }
}

static void mesh_request_mounts(struct junknas_mesh *mesh,
                                const char *host,
                                uint16_t port,
                                uint64_t since) {
    char payload[128];
    snprintf(payload, sizeof(payload), "%s %llu\n", MESH_MOUNTS_REQ,
             (unsigned long long)since);
    (void)mesh_sendto(mesh, host, port, payload);
}

static void mesh_handle_mounts_resp(struct junknas_mesh *mesh, const char *payload) {
    if (!mesh || !payload) return;
    char *copy = strdup(payload);
    if (!copy) return;

    char *saveptr = NULL;
    char *line = strtok_r(copy, "\n", &saveptr);
    if (!line) { free(copy); return; }

    unsigned long long updated = 0;
    int count = 0;
    if (sscanf(line, "%*s %llu %d", &updated, &count) != 2) {
        free(copy);
        return;
    }

    pthread_mutex_lock(&mesh->lock);
    if (updated > mesh->config->data_mount_points_updated_at) {
        mesh->config->data_mount_point_count = 0;
        for (int i = 0; i < count; i++) {
            char *entry = strtok_r(NULL, "\n", &saveptr);
            if (!entry) break;
            (void)junknas_config_add_data_mount_point(mesh->config, entry);
        }
        mesh->config->data_mount_points_updated_at = (uint64_t)updated;
    }
    pthread_mutex_unlock(&mesh->lock);

    free(copy);
}

static void mesh_mark_active(struct junknas_mesh *mesh) {
    if (!mesh) return;
    pthread_mutex_lock(&mesh->lock);
    mesh->active = 1;
    mesh->standalone = 0;
    pthread_mutex_unlock(&mesh->lock);
}

static void mesh_extract_host(const struct sockaddr_storage *addr, char *host, size_t host_len) {
    if (!addr || !host || host_len == 0) return;
    host[0] = '\0';
    void *src = NULL;
    if (addr->ss_family == AF_INET) {
        src = &((struct sockaddr_in *)addr)->sin_addr;
    } else if (addr->ss_family == AF_INET6) {
        src = &((struct sockaddr_in6 *)addr)->sin6_addr;
    }
    if (src) {
        (void)inet_ntop(addr->ss_family, src, host, (socklen_t)host_len);
    }
}

static void *mesh_listener_thread(void *arg) {
    struct junknas_mesh *mesh = (struct junknas_mesh *)arg;
    char buf[MESH_MAX_PACKET + 1];

    while (!mesh->stop) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(mesh->udp_fd, &readfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int rc = select(mesh->udp_fd + 1, &readfds, NULL, NULL, &tv);
        if (rc <= 0) continue;

        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        ssize_t got = recvfrom(mesh->udp_fd, buf, MESH_MAX_PACKET, 0,
                               (struct sockaddr *)&addr, &addr_len);
        if (got <= 0) continue;
        buf[got] = '\0';

        char host[MAX_ENDPOINT_LEN];
        mesh_extract_host(&addr, host, sizeof(host));
        uint16_t peer_port = 0;
        if (addr.ss_family == AF_INET) {
            peer_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            peer_port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
        }

        if (strncmp(buf, MESH_HELLO, strlen(MESH_HELLO)) == 0) {
            unsigned long long web_port = 0;
            unsigned long long mounts_updated = 0;
            if (sscanf(buf, "JNK_HELLO %llu %llu", &web_port, &mounts_updated) == 2) {
                mesh_record_peer(mesh, host, peer_port, (uint16_t)web_port);
                mesh_mark_active(mesh);

                char reply[128];
                pthread_mutex_lock(&mesh->lock);
                unsigned long long local_updated = (unsigned long long)mesh->config->data_mount_points_updated_at;
                pthread_mutex_unlock(&mesh->lock);
                snprintf(reply, sizeof(reply), "%s %u %llu\n",
                         MESH_HELLO_ACK, mesh->config->web_port, local_updated);
                (void)sendto(mesh->udp_fd, reply, strlen(reply), 0,
                             (struct sockaddr *)&addr, addr_len);

                if (mounts_updated > local_updated) {
                    mesh_request_mounts(mesh, host, peer_port, local_updated);
                }
            }
            continue;
        }

        if (strncmp(buf, MESH_HELLO_ACK, strlen(MESH_HELLO_ACK)) == 0) {
            unsigned long long web_port = 0;
            unsigned long long mounts_updated = 0;
            if (sscanf(buf, "JNK_HELLO_ACK %llu %llu", &web_port, &mounts_updated) == 2) {
                mesh_record_peer(mesh, host, peer_port, (uint16_t)web_port);
                mesh_mark_active(mesh);

                pthread_mutex_lock(&mesh->lock);
                unsigned long long local_updated = (unsigned long long)mesh->config->data_mount_points_updated_at;
                pthread_mutex_unlock(&mesh->lock);
                if (mounts_updated > local_updated) {
                    mesh_request_mounts(mesh, host, peer_port, local_updated);
                }
            }
            continue;
        }

        if (strncmp(buf, MESH_MOUNTS_REQ, strlen(MESH_MOUNTS_REQ)) == 0) {
            mesh_mark_active(mesh);
            mesh_send_mounts_resp(mesh, &addr, addr_len);
            continue;
        }

        if (strncmp(buf, MESH_MOUNTS_RESP, strlen(MESH_MOUNTS_RESP)) == 0) {
            mesh_handle_mounts_resp(mesh, buf);
            continue;
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

    pthread_mutex_lock(&mesh->lock);
    size_t peer_count = mesh->peer_count;
    mesh_peer_t peers[MESH_MAX_PEERS];
    memcpy(peers, mesh->peers, sizeof(peers));
    pthread_mutex_unlock(&mesh->lock);

    for (size_t i = 0; i < peer_count; i++) {
        uint16_t web_port = peers[i].web_port ? peers[i].web_port : mesh->config->web_port;
        char request[512];
        snprintf(request, sizeof(request),
                 "GET /chunks/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                 hashhex, peers[i].host);

        FILE *out = fopen(dest_path, "wb");
        if (!out) continue;
        int status = 0;
        int rc = http_request(peers[i].host, web_port, request, NULL, 0, out, &status);
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

    pthread_mutex_lock(&mesh->lock);
    size_t peer_count = mesh->peer_count;
    mesh_peer_t peers[MESH_MAX_PEERS];
    memcpy(peers, mesh->peers, sizeof(peers));
    pthread_mutex_unlock(&mesh->lock);

    for (size_t i = 0; i < peer_count; i++) {
        uint16_t web_port = peers[i].web_port ? peers[i].web_port : mesh->config->web_port;
        char request[512];
        snprintf(request, sizeof(request),
                 "POST /chunks/%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Length: %zu\r\n\r\n",
                 hashhex, peers[i].host, len);
        (void)http_request(peers[i].host, web_port, request, data, len, NULL, NULL);
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

static void mesh_send_hello(struct junknas_mesh *mesh, const char *host, uint16_t port) {
    char payload[128];
    pthread_mutex_lock(&mesh->lock);
    unsigned long long mounts_updated = (unsigned long long)mesh->config->data_mount_points_updated_at;
    pthread_mutex_unlock(&mesh->lock);
    snprintf(payload, sizeof(payload), "%s %u %llu\n", MESH_HELLO, mesh->config->web_port, mounts_updated);
    (void)mesh_sendto(mesh, host, port, payload);
}

junknas_mesh_t *junknas_mesh_start(junknas_config_t *config) {
    if (!config) return NULL;

    struct junknas_mesh *mesh = calloc(1, sizeof(*mesh));
    if (!mesh) return NULL;

    mesh->config = config;
    pthread_mutex_init(&mesh->lock, NULL);

    mesh->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (mesh->udp_fd < 0) {
        free(mesh);
        return NULL;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(config->wg.listen_port ? config->wg.listen_port : DEFAULT_WG_PORT);

    if (bind(mesh->udp_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(mesh->udp_fd);
        free(mesh);
        return NULL;
    }

    mesh_ensure_local_mount(mesh);

    if (pthread_create(&mesh->listener, NULL, mesh_listener_thread, mesh) != 0) {
        close(mesh->udp_fd);
        free(mesh);
        return NULL;
    }

    if (config->bootstrap_peer_count == 0) {
        mesh->standalone = 1;
        return mesh;
    }

    for (int i = 0; i < config->bootstrap_peer_count; i++) {
        char host[MAX_ENDPOINT_LEN];
        uint16_t port = 0;
        if (parse_endpoint(config->bootstrap_peers[i], host, sizeof(host), &port) == 0) {
            mesh_send_hello(mesh, host, port);
        }
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
    if (mesh->udp_fd >= 0) close(mesh->udp_fd);
    pthread_mutex_destroy(&mesh->lock);
    free(mesh);
}
