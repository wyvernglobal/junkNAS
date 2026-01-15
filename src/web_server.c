/*
 * junkNAS - Minimal web server for browsing and chunk sync
 */

#include "web_server.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define WEB_BACKLOG 16
#define WEB_BUF_SIZE 8192

struct junknas_web_server {
    junknas_config_t *config;
    int fd;
    pthread_t thread;
    int stop;
};

typedef struct {
    int fd;
    junknas_config_t *config;
} web_conn_t;

static int is_safe_relative(const char *path) {
    if (!path) return 0;
    if (path[0] == '/') return 0;
    if (strstr(path, "..")) return 0;
    return 1;
}

static int is_hex64(const char *hash) {
    if (!hash) return 0;
    if (strlen(hash) != 64) return 0;
    for (size_t i = 0; i < 64; i++) {
        char c = hash[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}

static int chunk_path_for_hash(const char *data_dir, const char *hash, char *out, size_t out_len) {
    if (!data_dir || !hash || !out) return -1;
    if (!is_hex64(hash)) return -1;
    if (snprintf(out, out_len, "%s/.jnk/chunks/sha256/%c%c/%s",
                 data_dir, hash[0], hash[1], hash) >= (int)out_len) {
        return -1;
    }
    return 0;
}

static void send_all(int fd, const char *data) {
    if (!data) return;
    send(fd, data, strlen(data), 0);
}

static void send_status(int fd, int code, const char *message) {
    char buf[128];
    snprintf(buf, sizeof(buf), "HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n", code, message);
    send_all(fd, buf);
}

static void send_text(int fd, int code, const char *body) {
    char header[256];
    size_t len = body ? strlen(body) : 0;
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
             code, len);
    send_all(fd, header);
    if (body) send(fd, body, len, 0);
}

static void send_html_header(int fd, const char *title) {
    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n");
    send_all(fd, header);
    send_all(fd, "<!doctype html><html><head><meta charset=\"utf-8\">");
    send_all(fd, "<title>");
    send_all(fd, title ? title : "junkNAS");
    send_all(fd, "</title></head><body>");
}

static void send_html_footer(int fd) {
    send_all(fd, "</body></html>");
}

static void respond_mount_listing(int fd, junknas_config_t *config, const char *rel_path) {
    char full_path[MAX_PATH_LEN];
    if (rel_path && rel_path[0] != '\0') {
        snprintf(full_path, sizeof(full_path), "%s/%s", config->mount_point, rel_path);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", config->mount_point);
    }

    DIR *dir = opendir(full_path);
    if (!dir) {
        send_status(fd, 404, "Not Found");
        return;
    }

    send_html_header(fd, "junkNAS fileshare");
    send_all(fd, "<h1>junkNAS fileshare</h1>");
    send_all(fd, "<p>Mount point: ");
    send_all(fd, config->mount_point);
    send_all(fd, "</p>");

    if (config->data_mount_point_count > 0) {
        char stamp[64];
        snprintf(stamp, sizeof(stamp), "%llu",
                 (unsigned long long)config->data_mount_points_updated_at);
        send_all(fd, "<h2>Mesh mount points</h2><ul>");
        for (int i = 0; i < config->data_mount_point_count; i++) {
            send_all(fd, "<li>");
            send_all(fd, config->data_mount_points[i]);
            send_all(fd, "</li>");
        }
        send_all(fd, "</ul><p>Updated at: ");
        send_all(fd, stamp);
        send_all(fd, "</p>");
    }

    send_all(fd, "<h2>Directory listing</h2><ul>");
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        send_all(fd, "<li>");
        if (ent->d_type == DT_DIR) {
            send_all(fd, "<strong>");
            send_all(fd, ent->d_name);
            send_all(fd, "/</strong>");
            send_all(fd, " (<a href=\"/browse/");
            if (rel_path && rel_path[0] != '\0') {
                send_all(fd, rel_path);
                send_all(fd, "/");
            }
            send_all(fd, ent->d_name);
            send_all(fd, "\">browse</a>)");
        } else {
            send_all(fd, "<a href=\"/files/");
            if (rel_path && rel_path[0] != '\0') {
                send_all(fd, rel_path);
                send_all(fd, "/");
            }
            send_all(fd, ent->d_name);
            send_all(fd, "\">");
            send_all(fd, ent->d_name);
            send_all(fd, "</a>");
        }
        send_all(fd, "</li>");
    }
    closedir(dir);
    send_all(fd, "</ul>");
    send_html_footer(fd);
}

static void respond_file(int fd, const char *path) {
    int in = open(path, O_RDONLY);
    if (in < 0) {
        send_status(fd, 404, "Not Found");
        return;
    }

    struct stat st;
    if (fstat(in, &st) != 0) {
        close(in);
        send_status(fd, 500, "Error");
        return;
    }

    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
             (size_t)st.st_size);
    send_all(fd, header);

    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        send(fd, buf, (size_t)n, 0);
    }
    close(in);
}

static int find_chunk_path(junknas_config_t *config, const char *hash, char *out, size_t out_len) {
    size_t dir_count = (config->data_dir_count > 0) ? config->data_dir_count : 1;
    for (size_t i = 0; i < dir_count && i < MAX_DATA_DIRS; i++) {
        const char *dir = (config->data_dir_count > 0) ? config->data_dirs[i] : config->data_dir;
        if (chunk_path_for_hash(dir, hash, out, out_len) == 0) {
            if (access(out, R_OK) == 0) return 0;
        }
    }
    return -1;
}

static void ensure_parent_dir(const char *path) {
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s", path);
    char *slash = strrchr(tmp, '/');
    if (!slash) return;
    *slash = '\0';
    mkdir(tmp, 0755);
}

static void handle_get(web_conn_t *conn, const char *path) {
    if (strcmp(path, "/") == 0) {
        respond_mount_listing(conn->fd, conn->config, "");
        return;
    }

    if (strncmp(path, "/browse/", 8) == 0) {
        const char *rel = path + 8;
        if (!is_safe_relative(rel)) {
            send_status(conn->fd, 400, "Bad Request");
            return;
        }
        respond_mount_listing(conn->fd, conn->config, rel);
        return;
    }

    if (strncmp(path, "/files/", 7) == 0) {
        const char *rel = path + 7;
        if (!is_safe_relative(rel)) {
            send_status(conn->fd, 400, "Bad Request");
            return;
        }
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", conn->config->mount_point, rel);
        respond_file(conn->fd, full_path);
        return;
    }

    if (strncmp(path, "/chunks/", 8) == 0) {
        const char *hash = path + 8;
        if (!is_hex64(hash)) {
            send_status(conn->fd, 400, "Bad Request");
            return;
        }
        char chunk_path[MAX_PATH_LEN];
        if (find_chunk_path(conn->config, hash, chunk_path, sizeof(chunk_path)) != 0) {
            send_status(conn->fd, 404, "Not Found");
            return;
        }
        respond_file(conn->fd, chunk_path);
        return;
    }

    send_status(conn->fd, 404, "Not Found");
}

static int read_headers(int fd, char *buf, size_t buf_len, size_t *out_len) {
    size_t used = 0;
    while (used + 1 < buf_len) {
        ssize_t n = recv(fd, buf + used, buf_len - used - 1, 0);
        if (n <= 0) break;
        used += (size_t)n;
        buf[used] = '\0';
        if (strstr(buf, "\r\n\r\n")) {
            if (out_len) *out_len = used;
            return 0;
        }
    }
    return -1;
}

static const char *find_header_case_insensitive(const char *headers, const char *needle) {
    if (!headers || !needle) return NULL;
    size_t nlen = strlen(needle);
    for (const char *p = headers; *p != '\0'; p++) {
        size_t i = 0;
        while (i < nlen && p[i] != '\0' &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) return p;
    }
    return NULL;
}

static long parse_content_length(const char *headers) {
    const char *cl = find_header_case_insensitive(headers, "Content-Length:");
    if (!cl) return -1;
    cl += strlen("Content-Length:");
    while (*cl == ' ' || *cl == '\t') cl++;
    char *end = NULL;
    long val = strtol(cl, &end, 10);
    if (end == cl || val < 0) return -1;
    return val;
}

static void handle_post_chunk(web_conn_t *conn, const char *hash, const char *headers, const char *body, size_t body_len) {
    if (!is_hex64(hash)) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }

    long content_len = parse_content_length(headers);
    if (content_len < 0) {
        send_status(conn->fd, 411, "Length Required");
        return;
    }

    char chunk_path[MAX_PATH_LEN];
    const char *dir = (conn->config->data_dir_count > 0) ? conn->config->data_dirs[0] : conn->config->data_dir;
    if (chunk_path_for_hash(dir, hash, chunk_path, sizeof(chunk_path)) != 0) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }
    ensure_parent_dir(chunk_path);

    int out = open(chunk_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        send_status(conn->fd, 500, "Error");
        return;
    }

    if (body_len > 0) {
        write(out, body, body_len);
    }
    size_t remaining = (size_t)content_len > body_len ? (size_t)content_len - body_len : 0;
    char buf[4096];
    while (remaining > 0) {
        ssize_t n = recv(conn->fd, buf, remaining > sizeof(buf) ? sizeof(buf) : remaining, 0);
        if (n <= 0) break;
        write(out, buf, (size_t)n);
        remaining -= (size_t)n;
    }
    close(out);

    send_text(conn->fd, 200, "OK\n");
}

static void handle_connection(web_conn_t *conn) {
    char buf[WEB_BUF_SIZE];
    size_t header_len = 0;
    if (read_headers(conn->fd, buf, sizeof(buf), &header_len) != 0) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }

    char *header_end = strstr(buf, "\r\n\r\n");
    if (!header_end) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }
    size_t body_len = header_len - (size_t)(header_end + 4 - buf);
    const char *body = header_end + 4;

    char method[8];
    char path[512];
    if (sscanf(buf, "%7s %511s", method, path) != 2) {
        send_status(conn->fd, 400, "Bad Request");
        return;
    }

    if (strcmp(method, "GET") == 0) {
        handle_get(conn, path);
        return;
    }

    if (strcmp(method, "POST") == 0) {
        if (strncmp(path, "/chunks/", 8) == 0) {
            handle_post_chunk(conn, path + 8, buf, body, body_len);
            return;
        }
        send_status(conn->fd, 404, "Not Found");
        return;
    }

    send_status(conn->fd, 405, "Method Not Allowed");
}

static void *connection_thread(void *arg) {
    web_conn_t *conn = (web_conn_t *)arg;
    handle_connection(conn);
    close(conn->fd);
    free(conn);
    return NULL;
}

static void *server_thread(void *arg) {
    struct junknas_web_server *server = (struct junknas_web_server *)arg;
    while (!server->stop) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int client = accept(server->fd, (struct sockaddr *)&addr, &addr_len);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }

        web_conn_t *conn = calloc(1, sizeof(*conn));
        if (!conn) {
            close(client);
            continue;
        }
        conn->fd = client;
        conn->config = server->config;

        pthread_t tid;
        if (pthread_create(&tid, NULL, connection_thread, conn) == 0) {
            pthread_detach(tid);
        } else {
            close(client);
            free(conn);
        }
    }
    return NULL;
}

junknas_web_server_t *junknas_web_server_start(junknas_config_t *config) {
    if (!config) return NULL;

    struct junknas_web_server *server = calloc(1, sizeof(*server));
    if (!server) return NULL;

    server->config = config;
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        free(server);
        return NULL;
    }

    int opt = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(config->web_port);

    if (bind(server->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(server->fd);
        free(server);
        return NULL;
    }

    if (listen(server->fd, WEB_BACKLOG) != 0) {
        close(server->fd);
        free(server);
        return NULL;
    }

    if (pthread_create(&server->thread, NULL, server_thread, server) != 0) {
        close(server->fd);
        free(server);
        return NULL;
    }

    return server;
}

void junknas_web_server_stop(junknas_web_server_t *server) {
    if (!server) return;
    server->stop = 1;
    if (server->fd >= 0) close(server->fd);
    pthread_join(server->thread, NULL);
    free(server);
}
