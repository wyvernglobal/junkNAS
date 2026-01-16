/*
 * junkNAS - Minimal web server for browsing and chunk sync
 */

#include "web_server.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

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

static void web_log_verbose(const junknas_config_t *config, const char *fmt, ...) {
    if (!config || !config->verbose) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

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

static void send_json(int fd, int code, const char *body) {
    char header[256];
    size_t len = body ? strlen(body) : 0;
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
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

static int parse_peer_json(cJSON *obj, junknas_wg_peer_t *peer) {
    if (!cJSON_IsObject(obj) || !peer) return -1;
    junknas_wg_peer_t out = {0};

    cJSON *pub = cJSON_GetObjectItemCaseSensitive(obj, "public_key");
    if (cJSON_IsString(pub) && pub->valuestring) {
        snprintf(out.public_key, sizeof(out.public_key), "%s", pub->valuestring);
    }
    cJSON *psk = cJSON_GetObjectItemCaseSensitive(obj, "preshared_key");
    if (cJSON_IsString(psk) && psk->valuestring) {
        snprintf(out.preshared_key, sizeof(out.preshared_key), "%s", psk->valuestring);
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

static cJSON *peer_to_json(const junknas_wg_peer_t *peer) {
    if (!peer) return NULL;
    cJSON *obj = cJSON_CreateObject();
    if (!obj) return NULL;
    cJSON_AddStringToObject(obj, "public_key", peer->public_key);
    cJSON_AddStringToObject(obj, "preshared_key", peer->preshared_key);
    cJSON_AddStringToObject(obj, "endpoint", peer->endpoint);
    cJSON_AddStringToObject(obj, "wg_ip", peer->wg_ip);
    cJSON_AddNumberToObject(obj, "persistent_keepalive", (double)peer->persistent_keepalive);
    cJSON_AddNumberToObject(obj, "web_port", (double)peer->web_port);
    return obj;
}

static cJSON *build_mesh_state_json(junknas_config_t *config) {
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    junknas_config_lock(config);
    cJSON_AddNumberToObject(root, "updated_at", (double)config->wg_peers_updated_at);
    cJSON_AddNumberToObject(root, "mounts_updated_at", (double)config->data_mount_points_updated_at);

    cJSON *self = cJSON_CreateObject();
    if (self) {
        cJSON_AddStringToObject(self, "public_key", config->wg.public_key);
        cJSON_AddStringToObject(self, "endpoint", config->wg.endpoint);
        cJSON_AddStringToObject(self, "wg_ip", config->wg.wg_ip);
        cJSON_AddNumberToObject(self, "web_port", (double)config->web_port);
        cJSON_AddNumberToObject(self, "persistent_keepalive", 0);
        cJSON_AddNumberToObject(self, "listen_port", (double)config->wg.listen_port);
        cJSON_AddItemToObject(root, "self", self);
    }

    cJSON *peers = cJSON_CreateArray();
    if (peers) {
        for (int i = 0; i < config->wg_peer_count; i++) {
            cJSON *peer = peer_to_json(&config->wg_peers[i]);
            if (peer) cJSON_AddItemToArray(peers, peer);
        }
        cJSON_AddItemToObject(root, "peers", peers);
    }

    cJSON *mounts = cJSON_CreateArray();
    if (mounts) {
        for (int i = 0; i < config->data_mount_point_count; i++) {
            cJSON_AddItemToArray(mounts, cJSON_CreateString(config->data_mount_points[i]));
        }
        cJSON_AddItemToObject(root, "mount_points", mounts);
    }
    junknas_config_unlock(config);
    return root;
}

static void respond_mesh_state(int fd, junknas_config_t *config) {
    cJSON *root = build_mesh_state_json(config);
    if (!root) {
        send_status(fd, 500, "Error");
        return;
    }

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) {
        send_status(fd, 500, "Error");
        return;
    }
    send_json(fd, 200, printed);
    free(printed);
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

static char *http_request_body(const char *host, uint16_t port, const char *request,
                               const char *body, size_t body_len, int *out_status) {
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    if (resolve_addr(host, port, SOCK_STREAM, &addr, &addr_len) != 0) return NULL;

    int fd = socket(addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

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

static void respond_mesh_config(int fd, junknas_config_t *config) {
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        send_status(fd, 500, "Error");
        return;
    }

    junknas_config_lock(config);
    cJSON *self = cJSON_CreateObject();
    if (self) {
        cJSON_AddStringToObject(self, "public_key", config->wg.public_key);
        cJSON_AddStringToObject(self, "endpoint", config->wg.endpoint);
        cJSON_AddStringToObject(self, "wg_ip", config->wg.wg_ip);
        cJSON_AddNumberToObject(self, "listen_port", (double)config->wg.listen_port);
        cJSON_AddNumberToObject(self, "web_port", (double)config->web_port);
        cJSON_AddItemToObject(root, "self", self);
    }

    cJSON_AddNumberToObject(root, "bootstrap_peers_updated_at",
                            (double)config->bootstrap_peers_updated_at);
    cJSON *bootstrap = cJSON_CreateArray();
    if (bootstrap) {
        for (int i = 0; i < config->bootstrap_peer_count; i++) {
            cJSON_AddItemToArray(bootstrap, cJSON_CreateString(config->bootstrap_peers[i]));
        }
        cJSON_AddItemToObject(root, "bootstrap_peers", bootstrap);
    }

    cJSON_AddNumberToObject(root, "wg_peers_updated_at",
                            (double)config->wg_peers_updated_at);
    cJSON *peers = cJSON_CreateArray();
    if (peers) {
        for (int i = 0; i < config->wg_peer_count; i++) {
            cJSON *peer = peer_to_json(&config->wg_peers[i]);
            if (peer) cJSON_AddItemToArray(peers, peer);
        }
        cJSON_AddItemToObject(root, "wg_peers", peers);
    }
    junknas_config_unlock(config);

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) {
        send_status(fd, 500, "Error");
        return;
    }
    send_json(fd, 200, printed);
    free(printed);
}

static const char *status_label(int status) {
    if (status > 0) return "central";
    if (status == 0) return "dead_end";
    return "unknown";
}

static void respond_mesh_status(int fd, junknas_config_t *config) {
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        send_status(fd, 500, "Error");
        return;
    }

    junknas_config_lock(config);
    int bootstrap_count = config->bootstrap_peer_count;
    int wg_count = config->wg_peer_count;
    int any_reachable = 0;
    for (int i = 0; i < bootstrap_count; i++) {
        if (config->bootstrap_peer_status[i] == 1) {
            any_reachable = 1;
            break;
        }
    }
    if (!any_reachable) {
        for (int i = 0; i < wg_count; i++) {
            if (config->wg_peer_status[i] == 1) {
                any_reachable = 1;
                break;
            }
        }
    }

    if (bootstrap_count == 0 && wg_count == 0) {
        cJSON_AddStringToObject(root, "role", "standalone");
    } else if (any_reachable) {
        cJSON_AddStringToObject(root, "role", "central");
    } else {
        cJSON_AddStringToObject(root, "role", "dead_end");
    }

    cJSON *bootstrap = cJSON_CreateArray();
    if (bootstrap) {
        for (int i = 0; i < bootstrap_count; i++) {
            cJSON *entry = cJSON_CreateObject();
            if (!entry) continue;
            cJSON_AddStringToObject(entry, "endpoint", config->bootstrap_peers[i]);
            cJSON_AddStringToObject(entry, "status", status_label(config->bootstrap_peer_status[i]));
            cJSON_AddItemToArray(bootstrap, entry);
        }
        cJSON_AddItemToObject(root, "bootstrap_peers", bootstrap);
    }

    cJSON *wg = cJSON_CreateArray();
    if (wg) {
        for (int i = 0; i < wg_count; i++) {
            cJSON *entry = cJSON_CreateObject();
            if (!entry) continue;
            cJSON_AddStringToObject(entry, "public_key", config->wg_peers[i].public_key);
            cJSON_AddStringToObject(entry, "wg_ip", config->wg_peers[i].wg_ip);
            cJSON_AddNumberToObject(entry, "web_port",
                                    (double)(config->wg_peers[i].web_port ? config->wg_peers[i].web_port
                                                                          : config->web_port));
            cJSON_AddStringToObject(entry, "status", status_label(config->wg_peer_status[i]));
            cJSON_AddItemToArray(wg, entry);
        }
        cJSON_AddItemToObject(root, "wg_peers", wg);
    }
    junknas_config_unlock(config);

    char *printed = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!printed) {
        send_status(fd, 500, "Error");
        return;
    }
    send_json(fd, 200, printed);
    free(printed);
}

static void respond_mesh_ui(int fd) {
    send_html_header(fd, "junkNAS mesh");
    send_all(fd,
             "<style>"
             "body{font-family:Arial,sans-serif;margin:20px;color:#222;}"
             "h1{margin-bottom:4px;} .status{padding:8px 12px;border-radius:6px;margin:10px 0;}"
             ".status.central{background:#e6f7ec;color:#126b2d;}"
             ".status.dead_end{background:#ffe8e8;color:#a60000;}"
             ".status.standalone{background:#eef2ff;color:#1e3a8a;}"
             "table{border-collapse:collapse;width:100%;margin-top:8px;}"
             "th,td{border:1px solid #ddd;padding:6px;text-align:left;}"
             "input{width:100%;box-sizing:border-box;}"
             "textarea{width:100%;box-sizing:border-box;}"
             ".actions{margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;}"
             ".badge{display:inline-block;padding:2px 6px;border-radius:4px;background:#eee;font-size:12px;}"
             "</style>");
    send_all(fd, "<h1>junkNAS mesh settings</h1>");
    send_all(fd, "<div id=\"mesh-role\" class=\"status\">Checking mesh status…</div>");
    send_all(fd, "<section><h2>Local node</h2><div id=\"self-info\">Loading…</div></section>");
    send_all(fd, "<section><h2>Bootstrap peers</h2>"
                  "<p>One endpoint per line (host:port).</p>"
                  "<textarea id=\"bootstrap-peers\" rows=\"5\"></textarea>"
                  "<div id=\"bootstrap-status\"></div></section>");
    send_all(fd, "<section><h2>WireGuard peers</h2>"
                  "<table id=\"wg-peers\">"
                  "<thead><tr>"
                  "<th>Public key</th><th>Preshared key</th><th>Endpoint</th>"
                  "<th>WG IP</th><th>Keepalive</th><th>Web port</th><th>Status</th><th></th>"
                  "</tr></thead><tbody></tbody></table>"
                  "<div class=\"actions\"><button id=\"add-wg\">Add peer</button></div></section>");
    send_all(fd, "<div class=\"actions\">"
                  "<button id=\"save-config\">Save changes</button>"
                  "<button id=\"sync-mesh\">Sync mesh now</button>"
                  "<span id=\"save-status\"></span>"
                  "</div>");
    send_all(fd,
             "<script>"
             "const wgPeers = [];"
             "const statusMap = {bootstrap:[], wg:[]};"
             "const escapeHtml = (text) => text.replace(/[&<>\"']/g, (c) => ({\"&\":\"&amp;\",\"<\":\"&lt;\",\">\":\"&gt;\",\"\\\"\":\"&quot;\",\"'\":\"&#39;\"}[c]));"
             "function renderWgPeers(){"
             "const tbody=document.querySelector('#wg-peers tbody');"
             "tbody.innerHTML='';"
             "wgPeers.forEach((peer,index)=>{"
             "const row=document.createElement('tr');"
             "const status=statusMap.wg[index]||'unknown';"
             "row.innerHTML=`"
             "<td><input data-field='public_key' value='${escapeHtml(peer.public_key||'')}'></td>"
             "<td><input data-field='preshared_key' value='${escapeHtml(peer.preshared_key||'')}'></td>"
             "<td><input data-field='endpoint' value='${escapeHtml(peer.endpoint||'')}'></td>"
             "<td><input data-field='wg_ip' value='${escapeHtml(peer.wg_ip||'')}'></td>"
             "<td><input data-field='persistent_keepalive' value='${escapeHtml(String(peer.persistent_keepalive||''))}'></td>"
             "<td><input data-field='web_port' value='${escapeHtml(String(peer.web_port||''))}'></td>"
             "<td><span class='badge'>${escapeHtml(status)}</span></td>"
             "<td><button data-action='remove'>Remove</button></td>`;"
             "row.querySelector('[data-action=\"remove\"]').addEventListener('click',()=>{"
             "wgPeers.splice(index,1);"
             "renderWgPeers();"
             "});"
             "tbody.appendChild(row);"
             "});"
             "}"
             "async function loadConfig(){"
             "const res=await fetch('/mesh/config');"
             "const data=await res.json();"
             "document.getElementById('bootstrap-peers').value=(data.bootstrap_peers||[]).join('\\n');"
             "const self=data.self||{};"
             "document.getElementById('self-info').innerHTML=`"
             "<div><strong>Public key:</strong> ${escapeHtml(self.public_key||'')}</div>"
             "<div><strong>WG IP:</strong> ${escapeHtml(self.wg_ip||'')}</div>"
             "<div><strong>Endpoint:</strong> ${escapeHtml(self.endpoint||'')}</div>"
             "<div><strong>WireGuard port:</strong> ${escapeHtml(String(self.listen_port||''))}</div>"
             "<div><strong>Web port:</strong> ${escapeHtml(String(self.web_port||''))}</div>`;"
             "wgPeers.length=0;"
             "(data.wg_peers||[]).forEach(peer=>wgPeers.push(peer));"
             "await loadStatus();"
             "renderWgPeers();"
             "}"
             "async function loadStatus(){"
             "const res=await fetch('/mesh/status');"
             "const data=await res.json();"
             "const role=data.role||'unknown';"
             "const statusBox=document.getElementById('mesh-role');"
             "statusBox.className='status '+role;"
             "if(role==='dead_end'){"
             "statusBox.textContent='This node is a dead end (no reachable peers).';"
             "}else if(role==='central'){"
             "statusBox.textContent='This node is central (reachable peers detected).';"
             "}else if(role==='standalone'){"
             "statusBox.textContent='Standalone mesh (no peers configured).';"
             "}else{"
             "statusBox.textContent='Mesh status unavailable.';"
             "}"
             "statusMap.bootstrap=(data.bootstrap_peers||[]).map(p=>p.status);"
             "statusMap.wg=(data.wg_peers||[]).map(p=>p.status);"
             "const bootstrapList=(data.bootstrap_peers||[]).map(p=>`<div><span class='badge'>${escapeHtml(p.status||'unknown')}</span> ${escapeHtml(p.endpoint||'')}</div>`).join('');"
             "document.getElementById('bootstrap-status').innerHTML=bootstrapList||'<em>No bootstrap peers.</em>';"
             "}"
             "document.getElementById('add-wg').addEventListener('click',()=>{"
             "wgPeers.push({public_key:'',preshared_key:'',endpoint:'',wg_ip:'',persistent_keepalive:0,web_port:0});"
             "renderWgPeers();"
             "});"
             "document.getElementById('save-config').addEventListener('click',async()=>{"
             "const bootstrap=document.getElementById('bootstrap-peers').value.split('\\n').map(v=>v.trim()).filter(Boolean);"
             "const peers=[];"
             "document.querySelectorAll('#wg-peers tbody tr').forEach(row=>{"
             "const get=(field)=>row.querySelector(`[data-field='${field}']`).value.trim();"
             "const peer={"
             "public_key:get('public_key'),"
             "preshared_key:get('preshared_key'),"
             "endpoint:get('endpoint'),"
             "wg_ip:get('wg_ip'),"
             "persistent_keepalive:parseInt(get('persistent_keepalive')||'0',10)||0,"
             "web_port:parseInt(get('web_port')||'0',10)||0"
             "};"
             "if(peer.public_key || peer.wg_ip){peers.push(peer);}"
             "});"
             "const res=await fetch('/mesh/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bootstrap_peers:bootstrap,wg_peers:peers})});"
             "const msg=document.getElementById('save-status');"
             "if(res.ok){"
             "msg.textContent='Saved.';"
             "await loadConfig();"
             "}else{"
             "msg.textContent='Save failed.';"
             "}"
             "});"
             "document.getElementById('sync-mesh').addEventListener('click',async()=>{"
             "const res=await fetch('/mesh/sync',{method:'POST'});"
             "const msg=document.getElementById('save-status');"
             "if(res.ok){msg.textContent='Sync started.';}else{msg.textContent='Sync failed.';}"
             "await loadStatus();"
             "});"
             "loadConfig();"
             "</script>");
    send_html_footer(fd);
}

static int merge_mesh_payload(junknas_config_t *config, const char *payload) {
    if (!payload) return -1;
    cJSON *root = cJSON_Parse(payload);
    if (!root) return -1;

    int peers_changed = 0;
    int mounts_changed = 0;
    time_t now = time(NULL);

    junknas_config_lock(config);
    const char *local_pub = config->wg.public_key;

    cJSON *self = cJSON_GetObjectItemCaseSensitive(root, "self");
    if (cJSON_IsObject(self)) {
        junknas_wg_peer_t peer = {0};
        if (parse_peer_json(self, &peer) == 0) {
            if (local_pub[0] == '\0' || strcmp(local_pub, peer.public_key) != 0) {
                int rc = junknas_config_upsert_wg_peer(config, &peer);
                if (rc == 1) peers_changed = 1;
            }
        }
    }

    cJSON *peers = cJSON_GetObjectItemCaseSensitive(root, "peers");
    if (cJSON_IsArray(peers)) {
        int n = cJSON_GetArraySize(peers);
        for (int i = 0; i < n; i++) {
            cJSON *entry = cJSON_GetArrayItem(peers, i);
            junknas_wg_peer_t peer = {0};
            if (parse_peer_json(entry, &peer) != 0) continue;
            if (local_pub[0] != '\0' && strcmp(local_pub, peer.public_key) == 0) continue;
            int rc = junknas_config_upsert_wg_peer(config, &peer);
            if (rc == 1) peers_changed = 1;
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
            mounts_changed = 1;
        }
    }

    if (peers_changed) {
        config->wg_peers_updated_at = (uint64_t)now;
    }
    if (peers_changed || mounts_changed) {
        (void)junknas_config_save(config, config->config_file_path);
    }
    junknas_config_unlock(config);

    cJSON_Delete(root);
    return (peers_changed || mounts_changed) ? 1 : 0;
}

static int update_mesh_config(junknas_config_t *config, const char *payload) {
    if (!payload) return -1;
    cJSON *root = cJSON_Parse(payload);
    if (!root) return -1;

    junknas_wg_peer_t peers[MAX_WG_PEERS];
    int peer_count = 0;

    cJSON *peer_arr = cJSON_GetObjectItemCaseSensitive(root, "wg_peers");
    if (cJSON_IsArray(peer_arr)) {
        int n = cJSON_GetArraySize(peer_arr);
        for (int i = 0; i < n && peer_count < MAX_WG_PEERS; i++) {
            cJSON *entry = cJSON_GetArrayItem(peer_arr, i);
            junknas_wg_peer_t peer = {0};
            if (parse_peer_json(entry, &peer) == 0) {
                peers[peer_count++] = peer;
            }
        }
    }

    char bootstrap[MAX_BOOTSTRAP_PEERS][MAX_ENDPOINT_LEN];
    int bootstrap_count = 0;
    cJSON *bootstrap_arr = cJSON_GetObjectItemCaseSensitive(root, "bootstrap_peers");
    if (cJSON_IsArray(bootstrap_arr)) {
        int n = cJSON_GetArraySize(bootstrap_arr);
        for (int i = 0; i < n && bootstrap_count < MAX_BOOTSTRAP_PEERS; i++) {
            cJSON *entry = cJSON_GetArrayItem(bootstrap_arr, i);
            if (cJSON_IsString(entry) && entry->valuestring) {
                char host[MAX_ENDPOINT_LEN];
                uint16_t port = 0;
                if (parse_endpoint(entry->valuestring, host, sizeof(host), &port) == 0) {
                    snprintf(bootstrap[bootstrap_count], sizeof(bootstrap[bootstrap_count]),
                             "%s", entry->valuestring);
                    bootstrap_count++;
                } else {
                    cJSON_Delete(root);
                    return -1;
                }
            }
        }
    }

    time_t now = time(NULL);
    junknas_config_lock(config);
    config->bootstrap_peer_count = 0;
    for (int i = 0; i < bootstrap_count; i++) {
        snprintf(config->bootstrap_peers[config->bootstrap_peer_count],
                 sizeof(config->bootstrap_peers[config->bootstrap_peer_count]),
                 "%s", bootstrap[i]);
        config->bootstrap_peer_status[config->bootstrap_peer_count] = -1;
        config->bootstrap_peer_count++;
    }
    config->bootstrap_peers_updated_at = (uint64_t)now;

    (void)junknas_config_set_wg_peers(config, peers, peer_count);
    for (int i = 0; i < config->wg_peer_count; i++) {
        config->wg_peer_status[i] = -1;
    }
    config->wg_peers_updated_at = (uint64_t)now;
    (void)junknas_config_save(config, config->config_file_path);
    junknas_config_unlock(config);

    cJSON_Delete(root);
    return 0;
}

static int sync_mesh_with_peer(junknas_config_t *config, const char *endpoint, const char *payload) {
    char host[MAX_ENDPOINT_LEN];
    uint16_t port = 0;
    if (parse_endpoint(endpoint, host, sizeof(host), &port) != 0) return -1;

    size_t payload_len = strlen(payload);
    char request[512];
    snprintf(request, sizeof(request),
             "POST /mesh/peers HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n",
             host, payload_len);

    int status = 0;
    char *body = http_request_body(host, port, request, payload, payload_len, &status);
    if (!body) return -1;

    if (status >= 200 && status < 300) {
        if (body[0] != '\0') {
            (void)merge_mesh_payload(config, body);
        }
        free(body);
        return 0;
    }

    free(body);
    return -1;
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
    send_all(fd, "<p><a href=\"/mesh/ui\">Mesh settings</a></p>");
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

    if (strcmp(path, "/mesh/peers") == 0) {
        respond_mesh_state(conn->fd, conn->config);
        return;
    }

    if (strcmp(path, "/mesh/config") == 0) {
        respond_mesh_config(conn->fd, conn->config);
        return;
    }

    if (strcmp(path, "/mesh/status") == 0) {
        respond_mesh_status(conn->fd, conn->config);
        return;
    }

    if (strcmp(path, "/mesh/ui") == 0 || strcmp(path, "/mesh") == 0) {
        respond_mesh_ui(conn->fd);
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
        if (strcmp(path, "/mesh/peers") == 0) {
            int updated = merge_mesh_payload(conn->config, body);
            if (updated >= 0) {
                respond_mesh_state(conn->fd, conn->config);
            } else {
                send_status(conn->fd, 400, "Bad Request");
            }
            return;
        }
        if (strcmp(path, "/mesh/config") == 0) {
            if (update_mesh_config(conn->config, body) == 0) {
                respond_mesh_config(conn->fd, conn->config);
            } else {
                send_status(conn->fd, 400, "Bad Request");
            }
            return;
        }
        if (strcmp(path, "/mesh/sync") == 0) {
            cJSON *payload_json = build_mesh_state_json(conn->config);
            if (!payload_json) {
                send_status(conn->fd, 500, "Error");
                return;
            }
            char *payload = cJSON_PrintUnformatted(payload_json);
            cJSON_Delete(payload_json);
            if (!payload) {
                send_status(conn->fd, 500, "Error");
                return;
            }

            junknas_config_lock(conn->config);
            int bootstrap_count = conn->config->bootstrap_peer_count;
            char bootstrap[MAX_BOOTSTRAP_PEERS][MAX_ENDPOINT_LEN];
            for (int i = 0; i < bootstrap_count; i++) {
                snprintf(bootstrap[i], sizeof(bootstrap[i]), "%s", conn->config->bootstrap_peers[i]);
            }
            int wg_count = conn->config->wg_peer_count;
            junknas_wg_peer_t wg_peers[MAX_WG_PEERS];
            if (wg_count > MAX_WG_PEERS) wg_count = MAX_WG_PEERS;
            for (int i = 0; i < wg_count; i++) {
                wg_peers[i] = conn->config->wg_peers[i];
            }
            uint16_t default_web_port = conn->config->web_port;
            junknas_config_unlock(conn->config);

            int synced = 0;
            for (int i = 0; i < bootstrap_count; i++) {
                int rc = sync_mesh_with_peer(conn->config, bootstrap[i], payload);
                junknas_config_lock(conn->config);
                conn->config->bootstrap_peer_status[i] = (rc == 0) ? 1 : 0;
                junknas_config_unlock(conn->config);
                if (rc == 0) synced++;
            }

            for (int i = 0; i < wg_count; i++) {
                uint16_t web_port = wg_peers[i].web_port ? wg_peers[i].web_port : default_web_port;
                char endpoint[MAX_ENDPOINT_LEN];
                snprintf(endpoint, sizeof(endpoint), "%s:%u", wg_peers[i].wg_ip, web_port);
                int rc = sync_mesh_with_peer(conn->config, endpoint, payload);
                junknas_config_lock(conn->config);
                conn->config->wg_peer_status[i] = (rc == 0) ? 1 : 0;
                junknas_config_unlock(conn->config);
                if (rc == 0) synced++;
            }

            free(payload);
            char response[128];
            snprintf(response, sizeof(response), "{\"synced\":%d}", synced);
            send_json(conn->fd, 200, response);
            return;
        }
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
    if (!server) {
        web_log_verbose(config, "web: failed to allocate server");
        return NULL;
    }

    server->config = config;
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        web_log_verbose(config, "web: failed to create socket");
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
        web_log_verbose(config, "web: bind failed on port %u", config->web_port);
        close(server->fd);
        free(server);
        return NULL;
    }

    if (listen(server->fd, WEB_BACKLOG) != 0) {
        web_log_verbose(config, "web: listen failed on port %u", config->web_port);
        close(server->fd);
        free(server);
        return NULL;
    }

    if (pthread_create(&server->thread, NULL, server_thread, server) != 0) {
        web_log_verbose(config, "web: failed to start web server thread");
        close(server->fd);
        free(server);
        return NULL;
    }

    web_log_verbose(config, "web: server listening on port %u", config->web_port);
    return server;
}

void junknas_web_server_stop(junknas_web_server_t *server) {
    if (!server) return;
    server->stop = 1;
    if (server->fd >= 0) close(server->fd);
    pthread_join(server->thread, NULL);
    free(server);
}
