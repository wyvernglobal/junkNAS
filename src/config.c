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
 *   ],
 *   "bootstrap_peers_updated_at": 1714757902
 * }
 */

#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <ctype.h>
#include <cjson/cJSON.h>

/* ------------------------------ Helpers ---------------------------------- */

typedef uint8_t jn_wg_key[32];
typedef char jn_wg_key_b64_string[((sizeof(jn_wg_key) + 2) / 3) * 4 + 1];

static void jn_wg_encode_base64(char dest[static 4], const uint8_t src[static 3]) {
    const uint8_t input[] = {
        (src[0] >> 2) & 63,
        ((src[0] << 4) | (src[1] >> 4)) & 63,
        ((src[1] << 2) | (src[2] >> 6)) & 63,
        src[2] & 63
    };

    for (unsigned int i = 0; i < 4; ++i) {
        dest[i] = input[i] + 'A'
                  + (((25 - input[i]) >> 8) & 6)
                  - (((51 - input[i]) >> 8) & 75)
                  - (((61 - input[i]) >> 8) & 15)
                  + (((62 - input[i]) >> 8) & 3);
    }
}

static void jn_wg_key_to_base64(jn_wg_key_b64_string base64, const jn_wg_key key) {
    unsigned int i;

    for (i = 0; i < 32 / 3; ++i) {
        jn_wg_encode_base64(&base64[i * 4], &key[i * 3]);
    }
    jn_wg_encode_base64(&base64[i * 4], (const uint8_t[]){ key[i * 3 + 0], key[i * 3 + 1], 0 });
    base64[sizeof(jn_wg_key_b64_string) - 2] = '=';
    base64[sizeof(jn_wg_key_b64_string) - 1] = '\0';
}

static int jn_wg_decode_base64(const char src[static 4]) {
    int val = 0;

    for (unsigned int i = 0; i < 4; ++i) {
        val |= (-1
                + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64))
                + ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70))
                + ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5))
                + ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63)
                + ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64)
            ) << (18 - 6 * i);
    }
    return val;
}

static int jn_wg_key_from_base64(jn_wg_key key, const jn_wg_key_b64_string base64) {
    unsigned int i;
    int val;
    volatile uint8_t ret = 0;

    if (strlen(base64) != sizeof(jn_wg_key_b64_string) - 1 ||
        base64[sizeof(jn_wg_key_b64_string) - 2] != '=') {
        errno = EINVAL;
        goto out;
    }

    for (i = 0; i < 32 / 3; ++i) {
        val = jn_wg_decode_base64(&base64[i * 4]);
        ret |= (uint32_t)val >> 31;
        key[i * 3 + 0] = (val >> 16) & 0xff;
        key[i * 3 + 1] = (val >> 8) & 0xff;
        key[i * 3 + 2] = val & 0xff;
    }
    val = jn_wg_decode_base64((const char[]){ base64[i * 4 + 0], base64[i * 4 + 1], base64[i * 4 + 2], 'A' });
    ret |= ((uint32_t)val >> 31) | (val & 0xff);
    key[i * 3 + 0] = (val >> 16) & 0xff;
    key[i * 3 + 1] = (val >> 8) & 0xff;
    errno = EINVAL & ~((ret - 1) >> 8);
out:
    return -errno;
}

typedef int64_t jn_wg_fe[16];

static __attribute__((noinline)) void jn_wg_memzero_explicit(void *s, size_t count) {
    memset(s, 0, count);
    __asm__ __volatile__("" : : "r"(s) : "memory");
}

static void jn_wg_carry(jn_wg_fe o) {
    for (int i = 0; i < 16; ++i) {
        o[(i + 1) % 16] += (i == 15 ? 38 : 1) * (o[i] >> 16);
        o[i] &= 0xffff;
    }
}

static void jn_wg_cswap(jn_wg_fe p, jn_wg_fe q, int b) {
    int64_t t;
    int64_t c = ~(b - 1);

    for (int i = 0; i < 16; ++i) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }

    jn_wg_memzero_explicit(&t, sizeof(t));
    jn_wg_memzero_explicit(&c, sizeof(c));
    jn_wg_memzero_explicit(&b, sizeof(b));
}

static void jn_wg_pack(uint8_t *o, const jn_wg_fe n) {
    int b;
    jn_wg_fe m;
    jn_wg_fe t;

    memcpy(t, n, sizeof(t));
    jn_wg_carry(t);
    jn_wg_carry(t);
    jn_wg_carry(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        jn_wg_cswap(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = t[i] >> 8;
    }

    jn_wg_memzero_explicit(m, sizeof(m));
    jn_wg_memzero_explicit(t, sizeof(t));
    jn_wg_memzero_explicit(&b, sizeof(b));
}

static void jn_wg_add(jn_wg_fe o, const jn_wg_fe a, const jn_wg_fe b) {
    for (int i = 0; i < 16; ++i) {
        o[i] = a[i] + b[i];
    }
}

static void jn_wg_subtract(jn_wg_fe o, const jn_wg_fe a, const jn_wg_fe b) {
    for (int i = 0; i < 16; ++i) {
        o[i] = a[i] - b[i];
    }
}

static void jn_wg_multmod(jn_wg_fe o, const jn_wg_fe a, const jn_wg_fe b) {
    int64_t t[31] = { 0 };

    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; ++i) {
        t[i] += 38 * t[i + 16];
    }
    memcpy(o, t, sizeof(jn_wg_fe));
    jn_wg_carry(o);
    jn_wg_carry(o);

    jn_wg_memzero_explicit(t, sizeof(t));
}

static void jn_wg_invert(jn_wg_fe o, const jn_wg_fe i) {
    jn_wg_fe c;

    memcpy(c, i, sizeof(c));
    for (int a = 253; a >= 0; --a) {
        jn_wg_multmod(c, c, c);
        if (a != 2 && a != 4) {
            jn_wg_multmod(c, c, i);
        }
    }
    memcpy(o, c, sizeof(jn_wg_fe));

    jn_wg_memzero_explicit(c, sizeof(c));
}

static void jn_wg_clamp_key(uint8_t *z) {
    z[31] = (z[31] & 127) | 64;
    z[0] &= 248;
}

static void jn_wg_generate_public_key(jn_wg_key public_key, const jn_wg_key private_key) {
    int r;
    uint8_t z[32];
    jn_wg_fe a = { 1 }, b = { 9 }, c = { 0 }, d = { 1 }, e, f;

    memcpy(z, private_key, sizeof(z));
    jn_wg_clamp_key(z);

    for (int i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        jn_wg_cswap(a, b, r);
        jn_wg_cswap(c, d, r);
        jn_wg_add(e, a, c);
        jn_wg_subtract(a, a, c);
        jn_wg_add(c, b, d);
        jn_wg_subtract(b, b, d);
        jn_wg_multmod(d, e, e);
        jn_wg_multmod(f, a, a);
        jn_wg_multmod(a, c, a);
        jn_wg_multmod(c, b, e);
        jn_wg_add(e, a, c);
        jn_wg_subtract(a, a, c);
        jn_wg_multmod(b, a, a);
        jn_wg_subtract(c, d, f);
        jn_wg_multmod(a, c, (const jn_wg_fe){ 0xdb41, 1 });
        jn_wg_add(a, a, d);
        jn_wg_multmod(c, c, a);
        jn_wg_multmod(a, d, f);
        jn_wg_multmod(d, b, (const jn_wg_fe){ 9 });
        jn_wg_multmod(b, e, e);
        jn_wg_cswap(a, b, r);
        jn_wg_cswap(c, d, r);
    }
    jn_wg_invert(c, c);
    jn_wg_multmod(a, a, c);
    jn_wg_pack(public_key, a);

    jn_wg_memzero_explicit(&r, sizeof(r));
    jn_wg_memzero_explicit(z, sizeof(z));
    jn_wg_memzero_explicit(a, sizeof(a));
    jn_wg_memzero_explicit(b, sizeof(b));
    jn_wg_memzero_explicit(c, sizeof(c));
    jn_wg_memzero_explicit(d, sizeof(d));
    jn_wg_memzero_explicit(e, sizeof(e));
    jn_wg_memzero_explicit(f, sizeof(f));
}

static void jn_wg_generate_preshared_key(jn_wg_key preshared_key) {
    ssize_t ret;
    size_t i;
    int fd;
#if defined(__OpenBSD__) || (defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12) || \
    (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
    if (!getentropy(preshared_key, sizeof(jn_wg_key))) {
        return;
    }
#endif
#if defined(__NR_getrandom) && defined(__linux__)
    if (syscall(__NR_getrandom, preshared_key, sizeof(jn_wg_key), 0) == sizeof(jn_wg_key)) {
        return;
    }
#endif
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return;
    }
    for (i = 0; i < sizeof(jn_wg_key); i += (size_t)ret) {
        ret = read(fd, preshared_key + i, sizeof(jn_wg_key) - i);
        if (ret <= 0) {
            close(fd);
            return;
        }
    }
    close(fd);
}

static void jn_wg_generate_private_key(jn_wg_key private_key) {
    jn_wg_generate_preshared_key(private_key);
    jn_wg_clamp_key(private_key);
}

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
        return safe_strcpy(out, out_len, "private.key");
    }

    const char *slash = strrchr(config->config_file_path, '/');
    if (!slash) {
        return safe_strcpy(out, out_len, "private.key");
    }

    size_t dir_len = (size_t)(slash - config->config_file_path);
    if (dir_len == 0) {
        return snprintf(out, out_len, "/private.key") >= (int)out_len ? -1 : 0;
    }

    return snprintf(out, out_len, "%.*s/private.key", (int)dir_len, config->config_file_path) >= (int)out_len
               ? -1
               : 0;
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

int junknas_config_add_data_mount_point(junknas_config_t *config, const char *mount_point) {
    if (!config || !mount_point) return -1;

    if (config->data_mount_point_count < 0) config->data_mount_point_count = 0;

    if (config->data_mount_point_count >= MAX_DATA_MOUNT_POINTS) {
        return -1;
    }

    int idx = config->data_mount_point_count;

    (void)safe_strcpy(config->data_mount_points[idx], MAX_PATH_LEN, mount_point);

    config->data_mount_point_count++;
    return 0;
}

void junknas_config_cleanup(junknas_config_t *config) {
    /* Currently everything is fixed-size buffers, so nothing to free.
     */
    if (config) {
        pthread_mutex_destroy(&config->lock);
    }
}

void junknas_config_lock(junknas_config_t *config) {
    if (!config) return;
    pthread_mutex_lock(&config->lock);
}

void junknas_config_unlock(junknas_config_t *config) {
    if (!config) return;
    pthread_mutex_unlock(&config->lock);
}

static int wg_peer_equal(const junknas_wg_peer_t *a, const junknas_wg_peer_t *b) {
    if (!a || !b) return 0;
    if (strcmp(a->public_key, b->public_key) != 0) return 0;
    if (strcmp(a->preshared_key, b->preshared_key) != 0) return 0;
    if (strcmp(a->endpoint, b->endpoint) != 0) return 0;
    if (strcmp(a->wg_ip, b->wg_ip) != 0) return 0;
    if (a->persistent_keepalive != b->persistent_keepalive) return 0;
    if (a->web_port != b->web_port) return 0;
    return 1;
}

int junknas_config_upsert_wg_peer(junknas_config_t *config, const junknas_wg_peer_t *peer) {
    if (!config || !peer || peer->public_key[0] == '\0') return -1;

    for (int i = 0; i < config->wg_peer_count; i++) {
        if (strcmp(config->wg_peers[i].public_key, peer->public_key) == 0) {
            if (wg_peer_equal(&config->wg_peers[i], peer)) return 0;
            config->wg_peers[i] = *peer;
            return 1;
        }
    }

    if (config->wg_peer_count >= MAX_WG_PEERS) {
        return -1;
    }

    config->wg_peers[config->wg_peer_count++] = *peer;
    return 1;
}

int junknas_config_set_wg_peers(junknas_config_t *config, const junknas_wg_peer_t *peers, int count) {
    if (!config || !peers || count < 0 || count > MAX_WG_PEERS) return -1;

    config->wg_peer_count = 0;
    for (int i = 0; i < count; i++) {
        if (peers[i].public_key[0] == '\0') continue;
        config->wg_peers[config->wg_peer_count++] = peers[i];
    }
    return 0;
}

static int g_startup_verbose = 0;

void junknas_config_set_startup_verbose(int verbose) {
    g_startup_verbose = verbose ? 1 : 0;
}

static int config_should_log_verbose(const junknas_config_t *config) {
    return (config && config->verbose) || g_startup_verbose;
}

static void config_log_verbose(const junknas_config_t *config, const char *fmt, ...) {
    if (!config_should_log_verbose(config)) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

static void set_defaults(junknas_config_t *config) {
    /* This function sets the full config structure to known defaults. */
    memset(config, 0, sizeof(*config));
    pthread_mutex_init(&config->lock, NULL);

    /* Storage */
    (void)safe_strcpy(config->storage_size, sizeof(config->storage_size), DEFAULT_STORAGE_SIZE);
    config->max_storage_bytes = junknas_parse_storage_size(DEFAULT_STORAGE_SIZE);

    /* Paths */
    (void)safe_strcpy(config->data_dir, sizeof(config->data_dir), DEFAULT_DATA_DIR);
    (void)safe_strcpy(config->data_dirs[0], sizeof(config->data_dirs[0]), DEFAULT_DATA_DIR);
    config->data_dir_count = 1;
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
    config->wg.endpoint[0] = '\0';
    config->wg.listen_port = (uint16_t)DEFAULT_WG_PORT;
    config->wg.mtu = 0;

    /* Bootstrap list */
    config->bootstrap_peer_count = 0;
    config->bootstrap_peers_updated_at = 0;

    /* WireGuard peers */
    config->wg_peer_count = 0;
    config->wg_peers_updated_at = 0;

    /* Mesh mount points */
    config->data_mount_point_count = 0;
    config->data_mount_points_updated_at = 0;
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
    if (config->data_dir_count == 0 || config->data_dir_count > MAX_DATA_DIRS) return -1;
    for (size_t i = 0; i < config->data_dir_count; i++) {
        if (config->data_dirs[i][0] == '\0') return -1;
    }
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

    if (config->data_mount_point_count < 0 || config->data_mount_point_count > MAX_DATA_MOUNT_POINTS) {
        return -1;
    }
    for (int i = 0; i < config->data_mount_point_count; i++) {
        if (config->data_mount_points[i][0] == '\0') return -1;
    }

    if (config->wg_peer_count < 0 || config->wg_peer_count > MAX_WG_PEERS) {
        return -1;
    }
    for (int i = 0; i < config->wg_peer_count; i++) {
        if (config->wg_peers[i].public_key[0] == '\0') return -1;
        if (config->wg_peers[i].wg_ip[0] == '\0') return -1;
    }

    return 0;
}

int junknas_config_ensure_wg_keys(junknas_config_t *config) {
    if (!config) return -1;

    char private_key_path[MAX_PATH_LEN];
    if (build_private_key_path(config, private_key_path, sizeof(private_key_path)) != 0) {
        config_log_verbose(config, "config: failed to build WireGuard key path");
        return -1;
    }

    config_log_verbose(config, "config: ensuring WireGuard keys in %s", private_key_path);
    junknas_config_lock(config);

    jn_wg_key private_key;
    jn_wg_key public_key;
    jn_wg_key_b64_string pub_b64;
    bool have_private = false;
    bool changed = false;
    bool should_write_private = false;

    char *file_contents = NULL;
    if (read_entire_file(private_key_path, &file_contents, NULL) == 0) {
        char normalized[MAX_WG_KEY_LEN];
        if (normalize_key_string(file_contents, normalized, sizeof(normalized)) == 0 &&
            jn_wg_key_from_base64(private_key, normalized) == 0) {
            if (strcmp(config->wg.private_key, normalized) != 0) {
                (void)safe_strcpy(config->wg.private_key, sizeof(config->wg.private_key), normalized);
                changed = true;
            }
            have_private = true;
            config_log_verbose(config, "config: loaded existing WireGuard private key");
        }
    } else {
        config_log_verbose(config, "config: no private key file found at %s", private_key_path);
    }
    free(file_contents);

    if (!have_private) {
        if (config->wg.private_key[0] != '\0' &&
            jn_wg_key_from_base64(private_key, config->wg.private_key) == 0) {
            have_private = true;
        } else {
            jn_wg_key_b64_string priv_b64;
            jn_wg_generate_private_key(private_key);
            jn_wg_key_to_base64(priv_b64, private_key);
            (void)safe_strcpy(config->wg.private_key, sizeof(config->wg.private_key), priv_b64);
            changed = true;
            have_private = true;
            config_log_verbose(config, "config: generated new WireGuard private key");
        }
        should_write_private = true;
    }

    if (!have_private) {
        junknas_config_unlock(config);
        config_log_verbose(config, "config: failed to obtain WireGuard private key");
        return -1;
    }

    if (jn_wg_key_from_base64(private_key, config->wg.private_key) != 0) {
        junknas_config_unlock(config);
        config_log_verbose(config, "config: WireGuard private key is invalid");
        return -1;
    }

    jn_wg_generate_public_key(public_key, private_key);
    jn_wg_key_to_base64(pub_b64, public_key);
    if (strcmp(config->wg.public_key, pub_b64) != 0) {
        (void)safe_strcpy(config->wg.public_key, sizeof(config->wg.public_key), pub_b64);
        changed = true;
        config_log_verbose(config, "config: updated WireGuard public key");
    }

    junknas_config_unlock(config);

    if (should_write_private) {
        if (write_entire_file_atomic(private_key_path, config->wg.private_key) != 0) {
            config_log_verbose(config, "config: failed to write private key to %s", private_key_path);
            return -1;
        }
        config_log_verbose(config, "config: wrote WireGuard private key to %s", private_key_path);
    }

    if (changed) {
        config_log_verbose(config, "config: saving updated WireGuard keys to %s", config->config_file_path);
        return junknas_config_save(config, config->config_file_path);
    }

    return 0;
}

int junknas_config_load(junknas_config_t *config, const char *config_file) {
    if (!config || !config_file) return -1;

    char *json_text = NULL;
    if (read_entire_file(config_file, &json_text, NULL) != 0) {
        config_log_verbose(config, "config: failed to read %s", config_file);
        return -1;
    }

    cJSON *root = cJSON_Parse(json_text);
    free(json_text);
    json_text = NULL;

    if (!root) {
        config_log_verbose(config, "config: failed to parse JSON in %s", config_file);
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
        (void)safe_strcpy(config->data_dirs[0], sizeof(config->data_dirs[0]), config->data_dir);
        config->data_dir_count = 1;
    }

    /* data_dirs */
    cJSON *data_dirs = cJSON_GetObjectItemCaseSensitive(root, "data_dirs");
    if (cJSON_IsArray(data_dirs)) {
        config->data_dir_count = 0;
        int n = cJSON_GetArraySize(data_dirs);
        if (n > MAX_DATA_DIRS) n = MAX_DATA_DIRS;

        for (int i = 0; i < n; i++) {
            cJSON *dir = cJSON_GetArrayItem(data_dirs, i);
            if (cJSON_IsString(dir) && dir->valuestring) {
                (void)safe_strcpy(config->data_dirs[config->data_dir_count],
                                  sizeof(config->data_dirs[config->data_dir_count]),
                                  dir->valuestring);
                config->data_dir_count++;
            }
        }

        if (config->data_dir_count > 0) {
            (void)safe_strcpy(config->data_dir, sizeof(config->data_dir), config->data_dirs[0]);
        } else {
            (void)safe_strcpy(config->data_dirs[0], sizeof(config->data_dirs[0]), config->data_dir);
            config->data_dir_count = 1;
        }
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

        cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(wg, "endpoint");
        if (cJSON_IsString(endpoint) && endpoint->valuestring) {
            (void)safe_strcpy(config->wg.endpoint, sizeof(config->wg.endpoint), endpoint->valuestring);
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

    cJSON *peers_updated_at = cJSON_GetObjectItemCaseSensitive(root, "bootstrap_peers_updated_at");
    if (cJSON_IsNumber(peers_updated_at) && peers_updated_at->valuedouble >= 0) {
        config->bootstrap_peers_updated_at = (uint64_t)peers_updated_at->valuedouble;
    }

    /* data_mount_points array */
    cJSON *mounts = cJSON_GetObjectItemCaseSensitive(root, "data_mount_points");
    if (cJSON_IsArray(mounts)) {
        config->data_mount_point_count = 0;
        int n = cJSON_GetArraySize(mounts);
        if (n > MAX_DATA_MOUNT_POINTS) n = MAX_DATA_MOUNT_POINTS;

        for (int i = 0; i < n; i++) {
            cJSON *m = cJSON_GetArrayItem(mounts, i);
            if (cJSON_IsString(m) && m->valuestring) {
                (void)junknas_config_add_data_mount_point(config, m->valuestring);
            }
        }
    }

    cJSON *mounts_updated_at = cJSON_GetObjectItemCaseSensitive(root, "data_mount_points_updated_at");
    if (cJSON_IsNumber(mounts_updated_at) && mounts_updated_at->valuedouble >= 0) {
        config->data_mount_points_updated_at = (uint64_t)mounts_updated_at->valuedouble;
    }

    cJSON *wg_peers = cJSON_GetObjectItemCaseSensitive(root, "wg_peers");
    if (cJSON_IsArray(wg_peers)) {
        config->wg_peer_count = 0;
        int n = cJSON_GetArraySize(wg_peers);
        if (n > MAX_WG_PEERS) n = MAX_WG_PEERS;
        for (int i = 0; i < n; i++) {
            cJSON *p = cJSON_GetArrayItem(wg_peers, i);
            if (!cJSON_IsObject(p)) continue;
            junknas_wg_peer_t peer = {0};

            cJSON *pub = cJSON_GetObjectItemCaseSensitive(p, "public_key");
            if (cJSON_IsString(pub) && pub->valuestring) {
                (void)safe_strcpy(peer.public_key, sizeof(peer.public_key), pub->valuestring);
            }
            cJSON *psk = cJSON_GetObjectItemCaseSensitive(p, "preshared_key");
            if (cJSON_IsString(psk) && psk->valuestring) {
                (void)safe_strcpy(peer.preshared_key, sizeof(peer.preshared_key), psk->valuestring);
            }
            cJSON *endpoint = cJSON_GetObjectItemCaseSensitive(p, "endpoint");
            if (cJSON_IsString(endpoint) && endpoint->valuestring) {
                (void)safe_strcpy(peer.endpoint, sizeof(peer.endpoint), endpoint->valuestring);
            }
            cJSON *wg_ip = cJSON_GetObjectItemCaseSensitive(p, "wg_ip");
            if (cJSON_IsString(wg_ip) && wg_ip->valuestring) {
                (void)safe_strcpy(peer.wg_ip, sizeof(peer.wg_ip), wg_ip->valuestring);
            }
            cJSON *keepalive = cJSON_GetObjectItemCaseSensitive(p, "persistent_keepalive");
            if (cJSON_IsNumber(keepalive) && keepalive->valuedouble >= 0) {
                peer.persistent_keepalive = (uint16_t)keepalive->valuedouble;
            }
            cJSON *web_port = cJSON_GetObjectItemCaseSensitive(p, "web_port");
            if (cJSON_IsNumber(web_port) && web_port->valuedouble > 0 && web_port->valuedouble < 65536) {
                peer.web_port = (uint16_t)web_port->valuedouble;
            }

            if (peer.public_key[0] != '\0' && peer.wg_ip[0] != '\0') {
                config->wg_peers[config->wg_peer_count++] = peer;
            }
        }
    }

    cJSON *wg_peers_updated_at = cJSON_GetObjectItemCaseSensitive(root, "wg_peers_updated_at");
    if (cJSON_IsNumber(wg_peers_updated_at) && wg_peers_updated_at->valuedouble >= 0) {
        config->wg_peers_updated_at = (uint64_t)wg_peers_updated_at->valuedouble;
    }

    cJSON_Delete(root);
    config_log_verbose(config, "config: loaded %s", config_file);
    return 0;
}

int junknas_config_save(const junknas_config_t *config, const char *config_file) {
    if (!config || !config_file) return -1;

    cJSON *root = cJSON_CreateObject();
    if (!root) return -1;

    /* top-level fields */
    cJSON_AddStringToObject(root, "storage_size", config->storage_size);
    cJSON_AddStringToObject(root, "data_dir", config->data_dir);
    cJSON *data_dirs_out = cJSON_CreateArray();
    if (!data_dirs_out) {
        cJSON_Delete(root);
        return -1;
    }
    cJSON_AddItemToObject(root, "data_dirs", data_dirs_out);

    size_t dir_count = (config->data_dir_count > 0) ? config->data_dir_count : 1;
    for (size_t i = 0; i < dir_count && i < MAX_DATA_DIRS; i++) {
        const char *dir = (config->data_dir_count > 0) ? config->data_dirs[i] : config->data_dir;
        cJSON_AddItemToArray(data_dirs_out, cJSON_CreateString(dir));
    }
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
    cJSON_AddStringToObject(wg, "endpoint", config->wg.endpoint);
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
    cJSON_AddNumberToObject(root, "bootstrap_peers_updated_at",
                            (double)config->bootstrap_peers_updated_at);

    /* data mount points */
    cJSON *mount_arr = cJSON_CreateArray();
    if (!mount_arr) {
        cJSON_Delete(root);
        return -1;
    }
    cJSON_AddItemToObject(root, "data_mount_points", mount_arr);
    for (int i = 0; i < config->data_mount_point_count && i < MAX_DATA_MOUNT_POINTS; i++) {
        cJSON_AddItemToArray(mount_arr, cJSON_CreateString(config->data_mount_points[i]));
    }
    cJSON_AddNumberToObject(root, "data_mount_points_updated_at",
                            (double)config->data_mount_points_updated_at);

    /* WireGuard peers */
    cJSON *wg_arr = cJSON_CreateArray();
    if (!wg_arr) {
        cJSON_Delete(root);
        return -1;
    }
    cJSON_AddItemToObject(root, "wg_peers", wg_arr);
    for (int i = 0; i < config->wg_peer_count && i < MAX_WG_PEERS; i++) {
        cJSON *peer = cJSON_CreateObject();
        if (!peer) {
            cJSON_Delete(root);
            return -1;
        }
        cJSON_AddStringToObject(peer, "public_key", config->wg_peers[i].public_key);
        cJSON_AddStringToObject(peer, "preshared_key", config->wg_peers[i].preshared_key);
        cJSON_AddStringToObject(peer, "endpoint", config->wg_peers[i].endpoint);
        cJSON_AddStringToObject(peer, "wg_ip", config->wg_peers[i].wg_ip);
        cJSON_AddNumberToObject(peer, "persistent_keepalive",
                                (double)config->wg_peers[i].persistent_keepalive);
        cJSON_AddNumberToObject(peer, "web_port", (double)config->wg_peers[i].web_port);
        cJSON_AddItemToArray(wg_arr, peer);
    }
    cJSON_AddNumberToObject(root, "wg_peers_updated_at",
                            (double)config->wg_peers_updated_at);

    /* Render JSON */
    char *printed = cJSON_Print(root);
    cJSON_Delete(root);

    if (!printed) return -1;

    int rc = write_entire_file_atomic(config_file, printed);
    free(printed);
    if (rc != 0) {
        config_log_verbose(config, "config: failed to write %s", config_file);
    } else {
        config_log_verbose(config, "config: wrote %s", config_file);
    }
    return (rc == 0) ? 0 : -1;
}

int junknas_config_init(junknas_config_t *config, const char *config_file) {
    if (!config) return -1;

    /* Start with defaults */
    set_defaults(config);
    config_log_verbose(config, "config: defaults loaded");

    /* If config_file provided, use it and also store the path */
    if (config_file && config_file[0] != '\0') {
        (void)safe_strcpy(config->config_file_path, sizeof(config->config_file_path), config_file);
        config_log_verbose(config, "config: loading config file %s", config_file);

        /* Loading is optional: missing file should not necessarily be fatal
         * BUT: right now we treat load failure as an error to make debugging easy.
         * We can change later to "ignore ENOENT".
         */
        if (junknas_config_load(config, config_file) != 0) {
            config_log_verbose(config, "config: failed to load %s", config_file);
            return -1;
        }
    }

    config_log_verbose(config, "config: ensuring WireGuard keys");
    if (junknas_config_ensure_wg_keys(config) != 0) {
        config_log_verbose(config, "config: WireGuard key setup failed");
        return -1;
    }

    /* Validate final config */
    if (junknas_config_validate(config) != 0) {
        config_log_verbose(config, "config: validation failed");
        return -1;
    }
    config_log_verbose(config, "config: validation succeeded");
    return 0;
}
