
#define FUSE_USE_VERSION 35

/*
 * junkNAS - FUSE filesystem (content-addressed chunk store + integrity + quota)
 *
 * USER VIEW (FUSE):
 *   /mount/foo.txt
 *
 * ON DISK (backing dir = cfg->data_dir):
 *   /data/foo.txt.__jnkmeta                 (manifest: size + chunk hashes)
 *   /data/.jnk/chunks/sha256/ab/<hash>      (content-addressed chunks)
 *
 * Key properties:
 *   - Fixed chunk size (1 MiB) except final chunk may be shorter.
 *   - File meta lists chunk hashes by index.
 *   - Reads verify chunk integrity by hashing and comparing to meta.
 *   - Writes build updated chunks, hash, then store by hash.
 *   - Quota enforced as total bytes stored in chunk store directory.
 *
 * Security / attack surface:
 *   - No symlinks, no xattrs, no chmod/chown, no device nodes, no ioctls.
 *   - Reject any FUSE path component that ends with internal suffixes or ".jnk".
 *   - Hide internal artifacts in directory listings.
 */

#include "fuse_fs.h"
#include <fuse3/fuse.h>
#include <sys/file.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* 1 MiB chunks (tunable later) */
#define JNK_CHUNK_SIZE (1024 * 1024)

/* Internal naming */
#define META_SUFFIX   ".__jnkmeta"
#define INTERNAL_DIR  ".jnk"

/* Chunk store: <data_dir>/.jnk/chunks/sha256/ab/<hashhex> */
#define STORE_SUBDIR  ".jnk/chunks/sha256"

/* ----------------------------- SHA-256 ----------------------------------
 * Minimal SHA-256 implementation (public-domain style).
 * Good enough for integrity & content addressing.
 */

typedef struct {
    uint32_t h[8];
    uint64_t len_bits;
    uint8_t  buf[64];
    size_t   buf_len;
} sha256_ctx;

static uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_init(sha256_ctx *c) {
    c->h[0] = 0x6a09e667u; c->h[1] = 0xbb67ae85u; c->h[2] = 0x3c6ef372u; c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu; c->h[5] = 0x9b05688cu; c->h[6] = 0x1f83d9abu; c->h[7] = 0x5be0cd19u;
    c->len_bits = 0;
    c->buf_len = 0;
}

static void sha256_compress(sha256_ctx *c, const uint8_t block[64]) {
    static const uint32_t K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };

    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4+0] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8)  | ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    uint32_t a=c->h[0], b=c->h[1], d=c->h[3], e=c->h[4], f=c->h[5], g=c->h[6], h=c->h[7], cc=c->h[2];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = cc;
        cc = b;
        b = a;
        a = temp1 + temp2;
    }

    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    c->len_bits += (uint64_t)n * 8u;

    while (n > 0) {
        size_t room = 64 - c->buf_len;
        size_t take = (n < room) ? n : room;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p += take;
        n -= take;

        if (c->buf_len == 64) {
            sha256_compress(c, c->buf);
            c->buf_len = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    /* pad */
    c->buf[c->buf_len++] = 0x80;
    if (c->buf_len > 56) {
        while (c->buf_len < 64) c->buf[c->buf_len++] = 0x00;
        sha256_compress(c, c->buf);
        c->buf_len = 0;
    }
    while (c->buf_len < 56) c->buf[c->buf_len++] = 0x00;

    /* length big-endian */
    uint64_t L = c->len_bits;
    for (int i = 7; i >= 0; i--) {
        c->buf[c->buf_len++] = (uint8_t)((L >> (i*8)) & 0xffu);
    }
    sha256_compress(c, c->buf);

    for (int i = 0; i < 8; i++) {
        out[i*4+0] = (uint8_t)((c->h[i] >> 24) & 0xffu);
        out[i*4+1] = (uint8_t)((c->h[i] >> 16) & 0xffu);
        out[i*4+2] = (uint8_t)((c->h[i] >> 8) & 0xffu);
        out[i*4+3] = (uint8_t)((c->h[i]) & 0xffu);
    }
}

static void sha256_hex(const uint8_t digest[32], char hex[65]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i*2+0] = H[(digest[i] >> 4) & 0xF];
        hex[i*2+1] = H[digest[i] & 0xF];
    }
    hex[64] = '\0';
}

static void sha256_buf_hex(const void *data, size_t n, char hex[65]) {
    sha256_ctx c;
    uint8_t d[32];
    sha256_init(&c);
    sha256_update(&c, data, n);
    sha256_final(&c, d);
    sha256_hex(d, hex);
}

/* --------------------------- Internal State ---------------------------- */

typedef struct {
    char   backing_dir[MAX_PATH_LEN];
    char   store_dirs[MAX_DATA_DIRS][MAX_PATH_LEN]; /* <backing>/.jnk/chunks/sha256 */
    size_t store_dir_count;
    size_t store_rr_next;
    char   refs_dir[MAX_PATH_LEN]; /* <bakcing>/.jnk/refs */
    int    verbose;
    size_t quota_bytes;             /* 0 = unlimited */
} jnk_fuse_state_t;

/* Per-open handle */
typedef struct dirty_chunk dirty_chunk_t;
typedef struct {
    char meta_path[MAX_PATH_LEN];
    size_t size;
    size_t chunk_count;
    char **hashes;      /* array of chunk hash strings (64-hex) */
    int dirty;

  /* needed for refcount delta */
  size_t orig_size;
  size_t orig_chunk_count;
  char **orig_hashes;

  /* Staged writes:
   * We do NOT commit content-addressed chunks to disk on every small write().
   * Instead, we stage per-chunk buffers here and commit once on release().
   */
  dirty_chunk_t *dirty_chunks;
} jnk_file_handle_t;

/* Dirty chunk node: full 1 MiB chunk buffer for a given index */
struct dirty_chunk {
    size_t idx;
    uint8_t *data;              /* JNK_CHUNK_SIZE bytes */
    struct dirty_chunk *next;
};

static jnk_fuse_state_t *get_state(void) {
    return (jnk_fuse_state_t *)fuse_get_context()->private_data;
}

/* --------------------------- Path Safety ------------------------------- */

static int str_endswith(const char *s, const char *suffix) {
    size_t ls = strlen(s), lf = strlen(suffix);
    if (ls < lf) return 0;
    return memcmp(s + (ls - lf), suffix, lf) == 0;
}

/* Reject any path component that tries to use internal naming. */
static int path_is_safe_user_path(const char *path) {
    if (!path || path[0] != '/') return 0;
    if (strcmp(path, "/") == 0) return 1;

    const char *p = path + 1;
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        if (len == 0) return 0;

        char comp[NAME_MAX + 1];
        if (len > NAME_MAX) return 0;
        memcpy(comp, p, len);
        comp[len] = '\0';

        if (strcmp(comp, ".") == 0 || strcmp(comp, "..") == 0) return 0;
        if (strcmp(comp, INTERNAL_DIR) == 0) return 0;
        if (str_endswith(comp, META_SUFFIX)) return 0;

        /* Prevent sneaky internal artifacts */
        if (strstr(comp, META_SUFFIX) != NULL) return 0;

        p = slash ? slash + 1 : (p + len);
    }
    return 1;
}

/* --------------------- Backing path construction ----------------------- */

static int make_real_and_meta(const char *backing_dir, const char *path,
                              char real_path[MAX_PATH_LEN],
                              char meta_path[MAX_PATH_LEN]) {
    if (!path_is_safe_user_path(path)) return -1;

    if (strcmp(path, "/") == 0) {
        if (snprintf(real_path, MAX_PATH_LEN, "%s", backing_dir) >= MAX_PATH_LEN) return -1;
        meta_path[0] = '\0';
        return 0;
    }

    if (snprintf(real_path, MAX_PATH_LEN, "%s%s", backing_dir, path) >= MAX_PATH_LEN) return -1;
    if (snprintf(meta_path, MAX_PATH_LEN, "%s%s%s", backing_dir, path, META_SUFFIX) >= MAX_PATH_LEN) return -1;
    return 0;
}

static int ensure_parent_dirs(const char *full_path) {
    char tmp[MAX_PATH_LEN];
    if (!full_path) return -1;
    size_t n = strnlen(full_path, sizeof(tmp));
    if (n >= sizeof(tmp)) return -1;
    memcpy(tmp, full_path, n);
    tmp[n] = '\0';

    char *slash = strrchr(tmp, '/');
    if (!slash) return 0;
    if (slash == tmp) return 0;
    *slash = '\0';

    char build[MAX_PATH_LEN];
    build[0] = '\0';

    const char *p = tmp;
    if (*p == '/') { strcpy(build, "/"); p++; }

    while (*p) {
        const char *next = strchr(p, '/');
        size_t len = next ? (size_t)(next - p) : strlen(p);
        if (len == 0) break;

        size_t cur = strlen(build);
        if (cur + len + 2 >= sizeof(build)) return -1;
        if (cur > 1 && build[cur - 1] != '/') strcat(build, "/");
        strncat(build, p, len);

        if (mkdir(build, 0755) != 0) {
            if (errno != EEXIST) return -1;
        }

        if (!next) break;
        p = next + 1;
    }
    return 0;
}

static int dir_exists(const char *p) {
    struct stat st;
    if (lstat(p, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

static int file_exists(const char *p) {
    struct stat st;
    if (lstat(p, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

/* ----------------------- Chunk store helpers --------------------------- */

static int ensure_dir(const char *p) {
    if (mkdir(p, 0755) != 0) {
        if (errno != EEXIST) return -1;
    }
    return 0;
}

static int ensure_store_layout_dir(const char *base_dir) {
  /* Create <base>/.jnk, <base>/.jnk/chunks/sha256 */
  char p1[MAX_PATH_LEN], p2[MAX_PATH_LEN], p3[MAX_PATH_LEN];

  if (snprintf(p1, sizeof(p1), "%s/%s", base_dir, INTERNAL_DIR) >= (int)sizeof(p1)) return -1;
  if (snprintf(p2, sizeof(p2), "%s/%s/chunks", base_dir, INTERNAL_DIR) >= (int)sizeof(p2)) return -1;
  if (snprintf(p3, sizeof(p3), "%s/%s/chunks/sha256", base_dir, INTERNAL_DIR) >= (int)sizeof(p3)) return -1;

  if (ensure_dir(p1) != 0) return -1;
  if (ensure_dir(p2) != 0) return -1;
  if (ensure_dir(p3) != 0) return -1;

  return 0;
}

static int ensure_store_layout(jnk_fuse_state_t *s) {
  /* Create <backing>/.jnk, <backing>/.jnk/refs */
  char p1[MAX_PATH_LEN], p4[MAX_PATH_LEN];

  if (snprintf(p1, sizeof(p1), "%s/%s", s->backing_dir, INTERNAL_DIR) >= (int)sizeof(p1)) return -1;
  if (snprintf(p4, sizeof(p4), "%s/%s/refs", s->backing_dir, INTERNAL_DIR) >= (int)sizeof(p4)) return -1;

  if (ensure_dir(p1) != 0) return -1;
  if (ensure_dir(p4) != 0) return -1;

  strncpy(s->refs_dir,  p4, sizeof(s->refs_dir)  - 1);

  for (size_t i = 0; i < s->store_dir_count; i++) {
      if (ensure_store_layout_dir(s->store_dirs[i]) != 0) return -1;
  }

  return 0;
}

static int store_path_for_hash(char out[MAX_PATH_LEN], const char *store_base_dir,
                               const char hashhex[65], int ensure_shard_dir) {
    char shard[3];
    shard[0] = hashhex[0];
    shard[1] = hashhex[1];
    shard[2] = '\0';

    char shard_dir[MAX_PATH_LEN];
    if (snprintf(shard_dir, sizeof(shard_dir), "%s/%s/chunks/sha256/%s",
                 store_base_dir, INTERNAL_DIR, shard) >= (int)sizeof(shard_dir)) return -1;

    /* ensure shard dir exists */
    if (ensure_shard_dir && ensure_dir(shard_dir) != 0) return -1;

    if (snprintf(out, MAX_PATH_LEN, "%s/%s", shard_dir, hashhex) >= MAX_PATH_LEN) return -1;
    return 0;
}
static int refs_path_for_hash(char out[MAX_PATH_LEN], const jnk_fuse_state_t *s, const char hashhex[65]) {
    char shard[3];
    shard[0] = hashhex[0];
    shard[1] = hashhex[1];
    shard[2] = '\0';

    char shard_dir[MAX_PATH_LEN];
    if (snprintf(shard_dir, sizeof(shard_dir), "%s/%s", s->refs_dir, shard) >= (int)sizeof(shard_dir)) return -1;

    if (ensure_dir(shard_dir) != 0) return -1;

    if (snprintf(out, MAX_PATH_LEN, "%s/%s.ref", shard_dir, hashhex) >= MAX_PATH_LEN) return -1;
    return 0;
}

/* Read refcount; returns 0 if missing (unknown) */
static int read_refcount_fd(int fd, long long *out) {
    char buf[64];
    lseek(fd, 0, SEEK_SET);
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    if (r <= 0) { *out = 0; return 0; }
    buf[r] = '\0';
    *out = atoll(buf);
    if (*out < 0) *out = 0;
    return 0;
}

static int write_refcount_fd(int fd, long long v) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%lld\n", v);
    if (n <= 0) return -1;

    if (ftruncate(fd, 0) != 0) return -1;
    lseek(fd, 0, SEEK_SET);

    ssize_t w = write(fd, buf, (size_t)n);
    if (w != n) return -1;
    if (fsync(fd) != 0) return -1;
    return 0;
}

/* delta > 0 increments; delta < 0 decrements. Safe rule:
 * - If decrement and ref file missing => do nothing (avoid accidental deletion).
 * - Only delete chunk when ref file exists and reaches 0.
 */
static int apply_ref_delta(jnk_fuse_state_t *s, const char hashhex[65], long long delta) {
    if (delta == 0) return 0;

    char refp[MAX_PATH_LEN];
    if (refs_path_for_hash(refp, s, hashhex) != 0) return -EIO;

    int flags = O_RDWR | O_CREAT;
    int fd = open(refp, flags, 0644);
    if (fd < 0) {
        /* If we cannot create/open ref file, fail safe */
        return -EIO;
    }

    if (flock(fd, LOCK_EX) != 0) {
        close(fd);
        return -EIO;
    }

    /* Detect "missing" by checking file size before we modify */
    struct stat st;
    int had_file = (fstat(fd, &st) == 0 && st.st_size > 0);

    long long cur = 0;
    (void)read_refcount_fd(fd, &cur);

    if (delta < 0 && !had_file) {
        /* Missing ref file: do NOT delete chunks based on unknown state */
        flock(fd, LOCK_UN);
        close(fd);
        return 0;
    }

    long long next = cur + delta;
    if (next < 0) next = 0;

    if (next == 0) {
        /* Delete ref file and chunk file */
        flock(fd, LOCK_UN);
        close(fd);

        (void)unlink(refp);

        char chunkp[MAX_PATH_LEN];
        for (size_t i = 0; i < s->store_dir_count; i++) {
            if (store_path_for_hash(chunkp, s->store_dirs[i], hashhex, 0) == 0) {
                (void)unlink(chunkp);
            }
        }
        return 0;
    }

    if (write_refcount_fd(fd, next) != 0) {
        flock(fd, LOCK_UN);
        close(fd);
        return -EIO;
    }

    flock(fd, LOCK_UN);
    close(fd);
    return 0;
}

/* Collect non-NULL hashes into a flat list (with duplicates). */
static char **collect_hash_list(char **hashes, size_t count, size_t *out_n) {
    size_t n = 0;
    for (size_t i = 0; i < count; i++) if (hashes[i]) n++;

    char **list = (char **)calloc(n ? n : 1, sizeof(char *));
    if (!list) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < count; i++) {
        if (!hashes[i]) continue;
        list[j] = hashes[i]; /* borrow pointer (do not free) */
        j++;
    }
    *out_n = n;
    return list;
}

static int cmp_cstr(const void *a, const void *b) {
    const char *sa = *(const char * const *)a;
    const char *sb = *(const char * const *)b;
    return strcmp(sa, sb);
}

/* Apply refcount changes from (orig_hashes) -> (new_hashes) as a multiset diff. */
static int apply_ref_deltas_from_manifests(jnk_fuse_state_t *s,
                                          char **orig_hashes, size_t orig_count,
                                          char **new_hashes,  size_t new_count) {
    size_t on = 0, nn = 0;
    char **olist = collect_hash_list(orig_hashes, orig_count, &on);
    char **nlist = collect_hash_list(new_hashes,  new_count,  &nn);
    if (!olist || !nlist) {
        free(olist); free(nlist);
        return -ENOMEM;
    }

    qsort(olist, on, sizeof(char *), cmp_cstr);
    qsort(nlist, nn, sizeof(char *), cmp_cstr);

    size_t i = 0, j = 0;
    while (i < on || j < nn) {
        const char *cur = NULL;

        if (j >= nn) cur = olist[i];
        else if (i >= on) cur = nlist[j];
        else cur = (strcmp(olist[i], nlist[j]) <= 0) ? olist[i] : nlist[j];

        /* count occurrences in each */
        long long oc = 0, nc = 0;
        while (i < on && strcmp(olist[i], cur) == 0) { oc++; i++; }
        while (j < nn && strcmp(nlist[j], cur) == 0) { nc++; j++; }

        long long delta = nc - oc;
        if (delta != 0) {
            int rc = apply_ref_delta(s, cur, delta);
            if (rc != 0) { free(olist); free(nlist); return rc; }
        }
    }

    free(olist);
    free(nlist);
    return 0;
}

/* Deep copy hashes array */
static int clone_hashes(char ***out, size_t *out_count, char **in, size_t in_count) {
    *out = NULL;
    *out_count = in_count;

    if (in_count == 0) return 0;

    char **h = (char **)calloc(in_count, sizeof(char *));
    if (!h) return -ENOMEM;

    for (size_t i = 0; i < in_count; i++) {
        if (!in[i]) { h[i] = NULL; continue; }
        h[i] = (char *)malloc(65);
        if (!h[i]) { /* cleanup */
            for (size_t k = 0; k < i; k++) free(h[k]);
            free(h);
            return -ENOMEM;
        }
        memcpy(h[i], in[i], 65);
    }

    *out = h;
    return 0;
}

/* Compute current store usage by walking all store dirs. (Simple & correct; can optimize later.) */
static int64_t store_usage_bytes(const jnk_fuse_state_t *s) {
    int64_t total = 0;
    for (size_t i = 0; i < s->store_dir_count; i++) {
        char store_root[MAX_PATH_LEN];
        if (snprintf(store_root, sizeof(store_root), "%s/%s/chunks/sha256",
                     s->store_dirs[i], INTERNAL_DIR) >= (int)sizeof(store_root)) {
            continue;
        }

        DIR *d = opendir(store_root);
        if (!d) continue;

        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

            char shard[MAX_PATH_LEN];
            if (snprintf(shard, sizeof(shard), "%s/%s", store_root, de->d_name) >= (int)sizeof(shard)) continue;

            DIR *sd = opendir(shard);
            if (!sd) continue;

            struct dirent *fe;
            while ((fe = readdir(sd)) != NULL) {
                if (strcmp(fe->d_name, ".") == 0 || strcmp(fe->d_name, "..") == 0) continue;

                char fp[MAX_PATH_LEN];
                if (snprintf(fp, sizeof(fp), "%s/%s", shard, fe->d_name) >= (int)sizeof(fp)) continue;

                struct stat st;
                if (lstat(fp, &st) == 0 && S_ISREG(st.st_mode)) total += (int64_t)st.st_size;
            }
            closedir(sd);
        }

        closedir(d);
    }

    return total;
}

/* Store chunk by hash, if missing. Returns 0 on success, -ENOSPC if quota exceeded. */
static int store_put_chunk_if_missing(jnk_fuse_state_t *s, const char hashhex[65], const uint8_t *data, size_t len) {
    char p[MAX_PATH_LEN];
    for (size_t i = 0; i < s->store_dir_count; i++) {
        if (store_path_for_hash(p, s->store_dirs[i], hashhex, 0) != 0) continue;
        if (file_exists(p)) {
            return 0; /* already present */
        }
    }

    /* quota check: if storing new unique chunk */
    if (s->quota_bytes != 0) {
        int64_t used = store_usage_bytes(s);
        if (used < 0) return -EIO;
        if ((uint64_t)used + (uint64_t)len > (uint64_t)s->quota_bytes) {
            return -ENOSPC;
        }
    }

    if (s->store_dir_count == 0) return -EIO;
    size_t target = s->store_rr_next % s->store_dir_count;
    s->store_rr_next = (s->store_rr_next + 1) % s->store_dir_count;

    if (store_path_for_hash(p, s->store_dirs[target], hashhex, 1) != 0) return -EIO;

    /* write atomically-ish */
    char tmp[MAX_PATH_LEN];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", p) >= (int)sizeof(tmp)) return -EIO;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) return -EIO;

    ssize_t w = write(fd, data, len);
    if (w < 0 || (size_t)w != len) {
        close(fd);
        (void)unlink(tmp);
        return -EIO;
    }
    if (fsync(fd) != 0) {
        close(fd);
        (void)unlink(tmp);
        return -EIO;
    }
    close(fd);

    if (rename(tmp, p) != 0) {
        (void)unlink(tmp);
        return -EIO;
    }

    return 0;
}

/* Read chunk from store and verify hash. Returns number of bytes read or -EIO/-ENOENT. */
static int read_chunk_verified(const jnk_fuse_state_t *s, const char hashhex[65], uint8_t *out, size_t max_len, size_t *out_len) {
    char p[MAX_PATH_LEN];
    int fd = -1;
    for (size_t i = 0; i < s->store_dir_count; i++) {
        if (store_path_for_hash(p, s->store_dirs[i], hashhex, 0) != 0) continue;
        fd = open(p, O_RDONLY);
        if (fd >= 0) break;
    }
    if (fd < 0) return -ENOENT;

    /* read whole chunk file */
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -EIO; }
    if (!S_ISREG(st.st_mode)) { close(fd); return -EIO; }

    size_t len = (size_t)st.st_size;
    if (len > max_len) { close(fd); return -EIO; }

    ssize_t r = read(fd, out, len);
    close(fd);
    if (r < 0 || (size_t)r != len) return -EIO;

    /* integrity check */
    char calc[65];
    sha256_buf_hex(out, len, calc);
    if (memcmp(calc, hashhex, 64) != 0) return -EIO;

    *out_len = len;
    return 0;
}

/* ---------------------------- Meta (manifest) --------------------------- */

static int load_manifest(const char *meta_path, size_t *out_size, char ***out_hashes, size_t *out_count) {
    *out_size = 0;
    *out_hashes = NULL;
    *out_count = 0;

    FILE *f = fopen(meta_path, "rb");
    if (!f) return -1;

    /* line1: size <bytes> */
    char line[256];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }

    unsigned long long sz = 0;
    if (sscanf(line, "size %llu", &sz) != 1) { fclose(f); return -1; }
    if (sz > (unsigned long long)SIZE_MAX) { fclose(f); return -1; }
    *out_size = (size_t)sz;

    /* subsequent lines: chunk <idx> <hashhex> */
    size_t cap = 0;
    size_t n = 0;
    char **hashes = NULL;

    while (fgets(line, sizeof(line), f)) {
        size_t idx = 0;
        char hh[65] = {0};
        if (sscanf(line, "chunk %zu %64s", &idx, hh) != 2) continue;

        /* ensure enough */
        if (idx >= cap) {
            size_t newcap = cap ? cap : 8;
            while (newcap <= idx) newcap *= 2;
            char **nh = (char **)realloc(hashes, newcap * sizeof(char *));
            if (!nh) { fclose(f); return -1; }
            hashes = nh;
            for (size_t i = cap; i < newcap; i++) hashes[i] = NULL;
            cap = newcap;
        }

        if (hashes[idx]) free(hashes[idx]);
        hashes[idx] = (char *)malloc(65);
        if (!hashes[idx]) { fclose(f); return -1; }
        memcpy(hashes[idx], hh, 65);

        if (idx + 1 > n) n = idx + 1;
    }

    fclose(f);
    *out_hashes = hashes;
    *out_count = n;
    return 0;
}

static int save_manifest_atomic(const char *meta_path, size_t size, char **hashes, size_t count) {
    if (ensure_parent_dirs(meta_path) != 0) return -1;

    char tmp[MAX_PATH_LEN];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", meta_path) >= (int)sizeof(tmp)) return -1;

    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;

    fprintf(f, "size %zu\n", size);

    for (size_t i = 0; i < count; i++) {
        if (hashes[i]) {
            fprintf(f, "chunk %zu %s\n", i, hashes[i]);
        }
    }

    if (fflush(f) != 0) { fclose(f); (void)unlink(tmp); return -1; }
    fclose(f);

    if (rename(tmp, meta_path) != 0) { (void)unlink(tmp); return -1; }
    return 0;
}

static void free_hashes(char **hashes, size_t count) {
    if (!hashes) return;
    for (size_t i = 0; i < count; i++) free(hashes[i]);
    free(hashes);
}

/* Ensure handle has hashes sized to at least new_count */
static int ensure_hash_capacity(jnk_file_handle_t *h, size_t new_count) {
    if (new_count <= h->chunk_count) return 0;

    char **nh = (char **)realloc(h->hashes, new_count * sizeof(char *));
    if (!nh) return -ENOMEM;

    for (size_t i = h->chunk_count; i < new_count; i++) nh[i] = NULL;
    h->hashes = nh;
    h->chunk_count = new_count;
    return 0;
}

/* --------------------------- FUSE Callbacks ---------------------------- */

static int jnk_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void)fi;
    jnk_fuse_state_t *s = get_state();

    char realp[MAX_PATH_LEN], metap[MAX_PATH_LEN];
    if (make_real_and_meta(s->backing_dir, path, realp, metap) != 0) return -EINVAL;

    memset(st, 0, sizeof(*st));

    if (strcmp(path, "/") == 0) {
        if (lstat(realp, st) != 0) return -errno;
        return 0;
    }

    if (dir_exists(realp)) {
        if (lstat(realp, st) != 0) return -errno;
        return 0;
    }

    if (file_exists(metap)) {
        size_t size = 0;
        char **hashes = NULL;
        size_t count = 0;
        if (load_manifest(metap, &size, &hashes, &count) != 0) return -EIO;
        free_hashes(hashes, count);

        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = (off_t)size;
        st->st_uid = getuid();
        st->st_gid = getgid();
        st->st_blksize = JNK_CHUNK_SIZE;
        st->st_atime = time(NULL);
        st->st_mtime = st->st_atime;
        st->st_ctime = st->st_atime;
        return 0;
    }

    return -ENOENT;
}

static int jnk_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t off, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void)off; (void)fi; (void)flags;
    jnk_fuse_state_t *s = get_state();

    char realp[MAX_PATH_LEN], metap[MAX_PATH_LEN];
    if (make_real_and_meta(s->backing_dir, path, realp, metap) != 0) return -EINVAL;

    DIR *d = opendir(realp);
    if (!d) return -errno;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        if (strcmp(name, INTERNAL_DIR) == 0) continue; /* hide .jnk */

        if (str_endswith(name, META_SUFFIX)) {
            /* Show logical file name (strip suffix) */
            size_t ln = strlen(name);
            size_t ms = strlen(META_SUFFIX);
            size_t base = ln - ms;
            char logical[NAME_MAX + 1];
            if (base > NAME_MAX) base = NAME_MAX;
            memcpy(logical, name, base);
            logical[base] = '\0';
            filler(buf, logical, NULL, 0, 0);
            continue;
        }

        /* show real dirs and any other non-internal things */
        filler(buf, name, NULL, 0, 0);
    }

    closedir(d);
    return 0;
}

static int jnk_mkdir(const char *path, mode_t mode) {
    jnk_fuse_state_t *s = get_state();

    char realp[MAX_PATH_LEN], metap[MAX_PATH_LEN];
    if (make_real_and_meta(s->backing_dir, path, realp, metap) != 0) return -EINVAL;

    (void)metap;

    if (ensure_parent_dirs(realp) != 0) return -EIO;
    if (mkdir(realp, mode) != 0) return -errno;
    return 0;
}

static int jnk_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode;
    jnk_fuse_state_t *s = get_state();

    char realp[MAX_PATH_LEN], metap[MAX_PATH_LEN];
    if (make_real_and_meta(s->backing_dir, path, realp, metap) != 0) return -EINVAL;

    /* If there is a real directory with this name, refuse to create a file */
    if (dir_exists(realp)) return -EISDIR;

    /* Create an empty manifest:
     *   size 0
     *   (no chunks)
     */
    if (save_manifest_atomic(metap, 0, NULL, 0) != 0) return -EIO;

    /* Allocate per-open handle */
    jnk_file_handle_t *h = (jnk_file_handle_t *)calloc(1, sizeof(*h));
    if (!h) return -ENOMEM;

    strncpy(h->meta_path, metap, sizeof(h->meta_path) - 1);

    /* Current in-memory view (modifiable during this open) */
    h->size = 0;
    h->chunk_count = 0;
    h->hashes = NULL;
    h->dirty = 0;
    h->dirty_chunks = NULL;

    /* Original snapshot (what was on disk when opened) for refcount delta.
     * For create, the file is new: original is empty too.
     */
    h->orig_size = 0;
    h->orig_chunk_count = 0;
    h->orig_hashes = NULL;

    /* Stash handle in fi->fh for read/write/truncate/release */
    fi->fh = (uint64_t)(uintptr_t)h;
    return 0;
}

static int jnk_open(const char *path, struct fuse_file_info *fi) {
    jnk_fuse_state_t *s = get_state();

    char realp[MAX_PATH_LEN], metap[MAX_PATH_LEN];
    if (make_real_and_meta(s->backing_dir, path, realp, metap) != 0) return -EINVAL;

    /* Opening a directory as a file should fail */
    if (dir_exists(realp)) return -EISDIR;

    /* A logical file exists iff its manifest exists */
    if (!file_exists(metap)) return -ENOENT;

    jnk_file_handle_t *h = (jnk_file_handle_t *)calloc(1, sizeof(*h));
    if (!h) return -ENOMEM;

    strncpy(h->meta_path, metap, sizeof(h->meta_path) - 1);

    /* Load manifest into the current working copy */
    if (load_manifest(metap, &h->size, &h->hashes, &h->chunk_count) != 0) {
        free(h);
        return -EIO;
    }
    h->dirty = 0;
    h->dirty_chunks = NULL;

    /* Snapshot original for refcount diffing on release()
     *
     * If the file is modified while open, we compare:
     *   orig_hashes -> hashes
     * and apply deltas to refcounts accordingly.
     */
    h->orig_size = h->size;
    if (clone_hashes(&h->orig_hashes, &h->orig_chunk_count, h->hashes, h->chunk_count) != 0) {
        free_hashes(h->hashes, h->chunk_count);
        free(h);
        return -ENOMEM;
    }

    fi->fh = (uint64_t)(uintptr_t)h;
    return 0;
}

/* ------------------------- Dirty Chunk Cache --------------------------- */

static dirty_chunk_t *dirty_find(jnk_file_handle_t *h, size_t idx) {
    for (dirty_chunk_t *d = h->dirty_chunks; d; d = d->next) {
        if (d->idx == idx) return d;
    }
    return NULL;
}

/* Load current chunk content into out buffer:
 * - If chunk exists in manifest: read+verify from store then pad with zeros.
 * - Else: zero-fill.
 */
static int load_chunk_into_buf(jnk_fuse_state_t *s, jnk_file_handle_t *h, size_t idx, uint8_t *out) {
    if (idx < h->chunk_count && h->hashes[idx]) {
        size_t got_len = 0;
        int rc = read_chunk_verified(s, h->hashes[idx], out, JNK_CHUNK_SIZE, &got_len);
        if (rc != 0) return -EIO;
        if (got_len < JNK_CHUNK_SIZE) memset(out + got_len, 0, JNK_CHUNK_SIZE - got_len);
        return 0;
    }
    memset(out, 0, JNK_CHUNK_SIZE);
    return 0;
}

static int dirty_get_or_create(jnk_fuse_state_t *s, jnk_file_handle_t *h, size_t idx, dirty_chunk_t **out) {
    dirty_chunk_t *d = dirty_find(h, idx);
    if (d) { *out = d; return 0; }

    /* Ensure hashes array covers idx so release() can update manifest cleanly */
    if (ensure_hash_capacity(h, idx + 1) != 0) return -ENOMEM;

    d = (dirty_chunk_t *)calloc(1, sizeof(*d));
    if (!d) return -ENOMEM;

    d->data = (uint8_t *)malloc(JNK_CHUNK_SIZE);
    if (!d->data) { free(d); return -ENOMEM; }

    int rc = load_chunk_into_buf(s, h, idx, d->data);
    if (rc != 0) { free(d->data); free(d); return rc; }

    d->idx = idx;
    d->next = h->dirty_chunks;
    h->dirty_chunks = d;

    *out = d;
    return 0;
}

static void dirty_free_all(jnk_file_handle_t *h) {
    dirty_chunk_t *d = h->dirty_chunks;
    while (d) {
        dirty_chunk_t *n = d->next;
        free(d->data);
        free(d);
        d = n;
    }
    h->dirty_chunks = NULL;
}

static void dirty_drop_from(jnk_file_handle_t *h, size_t keep_before) {
    dirty_chunk_t **pp = &h->dirty_chunks;
    while (*pp) {
        dirty_chunk_t *cur = *pp;
        if (cur->idx >= keep_before) {
            *pp = cur->next;
            free(cur->data);
            free(cur);
            continue;
        }
        pp = &cur->next;
    }
}


static int jnk_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)path;
    jnk_fuse_state_t *s = get_state();
    jnk_file_handle_t *h = (jnk_file_handle_t *)(uintptr_t)fi->fh;
    if (!h) return -EIO;

    if ((size_t)off >= h->size) return 0;
    size_t max_can = h->size - (size_t)off;
    if (size > max_can) size = max_can;

    size_t done = 0;
    while (done < size) {
        size_t abs_off = (size_t)off + done;
        size_t idx = abs_off / JNK_CHUNK_SIZE;
        size_t in_off = abs_off % JNK_CHUNK_SIZE;

        size_t want = size - done;
        size_t room = JNK_CHUNK_SIZE - in_off;
        if (want > room) want = room;

        dirty_chunk_t *d = dirty_find(h, idx);
        if (d) {
            memcpy(buf + done, d->data + in_off, want);
            done += want;
            continue;
        }

        /* Missing chunk hash => zeros (sparse) */
        if (idx >= h->chunk_count || !h->hashes[idx]) {
            memset(buf + done, 0, want);
            done += want;
            continue;
        }

        uint8_t chunk[JNK_CHUNK_SIZE];
        size_t got_len = 0;

        int rc = read_chunk_verified(s, h->hashes[idx], chunk, sizeof(chunk), &got_len);
        if (rc != 0) return -EIO;

        /* chunk may be shorter than full size; treat beyond as zeros */
        if (in_off >= got_len) {
            memset(buf + done, 0, want);
        } else {
            size_t avail = got_len - in_off;
            size_t take = (want < avail) ? want : avail;
            memcpy(buf + done, chunk + in_off, take);
            if (take < want) memset(buf + done + take, 0, want - take);
        }

        done += want;
    }

    return (int)done;
}

static int jnk_write(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)path;
    jnk_fuse_state_t *s = get_state();
    jnk_file_handle_t *h = (jnk_file_handle_t *)(uintptr_t)fi->fh;
    if (!h) return -EIO;

    size_t done = 0;
    while (done < size) {
        size_t abs_off = (size_t)off + done;
        size_t idx = abs_off / JNK_CHUNK_SIZE;
        size_t in_off = abs_off % JNK_CHUNK_SIZE;

        size_t want = size - done;
        size_t room = JNK_CHUNK_SIZE - in_off;
        if (want > room) want = room;

        dirty_chunk_t *d = NULL;
        int rc = dirty_get_or_create(s, h, idx, &d);
        if (rc != 0) return rc;
        if (in_off + want > JNK_CHUNK_SIZE) return -EIO;
        memcpy(d->data + in_off, buf + done, want);
        h->dirty = 1;

        done += want;
    }

    size_t end_pos = (size_t)off + size;
    if (end_pos > h->size) {
        h->size = end_pos;
        h->dirty = 1;
    }

    return (int)size;
}

static int jnk_truncate(const char *path, off_t newsize, struct fuse_file_info *fi) {
    (void)path;
    if (newsize < 0) return -EINVAL;

    jnk_file_handle_t *h = NULL;
    if (fi && fi->fh) h = (jnk_file_handle_t *)(uintptr_t)fi->fh;

    /* If not open, we load & rewrite manifest (simpler to require open for now) */
    if (!h) return -EACCES;

    size_t ns = (size_t)newsize;

    /* Shrink: drop hashes beyond last needed chunk; keep store data (GC later) */
    if (ns < h->size) {
        size_t needed = (ns == 0) ? 0 : ((ns - 1) / JNK_CHUNK_SIZE) + 1;
        if (needed < h->chunk_count) {
            for (size_t i = needed; i < h->chunk_count; i++) {
                free(h->hashes[i]);
                h->hashes[i] = NULL;
            }
            /* keep chunk_count as-is; manifest will omit NULLs beyond needed */
        }
        dirty_drop_from(h, needed);
        h->size = ns;
        h->dirty = 1;
        return 0;
    }

    /* Expand: just update size (sparse) */
    if (ns > h->size) {
        h->size = ns;
        h->dirty = 1;
    }
    return 0;
}

static int jnk_release(const char *path, struct fuse_file_info *fi) {
  (void)path;
  jnk_fuse_state_t *s = get_state();
  jnk_file_handle_t *h = (jnk_file_handle_t *)(uintptr_t)fi->fh;
  if (!h) return 0;

  for (dirty_chunk_t *d = h->dirty_chunks; d; d = d->next) {
    char hashhex[65];
    sha256_buf_hex(d->data, JNK_CHUNK_SIZE, hashhex);
    int rc = store_put_chunk_if_missing(s, hashhex, d->data, JNK_CHUNK_SIZE);
    if (rc != 0) {
      dirty_free_all(h);
      free_hashes(h->orig_hashes, h->orig_chunk_count);
      free_hashes(h->hashes, h->chunk_count);
      free(h);
      return rc;
    }
    if (ensure_hash_capacity(h, d->idx + 1) != 0) {
      dirty_free_all(h);
      free_hashes(h->orig_hashes, h->orig_chunk_count);
      free_hashes(h->hashes, h->chunk_count);
      free(h);
      return -ENOMEM;
    }
    if (h->hashes[d->idx]) {
      free(h->hashes[d->idx]);
      h->hashes[d->idx] = NULL;
    }
    h->hashes[d->idx] = (char *)malloc(65);
    if (!h->hashes[d->idx]) {
      dirty_free_all(h);
      free_hashes(h->orig_hashes, h->orig_chunk_count);
      free_hashes(h->hashes, h->chunk_count);
      free(h);
      return -ENOMEM;
    }
    memcpy(h->hashes[d->idx], hashhex, 65);
    h->dirty = 1;
  }
  dirty_free_all(h);

  /* If the manifest changed, write it, then update refs based on diff */
  if (h->dirty) {
    if (save_manifest_atomic(h->meta_path, h->size, h->hashes, h->chunk_count) != 0) {
      /* fail safe: don’t touch refs if we couldn’t persist manifest */
    } else {
      (void)apply_ref_deltas_from_manifests(s,
                                            h->orig_hashes, h->orig_chunk_count,
                                            h->hashes,      h->chunk_count);
    }
    h->dirty = 0;
  }

  /* cleanup */
  free_hashes(h->orig_hashes, h->orig_chunk_count);
  free_hashes(h->hashes, h->chunk_count);
  free(h);
  return 0;
}

static int jnk_unlink(const char *path) {
  jnk_fuse_state_t *s = get_state();
  char realp[MAX_PATH_LEN], metap[MAX_PATH_LEN];
  if (make_real_and_meta(s->backing_dir, path, realp, metap) != 0) return -EINVAL;
  (void)realp;

  if (!file_exists(metap)) return -ENOENT;

  /* Load manifest and decrement refs for all hashes */
  size_t sz = 0, cnt = 0;
  char **hashes = NULL;
  if (load_manifest(metap, &sz, &hashes, &cnt) == 0) {
    /* Apply delta: old=hashes -> new=empty */
    (void)apply_ref_deltas_from_manifests(s, hashes, cnt, NULL, 0);
    free_hashes(hashes, cnt);
  }

  /* Remove meta file */
  if (unlink(metap) != 0) return -errno;

  return 0;
}


static int jnk_rmdir(const char *path) {
    jnk_fuse_state_t *s = get_state();
    char realp[MAX_PATH_LEN], metap[MAX_PATH_LEN];
    if (make_real_and_meta(s->backing_dir, path, realp, metap) != 0) return -EINVAL;
    (void)metap;
    if (rmdir(realp) != 0) return -errno;
    return 0;
}

static int jnk_rename(const char *from, const char *to, unsigned int flags) {
    (void)flags;
    jnk_fuse_state_t *s = get_state();
    char fr[MAX_PATH_LEN], fm[MAX_PATH_LEN];
    char tr[MAX_PATH_LEN], tm[MAX_PATH_LEN];

    if (make_real_and_meta(s->backing_dir, from, fr, fm) != 0) return -EINVAL;
    if (make_real_and_meta(s->backing_dir, to,   tr, tm) != 0) return -EINVAL;

    if (dir_exists(fr)) {
        if (ensure_parent_dirs(tr) != 0) return -EIO;
        if (rename(fr, tr) != 0) return -errno;
        return 0;
    }

    if (!file_exists(fm)) return -ENOENT;

    if (ensure_parent_dirs(tm) != 0) return -EIO;
    if (rename(fm, tm) != 0) return -errno;
    return 0;
}

static int jnk_statfs(const char *path, struct statvfs *st) {
    jnk_fuse_state_t *s = get_state();
    char realp[MAX_PATH_LEN], metap[MAX_PATH_LEN];
    if (make_real_and_meta(s->backing_dir, path, realp, metap) != 0) return -EINVAL;
    (void)metap;

    if (statvfs(realp, st) != 0) return -errno;

    /* Enforce quota view if set */
    if (s->quota_bytes != 0) {
        int64_t used = store_usage_bytes(s);
        if (used < 0) return 0;

        uint64_t quota = (uint64_t)s->quota_bytes;
        uint64_t freeb = (quota > (uint64_t)used) ? (quota - (uint64_t)used) : 0;

        /* Present quota-limited filesystem stats */
        st->f_bsize  = 4096;
        st->f_frsize = 4096;
        st->f_blocks = (fsblkcnt_t)(quota / st->f_frsize);
        st->f_bfree  = (fsblkcnt_t)(freeb / st->f_frsize);
        st->f_bavail = st->f_bfree;
    }

    return 0;
}

/* Minimal ops table (avoid extra surfaces) */
static const struct fuse_operations jnk_ops = {
    .getattr  = jnk_getattr,
    .readdir  = jnk_readdir,
    .mkdir    = jnk_mkdir,
    .create   = jnk_create,
    .open     = jnk_open,
    .read     = jnk_read,
    .write    = jnk_write,
    .truncate = jnk_truncate,
    .release  = jnk_release,
    .unlink   = jnk_unlink,
    .rmdir    = jnk_rmdir,
    .rename   = jnk_rename,
    .statfs   = jnk_statfs,
};

/* ---------------------------- Entry Point ------------------------------ */

int junknas_fuse_run(const junknas_config_t *cfg, int argc, char **argv) {
    if (!cfg) return -1;

    jnk_fuse_state_t *state = (jnk_fuse_state_t *)calloc(1, sizeof(*state));
    if (!state) return -1;

    strncpy(state->backing_dir, cfg->data_dir, sizeof(state->backing_dir) - 1);
    state->store_dir_count = cfg->data_dir_count;
    if (state->store_dir_count == 0) state->store_dir_count = 1;
    if (state->store_dir_count > MAX_DATA_DIRS) state->store_dir_count = MAX_DATA_DIRS;
    for (size_t i = 0; i < state->store_dir_count; i++) {
        const char *dir = (cfg->data_dir_count > 0) ? cfg->data_dirs[i] : cfg->data_dir;
        strncpy(state->store_dirs[i], dir, sizeof(state->store_dirs[i]) - 1);
    }
    state->store_rr_next = 0;
    state->verbose = cfg->verbose;
    state->quota_bytes = cfg->max_storage_bytes; /* 0 = unlimited */

    if (mkdir(state->backing_dir, 0755) != 0) {
        if (errno != EEXIST) { free(state); return -1; }
    }

    for (size_t i = 0; i < state->store_dir_count; i++) {
        if (mkdir(state->store_dirs[i], 0755) != 0) {
            if (errno != EEXIST) { free(state); return -1; }
        }
    }

    if (ensure_store_layout(state) != 0) {
        free(state);
        return -1;
    }

    /* Correct FUSE3 args: build from scratch */
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    (void)argc;

    if (fuse_opt_add_arg(&args, argv[0]) != 0) { fuse_opt_free_args(&args); free(state); return -1; }

    /* Foreground for dev (you can remove later) */
    fuse_opt_add_arg(&args, "-f");

    /* Mountpoint from config */
    if (fuse_opt_add_arg(&args, cfg->mount_point) != 0) { fuse_opt_free_args(&args); free(state); return -1; }

    int rc = fuse_main(args.argc, args.argv, &jnk_ops, state);

    fuse_opt_free_args(&args);
    free(state);
    return (rc == 0) ? 0 : -1;
}
