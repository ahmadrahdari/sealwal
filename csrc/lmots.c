/* Hot loops for LM-OTS / LMS (RFC 8554), SHA-256, n = 32, w = 4.
 * Called from sealwal/lms.py through ctypes. Everything else (message
 * hashing, checksums, HSS, state) is done in Python.
 *
 *   gcc -O2 -shared -fPIC -o _lmots.so lmots.c -lcrypto
 */
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

#define P 67          /* number of chains for w = 4 */
#define CHAIN_END 15  /* 2^w - 1 */
#define D_PBLC 0x8080
#define D_LEAF 0x8282
#define D_INTR 0x8383

/* OpenSSL 3's one-shot SHA256() goes through EVP and costs ~4x more per
 * call than the old context API for these 55-86 byte inputs. */
static void sha(const uint8_t *in, size_t len, uint8_t *out)
{
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, in, len);
    SHA256_Final(out, &c);
}

static void put32(uint8_t *b, uint32_t v) { b[0] = v >> 24; b[1] = v >> 16; b[2] = v >> 8; b[3] = v; }
static void put16(uint8_t *b, uint16_t v) { b[0] = v >> 8; b[1] = v; }

static int coef(const uint8_t *s, int i)
{
    return (s[i / 2] >> (i % 2 ? 0 : 4)) & 0xf;
}

/* x_q[i] = H(I || q || i || 0xff || SEED)   (RFC 8554, appendix A) */
static void ots_x(const uint8_t *I, uint32_t q, uint16_t i, const uint8_t *seed, uint8_t *out)
{
    uint8_t b[55];
    memcpy(b, I, 16);
    put32(b + 16, q);
    put16(b + 20, i);
    b[22] = 0xff;
    memcpy(b + 23, seed, 32);
    sha(b, sizeof b, out);
}

/* tmp = H(I || q || i || j || tmp) for j in [from, to) */
static void chain(const uint8_t *I, uint32_t q, uint16_t i, int from, int to, uint8_t *tmp)
{
    uint8_t b[55];
    memcpy(b, I, 16);
    put32(b + 16, q);
    put16(b + 20, i);
    for (int j = from; j < to; j++) {
        b[22] = (uint8_t)j;
        memcpy(b + 23, tmp, 32);
        sha(b, sizeof b, tmp);
    }
}

static void pub_hash(const uint8_t *I, uint32_t q, const uint8_t *ys, uint8_t *K)
{
    SHA256_CTX c;
    uint8_t h[22];
    memcpy(h, I, 16);
    put32(h + 16, q);
    put16(h + 20, D_PBLC);
    SHA256_Init(&c);
    SHA256_Update(&c, h, sizeof h);
    SHA256_Update(&c, ys, 32 * P);
    SHA256_Final(K, &c);
}

void ots_keygen(const uint8_t *I, uint32_t q, const uint8_t *seed, uint8_t *K)
{
    uint8_t ys[32 * P];
    for (int i = 0; i < P; i++) {
        ots_x(I, q, i, seed, ys + 32 * i);
        chain(I, q, i, 0, CHAIN_END, ys + 32 * i);
    }
    pub_hash(I, q, ys, K);
}

/* V = Q || checksum, 34 bytes. Y gets the 67 chain values. */
void ots_sign(const uint8_t *I, uint32_t q, const uint8_t *seed, const uint8_t *V, uint8_t *Y)
{
    for (int i = 0; i < P; i++) {
        ots_x(I, q, i, seed, Y + 32 * i);
        chain(I, q, i, 0, coef(V, i), Y + 32 * i);
    }
}

void ots_candidate(const uint8_t *I, uint32_t q, const uint8_t *V, const uint8_t *Y, uint8_t *Kc)
{
    uint8_t zs[32 * P];
    memcpy(zs, Y, sizeof zs);
    for (int i = 0; i < P; i++)
        chain(I, q, i, coef(V, i), CHAIN_END, zs + 32 * i);
    pub_hash(I, q, zs, Kc);
}

/* Full LMS tree of height h. T must hold (2 << h) * 32 bytes; node r
 * (1 = root, leaves at 2^h .. 2^(h+1)-1) lands at T + 32 r. */
void lms_tree(const uint8_t *I, const uint8_t *seed, int h, uint8_t *T)
{
    uint32_t nleaf = 1u << h;
    uint8_t b[86], K[32];
    memcpy(b, I, 16);
    for (uint32_t q = 0; q < nleaf; q++) {
        ots_keygen(I, q, seed, K);
        put32(b + 16, nleaf + q);
        put16(b + 20, D_LEAF);
        memcpy(b + 22, K, 32);
        sha(b, 54, T + 32 * (nleaf + q));
    }
    for (uint32_t r = nleaf - 1; r >= 1; r--) {
        put32(b + 16, r);
        put16(b + 20, D_INTR);
        memcpy(b + 22, T + 32 * (2 * r), 32);
        memcpy(b + 54, T + 32 * (2 * r + 1), 32);
        sha(b, 86, T + 32 * r);
    }
}
