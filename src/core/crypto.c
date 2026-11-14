#include "cegram/crypto.h"
#include "cegram/mini-gmp.h"
#include <time.h>

#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
    #include <windows.h>
    #include <wincrypt.h>
#endif

int cegram_random_bytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return CEGRAM_ERR_GENERIC;

#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        BOOL res = CryptGenRandom(hProv, (DWORD)len, buf);
        CryptReleaseContext(hProv, 0);
        if (res) return CEGRAM_OK;
    }
#endif

    {
        size_t i;
        static int seeded = 0;
        if (!seeded) {
            srand((unsigned int)time(NULL));
            seeded = 1;
        }
        for (i = 0; i < len; ++i) {
            buf[i] = (uint8_t)(rand() & 0xFF);
        }
    }
    return CEGRAM_OK;
}

uint64_t cegram_generate_message_id(void) {
    static uint32_t counter = 0;
    uint64_t sec = (uint64_t)time(NULL);
    counter += 4;
    return (sec << 32) | ((uint64_t)(counter & 0xFFFFFFFC));
}

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    uint32_t block[80];
    int i;

    for (i = 0; i < 16; ++i) {
        block[i] = ((uint32_t)buffer[i * 4] << 24) |
                   ((uint32_t)buffer[i * 4 + 1] << 16) |
                   ((uint32_t)buffer[i * 4 + 2] << 8) |
                   ((uint32_t)buffer[i * 4 + 3]);
    }
    for (i = 16; i < 80; ++i) {
        block[i] = rol(block[i - 3] ^ block[i - 8] ^ block[i - 14] ^ block[i - 16], 1);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for (i = 0; i < 20; ++i) {
        uint32_t t = rol(a, 5) + ((b & c) | ((~b) & d)) + e + 0x5A827999 + block[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    for (i = 20; i < 40; ++i) {
        uint32_t t = rol(a, 5) + (b ^ c ^ d) + e + 0x6ED9EBA1 + block[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    for (i = 40; i < 60; ++i) {
        uint32_t t = rol(a, 5) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDC + block[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    for (i = 60; i < 80; ++i) {
        uint32_t t = rol(a, 5) + (b ^ c ^ d) + e + 0xCA62C1D6 + block[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}

void cegram_sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint64_t total_bits = (uint64_t)len * 8;
    uint8_t final_block[128];
    size_t pad_block_len;
    size_t i;

    while (len >= 64) {
        sha1_transform(state, data);
        data += 64;
        len -= 64;
    }

    memset(final_block, 0, sizeof(final_block));
    if (len > 0) {
        memcpy(final_block, data, len);
    }
    final_block[len] = 0x80;

    pad_block_len = (len < 56) ? 64 : 128;
    for (i = 0; i < 8; ++i) {
        final_block[pad_block_len - 1 - i] = (uint8_t)((total_bits >> (i * 8)) & 0xFF);
    }

    sha1_transform(state, final_block);
    if (pad_block_len == 128) {
        sha1_transform(state, final_block + 64);
    }

    for (i = 0; i < 5; ++i) {
        out[i * 4]     = (uint8_t)((state[i] >> 24) & 0xFF);
        out[i * 4 + 1] = (uint8_t)((state[i] >> 16) & 0xFF);
        out[i * 4 + 2] = (uint8_t)((state[i] >> 8) & 0xFF);
        out[i * 4 + 3] = (uint8_t)(state[i] & 0xFF);
    }
}

#define ror(v, n) (((v) >> (n)) | ((v) << (32 - (n))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x) (ror(x, 2) ^ ror(x, 13) ^ ror(x, 22))
#define S1(x) (ror(x, 6) ^ ror(x, 11) ^ ror(x, 25))
#define s0(x) (ror(x, 7) ^ ror(x, 18) ^ ((x) >> 3))
#define s1(x) (ror(x, 17) ^ ror(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t w[64];
    int i;

    for (i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (i = 16; i < 64; ++i) {
        w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; ++i) {
        uint32_t t1 = h + S1(e) + Ch(e, f, g) + K256[i] + w[i];
        uint32_t t2 = S0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void cegram_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint64_t total_bits = (uint64_t)len * 8;
    uint8_t final_block[128];
    size_t pad_block_len;
    size_t i;

    while (len >= 64) {
        sha256_transform(state, data);
        data += 64;
        len -= 64;
    }

    memset(final_block, 0, sizeof(final_block));
    if (len > 0) {
        memcpy(final_block, data, len);
    }
    final_block[len] = 0x80;

    pad_block_len = (len < 56) ? 64 : 128;
    for (i = 0; i < 8; ++i) {
        final_block[pad_block_len - 1 - i] = (uint8_t)((total_bits >> (i * 8)) & 0xFF);
    }

    sha256_transform(state, final_block);
    if (pad_block_len == 128) {
        sha256_transform(state, final_block + 64);
    }

    for (i = 0; i < 8; ++i) {
        out[i * 4]     = (uint8_t)((state[i] >> 24) & 0xFF);
        out[i * 4 + 1] = (uint8_t)((state[i] >> 16) & 0xFF);
        out[i * 4 + 2] = (uint8_t)((state[i] >> 8) & 0xFF);
        out[i * 4 + 3] = (uint8_t)(state[i] & 0xFF);
    }
}

static uint64_t gcd64(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

static uint64_t mulmod64(uint64_t a, uint64_t b, uint64_t m) {
#if defined(__SIZEOF_INT128__)
    return (uint64_t)(((__uint128_t)a * b) % m);
#else
    uint64_t res = 0;
    a %= m;
    while (b > 0) {
        if (b & 1) {
            res = (res + a);
            if (res >= m) res -= m;
        }
        a = (a + a);
        if (a >= m) a -= m;
        b >>= 1;
    }
    return res;
#endif
}

int cegram_factorize_pq(uint64_t pq, uint32_t *out_p, uint32_t *out_q) {
    uint64_t x = 2, y = 2, d = 1;
    uint64_t c = 1;
    int iter = 0;

    while (d == 1 && iter++ < 1000000) {
        x = (mulmod64(x, x, pq) + c) % pq;
        y = (mulmod64(y, y, pq) + c) % pq;
        y = (mulmod64(y, y, pq) + c) % pq;
        uint64_t diff = (x > y) ? (x - y) : (y - x);
        d = gcd64(diff, pq);
    }

    if (d == 1 || d == pq) {
        c = 3; x = 2; y = 2; d = 1; iter = 0;
        while (d == 1 && iter++ < 1000000) {
            x = (mulmod64(x, x, pq) + c) % pq;
            y = (mulmod64(y, y, pq) + c) % pq;
            y = (mulmod64(y, y, pq) + c) % pq;
            uint64_t diff = (x > y) ? (x - y) : (y - x);
            d = gcd64(diff, pq);
        }
    }

    if (d != 1 && d != pq) {
        uint64_t p = d;
        uint64_t q = pq / d;
        if (p > q) {
            uint64_t tmp = p;
            p = q;
            q = tmp;
        }
        if (out_p) *out_p = (uint32_t)p;
        if (out_q) *out_q = (uint32_t)q;
        return CEGRAM_OK;
    }
    return CEGRAM_ERR_CRYPTO;
}

int cegram_rsa_encrypt_pad(const uint8_t *inner_data, size_t inner_len,
                           const cegram_rsa_key_t *key, uint8_t out_encrypted[256]) {
    uint8_t data_with_hash[255];
    uint8_t sha1_hash[20];
    size_t pad_len;
    mpz_t m, e, n, c;
    size_t written = 0;
    uint8_t temp[256];

    if (!inner_data || !key || !out_encrypted || (20 + inner_len > 255)) {
        return CEGRAM_ERR_GENERIC;
    }

    cegram_sha1(inner_data, inner_len, sha1_hash);

    memcpy(data_with_hash, sha1_hash, 20);
    memcpy(data_with_hash + 20, inner_data, inner_len);

    pad_len = 255 - (20 + inner_len);
    if (pad_len > 0) {
        if (cegram_random_bytes(data_with_hash + 20 + inner_len, pad_len) != CEGRAM_OK) {
            return CEGRAM_ERR_CRYPTO;
        }
    }

    mpz_init(m);
    mpz_init(e);
    mpz_init(n);
    mpz_init(c);

    if (mpz_set_str(n, key->modulus_hex, 16) != 0) {
        mpz_clear(m); mpz_clear(e); mpz_clear(n); mpz_clear(c);
        return CEGRAM_ERR_CRYPTO;
    }
    mpz_set_ui(e, key->exponent);
    mpz_import(m, 255, 1, 1, 1, 0, data_with_hash);

    mpz_powm(c, m, e, n);

    memset(out_encrypted, 0, 256);
    mpz_export(temp, &written, 1, 1, 1, 0, c);
    if (written <= 256) {
        memcpy(out_encrypted + (256 - written), temp, written);
    } else {
        mpz_clear(m); mpz_clear(e); mpz_clear(n); mpz_clear(c);
        return CEGRAM_ERR_CRYPTO;
    }

    mpz_clear(m);
    mpz_clear(e);
    mpz_clear(n);
    mpz_clear(c);
    return CEGRAM_OK;
}

void cegram_derive_tmp_aes_keys(const uint8_t new_nonce[32],
                                const uint8_t server_nonce[16],
                                uint8_t out_key[32],
                                uint8_t out_iv[32]) {
    uint8_t buf[64];
    uint8_t h1[20], h2[20], h3[20];

    memcpy(buf, new_nonce, 32);
    memcpy(buf + 32, server_nonce, 16);
    cegram_sha1(buf, 48, h1);

    memcpy(buf, server_nonce, 16);
    memcpy(buf + 16, new_nonce, 32);
    cegram_sha1(buf, 48, h2);

    memcpy(buf, new_nonce, 32);
    memcpy(buf + 32, new_nonce, 32);
    cegram_sha1(buf, 64, h3);

    memcpy(out_key, h1, 20);
    memcpy(out_key + 20, h2, 12);

    memcpy(out_iv, h2 + 12, 8);
    memcpy(out_iv + 8, h3, 20);
    memcpy(out_iv + 28, new_nonce, 4);
}

void cegram_derive_msg_keys(const uint8_t auth_key[256],
                            const uint8_t msg_key[16],
                            int is_client,
                            uint8_t out_key[32],
                            uint8_t out_iv[32]) {
    int x = is_client ? 0 : 8;
    uint8_t buf[52];
    uint8_t sha256_a[32];
    uint8_t sha256_b[32];

    memcpy(buf, msg_key, 16);
    memcpy(buf + 16, auth_key + x, 36);
    cegram_sha256(buf, 52, sha256_a);

    memcpy(buf, auth_key + 40 + x, 36);
    memcpy(buf + 36, msg_key, 16);
    cegram_sha256(buf, 52, sha256_b);

    memcpy(out_key, sha256_a, 8);
    memcpy(out_key + 8, sha256_b + 8, 16);
    memcpy(out_key + 24, sha256_a + 24, 8);

    memcpy(out_iv, sha256_b, 8);
    memcpy(out_iv + 8, sha256_a + 8, 16);
    memcpy(out_iv + 24, sha256_b + 24, 8);
}
