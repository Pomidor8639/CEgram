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

/* --- SHA-1 Implementation --- */
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

/* --- Pollard's Rho PQ Factorization --- */
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
        /* Retry with different initial constant */
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

/* --- RSA Encryption with Custom MTProto Padding (255 -> 256 bytes) --- */
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

    /* 1. Calculate SHA-1 of inner_data */
    cegram_sha1(inner_data, inner_len, sha1_hash);

    /* 2. Assemble data_with_hash = sha1(inner_data) + inner_data + random_padding */
    memcpy(data_with_hash, sha1_hash, 20);
    memcpy(data_with_hash + 20, inner_data, inner_len);

    pad_len = 255 - (20 + inner_len);
    if (pad_len > 0) {
        if (cegram_random_bytes(data_with_hash + 20 + inner_len, pad_len) != CEGRAM_OK) {
            return CEGRAM_ERR_CRYPTO;
        }
    }

    /* 3. Modular exponentiation c = (m ^ e) mod n */
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

    /* 4. Export 256 bytes (big-endian) */
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
