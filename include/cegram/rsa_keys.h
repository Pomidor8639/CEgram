#ifndef CEGRAM_RSA_KEYS_H
#define CEGRAM_RSA_KEYS_H

#include "common.h"

typedef struct {
    uint64_t fingerprint;
    const char *modulus_hex;
    uint32_t exponent;
} cegram_rsa_key_t;

/* Find embedded Telegram RSA public key by fingerprint */
const cegram_rsa_key_t *cegram_find_rsa_key(uint64_t fingerprint);

#endif /* CEGRAM_RSA_KEYS_H */
