#ifndef CEGRAM_CRYPTO_H
#define CEGRAM_CRYPTO_H

#include "common.h"
#include "rsa_keys.h"

/* Generate cryptographically secure random bytes */
int cegram_random_bytes(uint8_t *buf, size_t len);

/* Generate MTProto unencrypted message_id based on current time */
uint64_t cegram_generate_message_id(void);

/* Calculate SHA-1 hash (output buffer must be at least 20 bytes) */
void cegram_sha1(const uint8_t *data, size_t len, uint8_t out[20]);

/* Factorize 64-bit pq into primes p and q (p < q) */
int cegram_factorize_pq(uint64_t pq, uint32_t *out_p, uint32_t *out_q);

/* Encrypt inner data with RSA and MTProto custom padding (outputs 256 bytes) */
int cegram_rsa_encrypt_pad(const uint8_t *inner_data, size_t inner_len,
                           const cegram_rsa_key_t *key, uint8_t out_encrypted[256]);

#endif /* CEGRAM_CRYPTO_H */
