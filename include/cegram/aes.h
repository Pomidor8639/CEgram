#ifndef CEGRAM_AES_H
#define CEGRAM_AES_H

#include "common.h"

typedef struct {
    uint32_t enc_round_keys[60];
    uint32_t dec_round_keys[60];
} cegram_aes256_ctx_t;

void cegram_aes256_init(cegram_aes256_ctx_t *ctx, const uint8_t key[32]);
void cegram_aes256_encrypt_block(const cegram_aes256_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]);
void cegram_aes256_decrypt_block(const cegram_aes256_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]);

void cegram_aes_ige_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                            const uint8_t key[32], const uint8_t iv[32]);

void cegram_aes_ige_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                            const uint8_t key[32], const uint8_t iv[32]);

#endif
